"""Tarea: búsqueda de CVEs y generación de informe con LLM.

Arquitectura de fuentes (best practices):
  1. CVE.org / CVE Services  → fuente canónica (registro oficial)
  2. NVD API v2              → enriquecimiento (CVSS, CPE, CWE)
  3. CISA KEV                → priorización operativa
  4. EPSS / GitHub / OSV     → datos complementarios
"""

import json
import logging
import os
from datetime import datetime
from typing import Any

from tasks.base import BaseTask
from scrapers.cve_org import get_cve_by_id as get_cve_org, get_cve_description
from scrapers.nvd import get_cve_by_id as get_cve_nvd, get_cve_enrichment, search_cves
from scrapers.epss import get_epss
from scrapers.cisa_kev import get_kev
from scrapers.github_exploits import find_exploits
from scrapers.osv import query_osv
from utils.llm_client import LlmClient
from utils.formatter import render_cve_report_text

logger = logging.getLogger(__name__)

PROMPT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "prompts", "cve_report.txt")


def _calc_priority(score: float | None, epss_score: float | None, kev_listed: bool) -> str:
    """Calcula prioridad de parcheo basada en datos objetivos."""
    if kev_listed:
        return "A+"
    if score is not None and epss_score is not None:
        if score >= 9.0 and epss_score >= 0.5:
            return "A+"
        if score >= 7.0 and epss_score >= 0.3:
            return "A"
        if score >= 7.0 or epss_score >= 0.3:
            return "B"
    if score is not None:
        if score >= 9.0:
            return "A"
        if score >= 7.0:
            return "B"
        if score >= 4.0:
            return "C"
    return "D"


def _merge_references(*ref_lists: list) -> list[str]:
    """Fusiona listas de referencias eliminando duplicados."""
    seen = set()
    merged = []
    for lst in ref_lists:
        if not lst:
            continue
        for url in lst:
            if url and url not in seen:
                seen.add(url)
                merged.append(url)
    return merged


def _build_box_drawing_report(entry: dict, language: str = "es") -> str:
    """Construye el informe completo con box-drawing, pre-rellenado con datos reales.

    El LLM solo debe reescribir la sección de análisis de riesgo.
    """
    cve = entry["cve"]
    epss = entry.get("epss")
    kev = entry.get("kev")
    github = entry.get("github")
    osv = entry.get("osv")
    priority = entry.get("priority", "D")

    cve_id = cve.get("cve_id", "Unknown")
    published = cve.get("published", "N/A")
    score = cve.get("score")
    severity = cve.get("severity", "N/A")
    vector = cve.get("vector", "N/A")
    description = cve.get("description", "No data found")
    refs = cve.get("references", [])

    # Seleccionar descripción según idioma
    desc_text = description
    if language == "es":
        desc_es = cve.get("description_es", "")
        desc_en = cve.get("description_en", "")
        desc_text = desc_es if desc_es else (desc_en if desc_en else description)
    else:
        desc_en = cve.get("description_en", "")
        desc_text = desc_en if desc_en else description

    score_str = str(score) if score is not None else "N/A"

    # Exploits
    if github and isinstance(github, list) and len(github) > 0:
        exploit_lines = []
        for repo in github[:5]:
            name = repo.get("name", "Unknown") if isinstance(repo, dict) else str(repo)
            exploit_lines.append(f"  • {name}")
        exploit_block = "\n".join(exploit_lines)
    else:
        exploit_block = "  No exploits found"

    # EPSS
    if epss:
        epss_str = f"  EPSS Score:  {epss['score_percent']}% Probability of exploitation."
    else:
        epss_str = "  EPSS Score:  N/A"

    # CISA KEV
    if kev:
        kev_str = (
            f"  ✅ LISTED in CISA KEV Catalog\n"
            f"  Vendor: {kev.get('vendor', 'N/A')}\n"
            f"  Product: {kev.get('product', 'N/A')}\n"
            f"  Added: {kev.get('date_added', 'N/A')}\n"
            f"  Ransomware: {kev.get('ransomware', 'N/A')}"
        )
    else:
        kev_str = "  ❌ No data found"

    # Referencias
    if refs:
        ref_lines = []
        for i, url in enumerate(refs[:10]):
            prefix = "├" if i < len(refs[:10]) - 1 else "└"
            ref_lines.append(f"{prefix} {url}")
        ref_block = "\n".join(ref_lines)
    else:
        ref_block = "└ N/A"

    # Placeholder para el análisis del LLM
    risk_placeholder = "  <AI analysis will be inserted here>"

    report = f"""╔═══════════════════════╗
║ CVE ID: {cve_id:<17} ║
╚═══════════════════════╝

┌───[ 🔍 Vulnerability information ]
│
├ Published:   {published}
├ Base Score:  {score_str} ({severity})
├ Vector:      {vector}
└ Description: {desc_text}

┌───[ 💣 Public Exploits (Total: {len(github) if github else 0}) ]
│
└{exploit_block}

┌───[ ♾️ Exploit Prediction Score (EPSS) ]
│
└{epss_str}

┌───[ 🛡️ CISA KEV Catalog ]
│
└{kev_str}

┌───[ 🤖 AI-Powered Risk Assessment ]
│
│{risk_placeholder}
│
└────────────────────────────────────────

┌───[ ⚠️ Patching Priority Rating ]
│
└ Priority:     {priority}

┌───[ 📚 Further References ]
│
{ref_block}"""

    return report


class CveSearchTask(BaseTask):
    task_type = "cve_search"

    def __init__(self, config_path: str = None):
        self.llm = LlmClient(config_path)
        with open(PROMPT_PATH, "r", encoding="utf-8") as f:
            self.prompt_template = f.read()

    def _enrich_cve(self, cve_id: str, language: str = "es") -> dict:
        """Enriquece un CVE consultando fuentes oficiales y complementarias."""
        logger.info("Enriching %s (lang=%s)", cve_id, language)

        # ── Fuente canónica: CVE.org ──────────────────────────────────────
        cve_org_data = get_cve_org(cve_id)

        # ── Fallback a NVD si CVE.org no responde ─────────────────────────
        nvd_data = None
        if not cve_org_data:
            logger.warning("CVE.org failed for %s, falling back to NVD", cve_id)
            nvd_data = get_cve_nvd(cve_id)
            if nvd_data:
                cve_org_data = {
                    "cve_id": nvd_data["cve_id"],
                    "state": "PUBLISHED",
                    "published": nvd_data.get("published", "")[:10],
                    "updated": "",
                    "assigner": "",
                    "descriptions": {"en": nvd_data.get("description", "")},
                    "description_en": nvd_data.get("description", ""),
                    "description_es": "",
                    "affected": [],
                    "references": nvd_data.get("references", []),
                    "metrics_cna": None,
                    "cwes": [],
                    "data_version": "",
                }

        if not cve_org_data:
            return None

        # ── Enriquecimiento NVD ───────────────────────────────────────────
        nvd_enrich = get_cve_enrichment(cve_id)

        # Fusionar datos
        cve = {
            "cve_id": cve_org_data["cve_id"],
            "state": cve_org_data.get("state", "UNKNOWN"),
            "published": cve_org_data.get("published", ""),
            "updated": cve_org_data.get("updated", ""),
            "assigner": cve_org_data.get("assigner", ""),
            "description_en": cve_org_data.get("description_en", ""),
            "description_es": cve_org_data.get("description_es", ""),
            "description": get_cve_description(cve_org_data, language),
            "affected": cve_org_data.get("affected", []),
            "references": _merge_references(
                cve_org_data.get("references", []),
                nvd_enrich.get("references", []) if nvd_enrich else [],
            ),
            "cwes": cve_org_data.get("cwes", []) or (nvd_enrich.get("cwes", []) if nvd_enrich else []),
            "cpes": nvd_enrich.get("cpes", []) if nvd_enrich else [],
        }

        # CVSS: preferir CNA, luego NVD
        score = severity = vector = cvss_version = None
        cna_metrics = cve_org_data.get("metrics_cna")
        if cna_metrics:
            score = cna_metrics.get("base_score")
            severity = cna_metrics.get("base_severity")
            vector = cna_metrics.get("vector_string")
            cvss_version = cna_metrics.get("version")
        elif nvd_enrich:
            score = nvd_enrich.get("cvss_score")
            severity = nvd_enrich.get("severity")
            vector = nvd_enrich.get("vector")
            cvss_version = nvd_enrich.get("cvss_version")

        cve["score"] = score
        cve["severity"] = severity or "N/A"
        cve["vector"] = vector or "N/A"
        cve["cvss_version"] = cvss_version or ""

        # ── Fuentes complementarias ───────────────────────────────────────
        epss = get_epss(cve_id)
        kev = get_kev(cve_id)
        github = find_exploits(cve_id, max_results=5)
        osv = query_osv(cve_id)

        # Si OSV aporta severidad y no tenemos, usarla
        if osv and osv.get("severity") and cve["severity"] == "N/A":
            cve["severity"] = osv["severity"]

        priority = _calc_priority(
            cve.get("score"),
            epss["score"] if epss else None,
            kev is not None,
        )

        return {
            "cve": cve,
            "epss": epss,
            "kev": kev,
            "github": github,
            "osv": osv,
            "priority": priority,
        }

    def execute(self, input_data: dict[str, Any]) -> dict[str, str]:
        cve_id = input_data.get("cve_id", "").strip().upper()
        cve_list = input_data.get("cve_list", [])
        product = input_data.get("product", "").strip()
        version = input_data.get("version", "").strip()
        year = input_data.get("year", "").strip()
        severity = input_data.get("severity", "").strip()
        max_results = int(input_data.get("max_results", 10))
        custom_template = input_data.get("template", "").strip()
        language = input_data.get("language", "es").strip().lower()[:2]
        if language not in ("es", "en"):
            language = "es"

        # Normalizar cve_list
        if not cve_list and cve_id:
            cve_list = [cve_id]

        cves = []

        # ── Modo batch por CVE IDs ────────────────────────────────────────
        if cve_list:
            logger.debug("CVE lookup by IDs: %s", cve_list)
            for cid in cve_list[:20]:
                data = self._enrich_cve(cid, language)
                if data:
                    cves.append(data)
                else:
                    logger.warning("CVE %s not found", cid)
            if not cves:
                ids_str = ", ".join(cve_list[:20])
                return {
                    "result_html": f"<p class='alert alert-error'>None of the CVEs were found: {ids_str}</p>",
                    "result_text": f"None of the CVEs were found: {ids_str}",
                }
        else:
            logger.debug("CVE search: product=%s version=%s year=%s severity=%s", product, version, year, severity)
            # Búsqueda por producto sigue usando NVD (CVE.org no tiene búsqueda por keyword)
            nvd_results = search_cves(
                keyword=product,
                version=version,
                year=year,
                severity=severity,
                max_results=max_results,
            )
            for nr in nvd_results:
                cid = nr.get("cve_id", "")
                if cid:
                    enriched = self._enrich_cve(cid, language)
                    if enriched:
                        cves.append(enriched)

        if not cves:
            msg = "No se encontraron CVEs con los criterios indicados." if language == "es" else "No CVEs found matching the criteria."
            return {
                "result_html": f"<p class='alert alert-warning'>{msg}</p>",
                "result_text": msg,
            }

        # ── Generar informe ───────────────────────────────────────────────
        if len(cves) == 1:
            return self._generate_single(cves[0], custom_template, language)
        else:
            return self._generate_batch(cves, language)

    def _generate_single(self, entry: dict, custom_template: str, language: str) -> dict[str, str]:
        """Genera informe para un único CVE."""
        cve_data = entry["cve"]
        cve_id = cve_data.get("cve_id", "Unknown")

        # Construir reporte pre-rellenado
        report_body = _build_box_drawing_report(entry, language)

        # Preparar prompt para el LLM
        if custom_template:
            system_prompt = custom_template
        else:
            system_prompt = self.prompt_template

        system_prompt = system_prompt.replace("{language}", "español" if language == "es" else "English")
        system_prompt = system_prompt.replace("LANG", "es" if language == "es" else "en")

        user_prompt = (
            "A continuación tienes un informe técnico pre-rellenado con datos oficiales.\n"
            "REESCRIBE ÚNICAMENTE la sección '🤖 AI-Powered Risk Assessment'.\n"
            "Mantén TODO el resto exactamente igual, incluyendo los caracteres de dibujo de cajas.\n\n"
            f"{report_body}"
        ) if language == "es" else (
            "Below is a pre-filled technical report with official data.\n"
            "REWRITE ONLY the '🤖 AI-Powered Risk Assessment' section.\n"
            "Keep EVERYTHING else exactly as is, including the box-drawing characters.\n\n"
            f"{report_body}"
        )

        logger.info("Calling LLM for %s", cve_id)
        try:
            llm_output = self.llm.chat(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
        except Exception as exc:
            logger.warning("LLM call failed for %s: %s", cve_id, exc)
            llm_output = report_body

        # Si el LLM devolvió algo raro, fallback al pre-rellenado
        if not llm_output or "CVE ID:" not in llm_output:
            llm_output = report_body

        result_html = render_cve_report_text(llm_output, cve_data)

        return {
            "result_html": result_html,
            "result_text": llm_output,
            "cvss_score": cve_data.get("score"),
            "severity": cve_data.get("severity"),
        }

    def _generate_batch(self, entries: list, language: str) -> dict[str, str]:
        """Genera informe comparativo para múltiples CVEs (sin LLM)."""
        from utils.formatter import render_cve_report_batch
        html = render_cve_report_batch(entries)

        # Texto plano: lista resumida
        lines = []
        header = "Informe de vulnerabilidades — Batch" if language == "es" else "Vulnerability Report — Batch"
        lines.append(header)
        lines.append("=" * 50)
        for entry in entries:
            cve = entry["cve"]
            lines.append(f"\n{cve['cve_id']} | CVSS: {cve.get('score', 'N/A')} | Priority: {entry['priority']}")
            lines.append(cve.get("description", "")[:200])
        text = "\n".join(lines)

        first = entries[0]["cve"] if entries else {}
        return {
            "result_html": html,
            "result_text": text,
            "cvss_score": first.get("score"),
            "severity": first.get("severity"),
        }
