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
from typing import Any

from tasks.base import BaseTask
from scrapers.cve_org import get_cve_by_id as get_cve_org, get_cve_description
from scrapers.nvd import get_cve_by_id as get_cve_nvd, get_cve_enrichment, search_cves
from scrapers.epss import get_epss
from scrapers.cisa_kev import get_kev
from scrapers.github_exploits import find_exploits
from scrapers.osv import query_osv
from utils.llm_client import LlmClient
from utils.formatter import render_cve_html

logger = logging.getLogger(__name__)


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


def _build_report_text(entry: dict, language: str = "es", llm_analysis: str = "") -> str:
    """Construye el informe completo con box-drawing, inyectando el análisis del LLM."""
    cve = entry["cve"]
    epss = entry.get("epss")
    kev = entry.get("kev")
    github = entry.get("github")
    priority = entry.get("priority", "D")

    cve_id = cve.get("cve_id", "Unknown")
    published = cve.get("published", "N/A")
    score = cve.get("score")
    severity = cve.get("severity", "N/A")
    vector = cve.get("vector", "N/A")
    refs = cve.get("references", [])

    desc_text = cve.get("description", "No data found")
    score_str = str(score) if score is not None else "N/A"

    # Exploits
    if github and isinstance(github, list) and len(github) > 0:
        exploit_block = "\n".join(f"  • {repo.get('name', 'Unknown')}" for repo in github[:5])
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
        slice_refs = refs[:10]
        last_idx = len(slice_refs) - 1
        for i, url in enumerate(slice_refs):
            prefix = "├" if i < last_idx else "└"
            ref_lines.append(f"{prefix} {url}")
        ref_block = "\n".join(ref_lines)
    else:
        ref_block = "└ N/A"

    # Análisis del LLM
    if not llm_analysis:
        llm_analysis = "  [No AI analysis available]"
    else:
        # Indentar cada línea del análisis
        lines = llm_analysis.strip().split("\n")
        llm_analysis = "\n".join(f"│  {line}" for line in lines)

    return (
        f"╔═══════════════════════╗\n"
        f"║ CVE ID: {cve_id:<17} ║\n"
        f"╚═══════════════════════╝\n\n"
        f"┌───[ 🔍 Vulnerability information ]\n"
        f"│\n"
        f"├ Published:   {published}\n"
        f"├ Base Score:  {score_str} ({severity})\n"
        f"├ Vector:      {vector}\n"
        f"└ Description: {desc_text}\n\n"
        f"┌───[ 💣 Public Exploits (Total: {len(github) if github else 0}) ]\n"
        f"│\n"
        f"└{exploit_block}\n\n"
        f"┌───[ ♾️ Exploit Prediction Score (EPSS) ]\n"
        f"│\n"
        f"└{epss_str}\n\n"
        f"┌───[ 🛡️ CISA KEV Catalog ]\n"
        f"│\n"
        f"└{kev_str}\n\n"
        f"┌───[ 🤖 AI-Powered Risk Assessment ]\n"
        f"│\n"
        f"{llm_analysis}\n"
        f"│\n"
        f"└────────────────────────────────────────\n\n"
        f"┌───[ ⚠️ Patching Priority Rating ]\n"
        f"│\n"
        f"└ Priority:     {priority}\n\n"
        f"┌───[ 📚 Further References ]\n"
        f"│\n"
        f"{ref_block}\n\n"
        f"Model: OrinSec Worker"
    )


def _build_llm_prompt(entry: dict, language: str = "es") -> str:
    """Construye el prompt que le pide al LLM SOLO el análisis de riesgo."""
    cve = entry["cve"]
    epss = entry.get("epss")
    kev = entry.get("kev")
    github = entry.get("github")
    osv = entry.get("osv")

    cve_id = cve.get("cve_id", "Unknown")
    desc = cve.get("description", "N/A")
    vector = cve.get("vector", "N/A")

    epss_str = f"{epss['score_percent']}%" if epss else "N/A"
    kev_str = "YES" if kev else "NO"
    exploit_count = len(github) if github else 0

    if language == "es":
        return (
            f"Eres un analista senior de ciberseguridad. Genera un análisis de riesgo técnico conciso "
            f"para la vulnerabilidad {cve_id}.\n\n"
            f"DATOS DE REFERENCIA (NO repitas estos valores en tu análisis):\n"
            f"- Descripción: {desc[:400]}\n"
            f"- Vector: {vector}\n"
            f"- EPSS: {epss_str}\n"
            f"- CISA KEV: {kev_str}\n"
            f"- Exploits públicos: {exploit_count}\n"
            f"- OSV: {len(osv['affected_packages']) if osv and osv.get('affected_packages') else 0} paquetes afectados\n\n"
            f"REGLAS:\n"
            f"1. Máximo 150 palabras.\n"
            f"2. NO repitas el score CVSS, la severidad, el EPSS ni el estado KEV.\n"
            f"3. NO inventes versiones de parche ni fechas.\n"
            f"4. Enfócate en: vector de explotación real, condiciones necesarias, impacto para la organización.\n"
            f"5. Usa [INFERIDO] solo para consecuencias lógicas obvias.\n"
            f"6. Responde en español.\n\n"
            f"Escribe SOLO el párrafo de análisis, sin títulos ni formato adicional."
        )
    else:
        return (
            f"You are a senior cybersecurity analyst. Generate a concise technical risk analysis "
            f"for vulnerability {cve_id}.\n\n"
            f"REFERENCE DATA (DO NOT repeat these values in your analysis):\n"
            f"- Description: {desc[:400]}\n"
            f"- Vector: {vector}\n"
            f"- EPSS: {epss_str}\n"
            f"- CISA KEV: {kev_str}\n"
            f"- Public exploits: {exploit_count}\n"
            f"- OSV: {len(osv['affected_packages']) if osv and osv.get('affected_packages') else 0} affected packages\n\n"
            f"RULES:\n"
            f"1. Maximum 150 words.\n"
            f"2. DO NOT repeat CVSS score, severity, EPSS or KEV status.\n"
            f"3. DO NOT invent patch versions or dates.\n"
            f"4. Focus on: real exploitation vector, required conditions, organizational impact.\n"
            f"5. Use [INFERRED] only for obvious logical consequences.\n"
            f"6. Respond in English.\n\n"
            f"Write ONLY the analysis paragraph, no titles or additional formatting."
        )


class CveSearchTask(BaseTask):
    task_type = "cve_search"

    def __init__(self, config_path: str = None):
        self.llm = LlmClient(config_path)

    def _enrich_cve(self, cve_id: str, language: str = "es") -> dict | None:
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
        language = input_data.get("language", "es").strip().lower()[:2]
        if language not in ("es", "en"):
            language = "es"
        custom_template = input_data.get("template", "").strip()

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
                msg = "Ninguno de los CVEs encontrado: " + ids_str if language == "es" else "None of the CVEs found: " + ids_str
                return {
                    "result_html": f"<p class='alert alert-error'>{msg}</p>",
                    "result_text": msg,
                }
        else:
            logger.debug("CVE search: product=%s version=%s year=%s severity=%s", product, version, year, severity)
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
            return self._generate_single(cves[0], language, custom_template)
        else:
            return self._generate_batch(cves, language)

    def _generate_single(self, entry: dict, language: str, custom_template: str = "") -> dict[str, str]:
        """Genera informe para un único CVE: código construye la estructura, LLM solo el análisis."""
        cve_data = entry["cve"]
        cve_id = cve_data.get("cve_id", "Unknown")

        # 1. Pedir al LLM SOLO el análisis de riesgo
        prompt = _build_llm_prompt(entry, language)
        logger.info("Calling LLM for risk analysis of %s", cve_id)

        if custom_template:
            system_prompt = custom_template
        else:
            system_prompt = (
                "Eres un analista senior de ciberseguridad. Responde de forma concisa y técnica."
                if language == "es" else
                "You are a senior cybersecurity analyst. Respond concisely and technically."
            )

        try:
            llm_analysis = self.llm.chat(
                system_prompt=system_prompt,
                user_prompt=prompt,
            )
            llm_analysis = llm_analysis.strip()
        except Exception as exc:
            logger.warning("LLM call failed for %s: %s", cve_id, exc)
            llm_analysis = ""

        # 2. Construir el reporte completo con box-drawing (determinístico)
        report_text = _build_report_text(entry, language, llm_analysis)

        # 3. Convertir a HTML visual determinístico
        result_html = render_cve_html(entry, llm_analysis, language)

        return {
            "result_html": result_html,
            "result_text": report_text,
            "cvss_score": cve_data.get("score"),
            "severity": cve_data.get("severity"),
        }

    def _generate_batch(self, entries: list, language: str) -> dict[str, str]:
        """Genera informe comparativo para múltiples CVEs (sin LLM)."""
        from utils.formatter import render_cve_report_batch
        html = render_cve_report_batch(entries)

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
