"""Tarea: búsqueda de CVEs y generación de informe con LLM."""

import json
import logging
import os
from datetime import datetime
from typing import Any

from tasks.base import BaseTask
from scrapers.nvd import search_cves, get_cve_by_id
from scrapers.epss import get_epss
from scrapers.cisa_kev import get_kev
from scrapers.github_exploits import find_exploits
from scrapers.osv import query_osv
from utils.llm_client import LlmClient
from utils.formatter import render_cve_report

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


class CveSearchTask(BaseTask):
    task_type = "cve_search"

    def __init__(self, config_path: str = None):
        self.llm = LlmClient(config_path)
        with open(PROMPT_PATH, "r", encoding="utf-8") as f:
            self.prompt_template = f.read()

    def _enrich_cve(self, cve: dict) -> dict:
        """Enriquece un CVE con datos de fuentes adicionales."""
        cid = cve.get("cve_id", "unknown")
        epss = get_epss(cid)
        kev = get_kev(cid)
        github = find_exploits(cid, max_results=5)
        osv = query_osv(cid)

        if osv and osv.get("severity") and not cve.get("severity"):
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

    def _analyze_single(self, entry: dict) -> tuple[str, dict | None]:
        """Analiza un CVE con el LLM. Devuelve (report_text, llm_analysis)."""
        context = json.dumps([entry], indent=2, ensure_ascii=False)
        cve_data = entry.get("cve", {})
        cve_id = cve_data.get("cve_id", "Unknown")

        logger.info("Llamando al LLM para %s", cve_id)
        try:
            llm_analysis = self.llm.chat_json(
                system_prompt=self.prompt_template,
                user_prompt=(
                    "Analiza los siguientes datos de CVEs y responde ÚNICAMENTE con el JSON solicitado. "
                    f"Datos estructurados:\n{context}"
                ),
            )
        except Exception as exc:
            logger.warning("LLM call failed for %s: %s", cve_id, exc)
            llm_analysis = None

        if llm_analysis and isinstance(llm_analysis, dict):
            desc_translated = llm_analysis.get("contexto_es", "").strip()
            if desc_translated:
                cve_data["description_es"] = desc_translated

            lines = [f"## ANÁLISIS DE RIESGO — {cve_id}", ""]
            lines.append(f"**Contexto:** {desc_translated or cve_data.get('description', 'No disponible')}")
            lines.append("")
            impacto = llm_analysis.get("impacto", "").strip()
            if impacto:
                lines.append(f"**Impacto:** {impacto}")
                lines.append("")
            recs = llm_analysis.get("recomendaciones", [])
            if recs:
                lines.append("**Recomendaciones:**")
                for r in recs:
                    lines.append(f"- {r}")
                lines.append("")
            notas = llm_analysis.get("notas", "").strip()
            if notas:
                lines.append(f"**Notas:** {notas}")
            report_text = "\n".join(lines)
            logger.info("LLM JSON analysis parsed successfully for %s", cve_id)
            return report_text, llm_analysis

        # Fallback
        logger.warning("LLM did not return valid JSON for %s, generating fallback", cve_id)
        report_text = self._build_fallback_text([entry])
        return report_text, None

    def _build_fallback_text(self, enriched: list[dict]) -> str:
        """Genera texto plano de fallback cuando el LLM no responde."""
        lines = ["## ANÁLISIS DE RIESGO — BATCH CVE", ""]
        for entry in enriched:
            cve = entry["cve"]
            epss = entry.get("epss")
            kev = entry.get("kev")
            osv = entry.get("osv")
            priority = entry.get("priority", "D")
            lines.append(f"### {cve.get('cve_id', 'Unknown')}")
            lines.append(f"- Descripción: {cve.get('description', 'No disponible')[:200]}")
            lines.append(f"- CVSS: {cve.get('score', 'N/A')} ({cve.get('severity', 'N/A')})")
            lines.append(f"- EPSS: {epss['score_percent'] if epss else 'N/A'}%")
            lines.append(f"- CISA KEV: {'SÍ' if kev else 'No'}")
            lines.append(f"- OSV.dev: {len(osv['affected_packages']) if osv else 'N/A'} paquetes")
            lines.append(f"- Prioridad: {priority}")
            lines.append("")
        lines.append("**Recomendaciones:**")
        lines.append("1. Verificar boletín oficial del fabricante para cada CVE.")
        lines.append("2. Aplicar controles compensatorios: aislamiento, restricción de privilegios, monitoreo.")
        lines.append("3. Priorizar según ratings mostrados.")
        return "\n".join(lines)

    def execute(self, input_data: dict[str, Any]) -> dict[str, str]:
        cve_id = input_data.get("cve_id", "").strip().upper()
        cve_list = input_data.get("cve_list", [])
        product = input_data.get("product", "").strip()
        version = input_data.get("version", "").strip()
        year = input_data.get("year", "").strip()
        severity = input_data.get("severity", "").strip()
        max_results = int(input_data.get("max_results", 10))

        # Normalizar cve_list
        if not cve_list and cve_id:
            cve_list = [cve_id]

        cves = []

        # ── Modo batch por CVE IDs ────────────────────────────────────────
        if cve_list:
            logger.debug("CVE lookup by IDs: %s", cve_list)
            for cid in cve_list[:20]:
                data = get_cve_by_id(cid)
                if data:
                    cves.append(data)
                else:
                    logger.warning("CVE %s not found in NVD", cid)
            if not cves:
                ids_str = ", ".join(cve_list[:20])
                return {
                    "result_html": f"<p class='alert alert-error'>Ninguno de los CVEs encontrado en NVD: {ids_str}</p>",
                    "result_text": f"Ninguno de los CVEs encontrado en NVD: {ids_str}",
                }
        else:
            logger.debug("CVE search: product=%s version=%s year=%s severity=%s", product, version, year, severity)
            cves = search_cves(
                keyword=product,
                version=version,
                year=year,
                severity=severity,
                max_results=max_results,
            )

        if not cves:
            return {
                "result_html": "<p class='alert alert-warning'>No se encontraron CVEs con los criterios indicados.</p>",
                "result_text": "No se encontraron CVEs con los criterios indicados.",
            }

        # ── Enriquecer cada CVE ───────────────────────────────────────────
        enriched = []
        for cve in cves:
            if not isinstance(cve, dict):
                logger.warning("Skipping invalid CVE entry (not a dict): %s", cve)
                continue
            enriched.append(self._enrich_cve(cve))

        # ── Procesar cada CVE individualmente (cola) ──────────────────────
        html_parts = []
        text_parts = []

        for entry in enriched:
            report_text, _ = self._analyze_single(entry)
            text_parts.append(report_text)
            try:
                html_parts.append(render_cve_report([entry], report_text))
            except Exception as exc:
                logger.exception("render failed for %s: %s", entry.get("cve", {}).get("cve_id"), exc)
                safe_text = report_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                html_parts.append(f"<pre style='white-space:pre-wrap;'>{safe_text}</pre>")

        # ── Combinar todo en un único reporte ─────────────────────────────
        total = len(html_parts)
        result_html = f'''<div class="cve-report" style="font-family:var(--font-base);color:var(--text);max-width:900px;margin:0 auto;">
  <div style="text-align:center;margin-bottom:1.5rem;">
    <div style="display:inline-block;border:2px solid var(--primary);padding:.75rem 2rem;border-radius:var(--radius);">
      <span style="font-size:1.4rem;font-weight:700;color:var(--primary);">Batch CVE Report</span>
    </div>
    <p style="color:var(--text-muted);margin-top:.5rem;">{total} CVE(s) analizado(s)</p>
  </div>
'''
        result_html += "\n<hr style='margin:2rem 0;border:none;border-top:2px solid var(--border);'>\n".join(html_parts)
        result_html += "</div>"

        full_text = "\n\n".join(text_parts)

        # Extraer score/severity del primer CVE para persistencia en el hosting
        first_cvss_score = None
        first_severity = None
        if enriched:
            first_cve = enriched[0].get("cve", {})
            first_cvss_score = first_cve.get("score")
            first_severity = first_cve.get("severity")

        return {
            "result_html": result_html,
            "result_text": full_text,
            "cvss_score": first_cvss_score,
            "severity": first_severity,
        }
