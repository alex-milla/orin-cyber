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
from utils.formatter import markdown_to_html

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

    def _build_compact_context(self, entry: dict) -> str:
        """Construye un bloque de contexto compacto en texto plano para el LLM."""
        cve = entry["cve"]
        epss = entry.get("epss") or {}
        kev = entry.get("kev")
        osv = entry.get("osv") or {}
        lines = [
            f"CVE: {cve.get('cve_id')}",
            f"Descripción: {cve.get('description', 'N/A')[:500]}",
            f"CVSS: {cve.get('score', 'N/A')} ({cve.get('severity', 'N/A')}) — {cve.get('vector', '')}",
            f"Publicado: {cve.get('published', '')[:10]}",
            f"EPSS: {epss.get('score_percent', 'N/A')}% probabilidad explotación",
        ]
        if kev:
            lines.append(f"CISA KEV: SÍ — Acción requerida: {kev.get('required_action', '')[:200]}")
        else:
            lines.append("CISA KEV: No listado")
        if osv.get("fixed_in"):
            lines.append(f"OSV fixed_in: {osv['fixed_in']}")
        return "\n".join(lines)

    def execute(self, input_data: dict[str, Any]) -> dict[str, str]:
        cve_id = input_data.get("cve_id", "").strip().upper()
        cve_list = input_data.get("cve_list", [])
        product = input_data.get("product", "").strip()
        version = input_data.get("version", "").strip()
        year = input_data.get("year", "").strip()
        severity = input_data.get("severity", "").strip()
        max_results = int(input_data.get("max_results", 10))
        custom_template = input_data.get("template", "").strip()

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

        # ── Generar informe con una sola ruta ─────────────────────────────
        template = custom_template if custom_template else self.prompt_template
        return self._execute(enriched, template)

    def _execute(self, enriched: list, template: str) -> dict[str, str]:
        """Genera informe usando una plantilla Markdown (libre o por defecto)."""
        html_parts = []
        text_parts = []

        for entry in enriched:
            cve_data = entry.get("cve", {})
            cve_id = cve_data.get("cve_id", "Unknown")
            context = self._build_compact_context(entry)

            logger.info("Llamando al LLM para %s", cve_id)
            try:
                report_text = self.llm.chat(
                    system_prompt=template,
                    user_prompt=(
                        "Analiza los siguientes datos de la vulnerabilidad y responde siguiendo la plantilla proporcionada.\n\n"
                        f"Datos:\n{context}"
                    ),
                )
            except Exception as exc:
                logger.warning("LLM call failed for %s: %s", cve_id, exc)
                report_text = (
                    f"## Error al generar informe para {cve_id}\n\n"
                    f"El modelo no respondió correctamente. Datos disponibles:\n\n```\n{context}\n```"
                )

            text_parts.append(report_text)

            # Construir HTML mínimo con metadatos + contenido del LLM
            severity = cve_data.get("severity", "N/A")
            score = cve_data.get("score")
            published = cve_data.get("published", "")[:10]
            score_str = str(score) if score is not None else "N/A"

            md_html = markdown_to_html(report_text)
            part_html = f'''<div class="cve-report" style="font-family:var(--font-base);color:var(--text);max-width:900px;margin:0 auto;">
  <div style="text-align:center;margin-bottom:1.5rem;">
    <div style="display:inline-block;border:2px solid var(--primary);padding:.75rem 2rem;border-radius:var(--radius);">
      <span style="font-size:1.4rem;font-weight:700;color:var(--primary);">{cve_id}</span>
    </div>
    <div style="margin-top:.5rem;">
      <span style="display:inline-block;background:var(--surface);padding:.25rem .75rem;border-radius:4px;font-size:.9rem;">
        CVSS: {score_str} | Severidad: {severity} | Publicado: {published or 'N/A'}
      </span>
    </div>
  </div>
  {md_html}
</div>'''
            html_parts.append(part_html)

        if len(html_parts) > 1:
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
        else:
            result_html = html_parts[0] if html_parts else "<p>Sin contenido.</p>"

        full_text = "\n\n".join(text_parts)

        # Extraer score/severity del primer CVE para persistencia
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
