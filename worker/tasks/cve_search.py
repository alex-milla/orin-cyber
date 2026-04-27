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

        # ── Decidir modo: individual vs batch ─────────────────────────────
        batch_mode = len(enriched) > 1

        if batch_mode:
            # Para batch (múltiples CVEs), no llamamos al LLM para evitar
            # exceso de tokens y tiempo. Generamos reporte con datos objetivos.
            logger.info("Batch mode: %d CVEs, skipping LLM call", len(enriched))
            report_text = self._build_fallback_text(enriched)
            report_text += (
                "\n\n*Nota: Modo batch activado. El análisis detallado del LLM está disponible "
                "solo para búsquedas individuales de CVE.*"
            )
        else:
            # ── Preparar datos para el LLM (modo individual) ──────────────
            context = json.dumps(enriched, indent=2, ensure_ascii=False)
            report_text = self.llm.chat(
                system_prompt=self.prompt_template,
                user_prompt=(
                    "Analiza los siguientes datos de CVEs. Primero traduce la descripción al español, "
                    f"luego genera el informe estructurado.\n\nDatos estructurados:\n{context}"
                ),
            )

            # Extraer traducción del output del LLM (sección CONTEXTO)
            import re
            first_enriched = enriched[0] if enriched else {}
            cve_data = first_enriched.get("cve", {})
            desc_translated = None
            if report_text:
                match = re.search(r'CONTEXTO\s*\n+((?:.+\n){1,3})', report_text, re.IGNORECASE)
                if match:
                    lines = [l.strip() for l in match.group(1).splitlines() if l.strip()]
                    desc_translated = " ".join(lines[:3])
                    logger.debug("Extracted Spanish description (%s chars)", len(desc_translated))
                else:
                    logger.debug("No CONTEXTO section found in LLM output")

            if desc_translated:
                cve_data["description_es"] = desc_translated

            # Fallback si el LLM retorna vacío
            if not report_text or not report_text.strip():
                logger.warning("LLM returned empty response, generating fallback analysis")
                report_text = self._build_fallback_text(enriched)

        # ── Formatear salida HTML ─────────────────────────────────────────
        try:
            if batch_mode:
                from utils.formatter import render_cve_report_batch
                result_html = render_cve_report_batch(enriched)
            else:
                result_html = render_cve_report(enriched, report_text)
        except Exception as exc:
            logger.exception("render failed: %s", exc)
            safe_text = report_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            result_html = f"<pre style='white-space:pre-wrap;'>{safe_text}</pre>"

        return {
            "result_html": result_html,
            "result_text": report_text,
        }
