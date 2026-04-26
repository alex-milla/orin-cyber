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

    def execute(self, input_data: dict[str, Any]) -> dict[str, str]:
        cve_id = input_data.get("cve_id", "").strip().upper()
        product = input_data.get("product", "").strip()
        version = input_data.get("version", "").strip()
        year = input_data.get("year", "").strip()
        severity = input_data.get("severity", "").strip()
        max_results = int(input_data.get("max_results", 10))

        # ── Modo búsqueda por CVE ID ──────────────────────────────────────
        if cve_id:
            logger.info("CVE lookup by ID: %s", cve_id)
            cve_data = get_cve_by_id(cve_id)
            if not cve_data:
                return {
                    "result_html": f"<p class='alert alert-error'>CVE {cve_id} no encontrado en NVD.</p>",
                    "result_text": f"CVE {cve_id} no encontrado en NVD.",
                }
            cves = [cve_data]
        else:
            logger.info("CVE search: product=%s version=%s year=%s severity=%s", product, version, year, severity)
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

        # ── Enriquecer cada CVE con datos adicionales ─────────────────────
        enriched = []
        for cve in cves:
            if not isinstance(cve, dict):
                logger.warning("Skipping invalid CVE entry (not a dict): %s", cve)
                continue
            cid = cve.get("cve_id", "unknown")
            logger.info("Enriching %s", cid)

            epss = get_epss(cid)
            kev = get_kev(cid)
            github = find_exploits(cid, max_results=5)

            priority = _calc_priority(
                cve.get("score"),
                epss["score"] if epss else None,
                kev is not None,
            )

            enriched.append({
                "cve": cve,
                "epss": epss,
                "kev": kev,
                "github": github,
                "priority": priority,
            })

        # ── Preparar datos para el LLM ────────────────────────────────────
        context = json.dumps(enriched, indent=2, ensure_ascii=False)

        # ── Llamar al LLM (1 sola llamada: traduce + analiza) ──────────────
        report_text = self.llm.chat(
            system_prompt=self.prompt_template,
            user_prompt=f"Analiza los siguientes datos de CVEs. Primero traduce la descripción al español, luego genera el informe estructurado.\n\nDatos estructurados:\n{context}",
        )

        # Extraer traducción del output del LLM (sección CONTEXTO)
        import re
        first_enriched = enriched[0] if enriched else {}
        cve_data = first_enriched.get("cve", {})
        desc_translated = None
        if report_text:
            # Buscar "CONTEXTO\n" y tomar las siguientes 1-3 líneas no vacías
            match = re.search(r'CONTEXTO\s*\n+((?:.+\n){1,3})', report_text, re.IGNORECASE)
            if match:
                lines = [l.strip() for l in match.group(1).splitlines() if l.strip()]
                desc_translated = " ".join(lines[:3])
                logger.info("Extracted Spanish description (%s chars)", len(desc_translated))
            else:
                logger.info("No CONTEXTO section found in LLM output")

        # Guardar traducción en el dict del CVE para el formatter
        if desc_translated:
            cve_data["description_es"] = desc_translated

        # Fallback si el LLM retorna vacío
        if not report_text or not report_text.strip():
            logger.warning("LLM returned empty response, generating fallback analysis")
            epss = first_enriched.get("epss")
            kev = first_enriched.get("kev")
            priority = first_enriched.get("priority", "D")
            report_text = (
                f"## ANÁLISIS DE RIESGO — {cve_data.get('cve_id', 'Unknown')}\n\n"
                f"**Contexto:** {cve_data.get('description', 'No disponible')}\n\n"
                f"**Datos objetivos:**\n"
                f"- CVSS: {cve_data.get('score', 'N/A')} ({cve_data.get('severity', 'N/A')})\n"
                f"- EPSS: {epss['score_percent'] if epss else 'N/A'}% (percentil {epss['percentile_percent'] if epss else 'N/A'}%)\n"
                f"- CISA KEV: {'SÍ — explotación activa confirmada' if kev else 'No listado'}\n"
                f"- Prioridad de parcheo: {priority}\n\n"
                f"**Recomendaciones:**\n"
                f"1. Verificar boletín oficial del fabricante para versión de parche exacta.\n"
                f"2. Aplicar controles compensatorios: aislamiento, restricción de privilegios, monitoreo de IOCs.\n"
                f"3. Priorizar según rating {priority}.\n\n"
                f"*Nota: El análisis detallado del LLM no pudo generarse (timeout o respuesta vacía). "
                f"Los datos mostrados provienen de fuentes objetivas (NVD, EPSS, CISA KEV)."
            )

        # ── Formatear salida HTML ─────────────────────────────────────────
        try:
            result_html = render_cve_report(enriched, report_text)
        except Exception as exc:
            logger.exception("render_cve_report failed: %s", exc)
            safe_text = report_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            result_html = f"<pre style='white-space:pre-wrap;'>{safe_text}</pre>"

        return {
            "result_html": result_html,
            "result_text": report_text,
        }
