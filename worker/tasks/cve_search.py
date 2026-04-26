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

        # ── Traducir descripciones al español (top 3 en modo búsqueda, todos en modo ID) ──
        max_translate = len(cves) if cve_id else min(3, len(cves))
        for idx, cve in enumerate(cves):
            if idx < max_translate:
                desc = cve.get("description", "")
                if desc:
                    cve["description_es"] = self.llm.translate(desc, target_lang="es", max_tokens=256)

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

        # ── Llamar al LLM para análisis sintético ─────────────────────────
        report_text = self.llm.chat(
            system_prompt=self.prompt_template,
            user_prompt=f"Analiza los siguientes datos de CVEs y genera un informe estructurado en español.\n\nDatos estructurados:\n{context}",
        )

        # ── Formatear salida HTML ─────────────────────────────────────────
        try:
            result_html = render_cve_report(enriched, report_text)
        except Exception as exc:
            logger.exception("render_cve_report failed: %s", exc)
            # Fallback: texto plano envuelto en HTML básico
            safe_text = (report_text or "Error generando reporte visual.").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            result_html = f"<pre style='white-space:pre-wrap;'>{safe_text}</pre>"

        return {
            "result_html": result_html,
            "result_text": report_text or "",
        }
