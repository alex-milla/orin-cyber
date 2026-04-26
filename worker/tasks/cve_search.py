"""Tarea: búsqueda de CVEs y generación de informe con LLM."""

import json
import logging
import os
from datetime import datetime
from typing import Any

from tasks.base import BaseTask
from scrapers.nvd import search_cves
from utils.llm_client import LlmClient
from utils.formatter import markdown_to_html, wrap_html_document

logger = logging.getLogger(__name__)

PROMPT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "prompts", "cve_report.txt")


class CveSearchTask(BaseTask):
    task_type = "cve_search"

    def __init__(self, config_path: str = None):
        self.llm = LlmClient(config_path)
        with open(PROMPT_PATH, "r", encoding="utf-8") as f:
            self.prompt_template = f.read()

    def execute(self, input_data: dict[str, Any]) -> dict[str, str]:
        product = input_data.get("product", "").strip()
        version = input_data.get("version", "").strip()
        year = input_data.get("year", "").strip()
        severity = input_data.get("severity", "").strip()
        max_results = int(input_data.get("max_results", 10))

        logger.info("CVE search: product=%s version=%s year=%s severity=%s", product, version, year, severity)

        # 1. Buscar en NVD
        cves = search_cves(
            keyword=product,
            version=version,
            year=year,
            severity=severity,
            max_results=max_results,
        )

        # 2. Preparar datos para el LLM
        raw_json = json.dumps(cves, indent=2, ensure_ascii=False)
        user_prompt = f"""Producto: {product}
Versión: {version or 'No especificada'}
Filtros: Año={year or 'Cualquiera'}, Severidad mínima={severity or 'Cualquiera'}

Datos crudos de NVD:
{raw_json}"""

        # 3. Llamar al LLM
        report_text = self.llm.chat(
            system_prompt=self.prompt_template,
            user_prompt=user_prompt,
        )

        # 4. Formatear salida
        html_body = markdown_to_html(report_text)
        result_html = wrap_html_document(
            html_body,
            title=f"Informe CVE — {product} {version}".strip(),
        )

        return {
            "result_html": result_html,
            "result_text": report_text,
        }
