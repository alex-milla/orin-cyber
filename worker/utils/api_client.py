"""Cliente HTTP para comunicarse con el hosting OrinSec."""

import configparser
import json
import logging
import os
from typing import Optional

import requests

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ApiClient:
    def __init__(self, config_path: Optional[str] = None):
        self.config = configparser.ConfigParser()
        path = config_path or os.path.join(BASE_DIR, "config.ini")
        self.config.read(path)

        self.base_url = self.config.get("hosting", "url").rstrip("/")
        self.api_key = self.config.get("hosting", "api_key")
        self.max_retries = self.config.getint("worker", "max_retries", fallback=3)

    def _headers(self) -> dict:
        return {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
            "User-Agent": "OrinSec-Worker/1.0",
        }

    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[dict]:
        url = f"{self.base_url}{endpoint}"
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = requests.request(
                    method, url, headers=self._headers(), timeout=30, **kwargs
                )
                resp.raise_for_status()
                return resp.json()
            except requests.RequestException as exc:
                logger.warning("Request failed (attempt %s/%s): %s", attempt, self.max_retries, exc)
                if attempt == self.max_retries:
                    logger.error("Max retries reached for %s %s", method, url)
                    raise
        return None

    def get_pending_tasks(self) -> list:
        """Obtiene tareas pendientes del hosting."""
        data = self._request("GET", "/api/v1/tasks.php?action=pending")
        if data and "tasks" in data:
            return data["tasks"]
        return []

    def claim_task(self, task_id: int) -> bool:
        """Marca una tarea como 'processing'."""
        try:
            data = self._request(
                "POST", "/api/v1/tasks.php?action=claim",
                json={"task_id": task_id}
            )
            return data is not None and data.get("success", False)
        except requests.RequestException:
            return False

    def send_result(self, task_id: int, result_html: str, result_text: str) -> bool:
        """Envía el resultado de una tarea completada."""
        try:
            data = self._request(
                "POST", "/api/v1/tasks.php?action=result",
                json={
                    "task_id": task_id,
                    "result_html": result_html,
                    "result_text": result_text,
                }
            )
            return data is not None and data.get("success", False)
        except requests.RequestException:
            return False

    def send_error(self, task_id: int, error_message: str) -> bool:
        """Envía un error de ejecución."""
        try:
            data = self._request(
                "POST", "/api/v1/tasks.php?action=result",
                json={
                    "task_id": task_id,
                    "error_message": error_message,
                }
            )
            return data is not None and data.get("success", False)
        except requests.RequestException:
            return False
