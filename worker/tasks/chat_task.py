"""Tarea de chat con el modelo LLM local."""

import logging
from typing import Any

from tasks.base import BaseTask
from utils.llm_client import LlmClient

logger = logging.getLogger(__name__)


class ChatTask(BaseTask):
    task_type = "chat"

    def __init__(self, config_path: str):
        self.config_path = config_path
        self.llm = LlmClient(config_path)

    def execute(self, input_data: dict[str, Any]) -> dict[str, str]:
        """
        input_data espera:
        - message: str  (mensaje del usuario)
        - system_prompt: str (opcional, por defecto un asistente genérico)
        """
        message = input_data.get("message", "")
        if not message:
            return {
                "result_html": "<p class='text-error'>Mensaje vacío.</p>",
                "result_text": "Mensaje vacío.",
            }

        system = input_data.get(
            "system_prompt",
            "Eres un asistente útil, claro y conciso. Responde siempre en el idioma del usuario.",
        )

        logger.info("ChatTask: enviando mensaje de %d chars", len(message))

        try:
            response = self.llm.chat(system, message)
            return {
                "result_html": f"<div class='chat-response'>{self._escape_html(response)}</div>",
                "result_text": response,
            }
        except Exception as exc:
            logger.exception("ChatTask falló")
            return {
                "result_html": f"<p class='text-error'>Error: {self._escape_html(str(exc))}</p>",
                "result_text": f"Error: {exc}",
            }

    @staticmethod
    def _escape_html(text: str) -> str:
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
