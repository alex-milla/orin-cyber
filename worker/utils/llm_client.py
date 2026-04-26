"""Cliente para llama-server local (API compatible OpenAI)."""

import configparser
import json
import logging
import os
from typing import Optional

import requests

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class LlmClient:
    def __init__(self, config_path: Optional[str] = None):
        self.config = configparser.ConfigParser()
        path = config_path or os.path.join(BASE_DIR, "config.ini")
        self.config.read(path)

        self.server_url = self.config.get("llm", "server_url").rstrip("/")
        self.model = self.config.get("llm", "model")
        self.max_tokens = self.config.getint("llm", "max_tokens", fallback=2048)
        self.temperature = self.config.getfloat("llm", "temperature", fallback=0.3)

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        """Envía un chat completion al servidor local."""
        url = f"{self.server_url}/v1/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }

        logger.info("LLM request: %s tokens max", self.max_tokens)
        resp = requests.post(url, json=payload, timeout=120)
        resp.raise_for_status()
        data = resp.json()

        if "choices" in data and len(data["choices"]) > 0:
            content = data["choices"][0].get("message", {}).get("content", "").strip()
            logger.info("LLM response received (%s chars)", len(content))
            return content

        logger.error("Unexpected LLM response: %s", data)
        raise RuntimeError("Respuesta inesperada del LLM")
