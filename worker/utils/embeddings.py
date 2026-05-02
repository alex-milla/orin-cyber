"""
Cliente para el servicio de embeddings local (llama-server --embedding).
Compatible con OpenAI Embeddings API (mismo formato).
"""
import json
import logging
import requests
from typing import List, Optional

logger = logging.getLogger(__name__)


class EmbeddingClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8081", timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._dim_cache: Optional[int] = None

    def embed(self, texts: List[str]) -> List[List[float]]:
        """
        Devuelve la lista de embeddings para los textos dados.
        El servicio llama-server expone /v1/embeddings (OpenAI-compatible).
        """
        if not texts:
            return []

        payload = {"input": texts, "model": "local"}
        try:
            r = requests.post(
                f"{self.base_url}/v1/embeddings",
                json=payload,
                timeout=self.timeout,
            )
            r.raise_for_status()
            data = r.json()
            embeddings = [item["embedding"] for item in data["data"]]
            if embeddings and self._dim_cache is None:
                self._dim_cache = len(embeddings[0])
                logger.info("Embedding dimension detected: %s", self._dim_cache)
            return embeddings
        except requests.exceptions.RequestException as e:
            logger.error("Embedding service error: %s", e)
            raise

    def embed_one(self, text: str) -> List[float]:
        result = self.embed([text])
        return result[0] if result else []

    @property
    def dimension(self) -> int:
        if self._dim_cache is None:
            self.embed_one("warmup")
        return self._dim_cache or 0

    def health(self) -> bool:
        try:
            r = requests.get(f"{self.base_url}/health", timeout=5)
            return r.status_code == 200
        except Exception:
            return False
