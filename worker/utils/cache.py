"""Capa de cache persistente en SQLite para el worker.

Evita reconsultar APIs externas cuando los datos no cambian (NVD, EPSS, OSV).
TTL configurable por fuente.
"""

import json
import logging
import os
import sqlite3
import time
from typing import Optional

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DB = os.path.join(BASE_DIR, "data", "cache.db")


def _conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(CACHE_DB), exist_ok=True)
    c = sqlite3.connect(CACHE_DB)
    c.execute(
        """CREATE TABLE IF NOT EXISTS cache (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )"""
    )
    return c


def get(key: str) -> Optional[dict]:
    """Devuelve el valor cacheado si existe y no ha expirado."""
    try:
        with _conn() as c:
            row = c.execute(
                "SELECT value FROM cache WHERE key = ? AND expires_at > ?",
                (key, int(time.time())),
            ).fetchone()
            if row:
                return json.loads(row[0])
    except Exception as exc:
        logger.debug("Cache get failed for %s: %s", key, exc)
    return None


def set(key: str, value: dict, ttl_seconds: int = 86400) -> None:
    """Guarda un valor en cache con TTL."""
    try:
        with _conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)",
                (key, json.dumps(value, ensure_ascii=False), int(time.time()) + ttl_seconds),
            )
    except Exception as exc:
        logger.debug("Cache set failed for %s: %s", key, exc)


def purge_expired() -> None:
    """Elimina entradas expiradas."""
    try:
        with _conn() as c:
            c.execute("DELETE FROM cache WHERE expires_at < ?", (int(time.time()),))
    except Exception as exc:
        logger.debug("Cache purge failed: %s", exc)
