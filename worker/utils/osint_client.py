"""Cliente OSINT con caché persistente para IOCs.

Fuentes soportadas:
- VirusTotal (API key requerida, 4 req/min gratis)
- AbuseIPDB (API key requerida, 1000 req/día gratis)
- URLhaus (sin API key, rate-limit manual)
- AlienVault OTX (API key requerida, 1000 req/hr gratis)

Todas las consultas pasan por cache SQLite local con TTL por fuente.
"""

import configparser
import logging
import os
import time
from typing import Any, Optional

import requests

from utils.cache import get as cache_get, set as cache_set

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# TTL por fuente (segundos)
_TTL = {
    "vt": 86400,       # 24h
    "abuseipdb": 43200,  # 12h
    "urlhaus": 86400,    # 24h
    "otx": 21600,        # 6h
}

# Rate limits por fuente (req/min)
_RATE_LIMIT = {
    "vt": 4,
    "abuseipdb": 60,     # 1000/día ≈ 41/hora, ponemos 60/hr conservador
    "urlhaus": 30,
    "otx": 60,
}

# Timestamps de última request por fuente
_last_request: dict[str, float] = {}


def _load_config(config_path: Optional[str] = None) -> dict[str, str]:
    """Carga API keys de config.ini sección [osint]."""
    cfg = configparser.ConfigParser()
    path = config_path or os.path.join(BASE_DIR, "config.ini")
    cfg.read(path)
    return {
        "vt_api_key": cfg.get("osint", "virustotal_api_key", fallback="").strip(),
        "abuse_api_key": cfg.get("osint", "abuseipdb_api_key", fallback="").strip(),
        "otx_api_key": cfg.get("osint", "otx_api_key", fallback="").strip(),
    }


def _rate_limit_wait(source: str) -> None:
    """Espera si es necesario para respetar rate limits."""
    min_interval = 60.0 / _RATE_LIMIT.get(source, 60)
    last = _last_request.get(source, 0)
    elapsed = time.time() - last
    if elapsed < min_interval:
        sleep_for = min_interval - elapsed
        logger.debug("Rate limit %s: esperando %.1fs", source, sleep_for)
        time.sleep(sleep_for)
    _last_request[source] = time.time()


def _cached(key: str, fetch_fn, ttl: int) -> Optional[dict]:
    """Wrapper cache: busca primero en cache, si no, llama fetch_fn."""
    cached = cache_get(key)
    if cached is not None:
        logger.debug("Cache hit: %s", key)
        return cached
    result = fetch_fn()
    if result is not None:
        cache_set(key, result, ttl)
    return result


def _normalize_ioc(ioc_value: str, ioc_type: str) -> str:
    """Normaliza el valor del IOC para uso en cache/URLs."""
    v = ioc_value.strip()
    if ioc_type in ("domain", "url", "hash"):
        v = v.lower()
    return v


# ── VirusTotal ──────────────────────────────────────────────────────

def get_virustotal_reputation(ioc_value: str, ioc_type: str, config_path: Optional[str] = None) -> Optional[dict]:
    """Consulta reputación en VirusTotal. Devuelve dict con malicious/suspicious/clean/undetected."""
    cfg = _load_config(config_path)
    api_key = cfg.get("vt_api_key", "")
    if not api_key:
        return None

    v = _normalize_ioc(ioc_value, ioc_type)
    cache_key = f"vt:{ioc_type}:{v}"

    def _fetch() -> Optional[dict]:
        _rate_limit_wait("vt")
        endpoint_map = {
            "ip": f"https://www.virustotal.com/api/v3/ip-addresses/{v}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{v}",
            "hash": f"https://www.virustotal.com/api/v3/files/{v}",
            "url": f"https://www.virustotal.com/api/v3/urls/{v}",
        }
        url = endpoint_map.get(ioc_type)
        if not url:
            return None
        try:
            resp = requests.get(url, headers={"x-apikey": api_key}, timeout=15)
            if resp.status_code == 404:
                return {"found": False, "malicious": 0, "suspicious": 0, "clean": 0, "undetected": 0}
            resp.raise_for_status()
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()),
                "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
            }
        except Exception as exc:
            logger.warning("VT query failed for %s: %s", v, exc)
            return None

    return _cached(cache_key, _fetch, _TTL["vt"])


# ── AbuseIPDB ───────────────────────────────────────────────────────

def get_abuseipdb_reputation(ip: str, config_path: Optional[str] = None) -> Optional[dict]:
    """Consulta reputación de IP en AbuseIPDB. Devuelve score 0-100 y reports."""
    cfg = _load_config(config_path)
    api_key = cfg.get("abuse_api_key", "")
    if not api_key:
        return None

    v = _normalize_ioc(ip, "ip")
    cache_key = f"abuseipdb:{v}"

    def _fetch() -> Optional[dict]:
        _rate_limit_wait("abuseipdb")
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": v, "maxAgeInDays": 90, "verbose": ""},
                timeout=15,
            )
            if resp.status_code == 404:
                return {"found": False, "score": 0, "reports": 0}
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "found": True,
                "score": data.get("abuseConfidenceScore", 0),
                "reports": data.get("totalReports", 0),
                "country": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "last_reported": data.get("lastReportedAt", ""),
            }
        except Exception as exc:
            logger.warning("AbuseIPDB query failed for %s: %s", v, exc)
            return None

    return _cached(cache_key, _fetch, _TTL["abuseipdb"])


# ── URLhaus ─────────────────────────────────────────────────────────

def get_urlhaus_lookup(ioc_value: str, ioc_type: str) -> Optional[dict]:
    """Consulta URLhaus (sin API key). Soporta URL y hash MD5/SHA256."""
    if ioc_type not in ("url", "hash"):
        return None

    v = _normalize_ioc(ioc_value, ioc_type)
    cache_key = f"urlhaus:{ioc_type}:{v}"

    def _fetch() -> Optional[dict]:
        _rate_limit_wait("urlhaus")
        try:
            if ioc_type == "url":
                resp = requests.post(
                    "https://urlhaus-api.abuse.ch/v1/url/",
                    data={"url": v},
                    timeout=15,
                )
            else:
                # hash
                resp = requests.post(
                    "https://urlhaus-api.abuse.ch/v1/payload/",
                    data={"sha256_hash": v} if len(v) == 64 else {"md5_hash": v},
                    timeout=15,
                )
            if resp.status_code == 404:
                return {"found": False, "malicious": False}
            data = resp.json()
            if data.get("query_status") == "no_results":
                return {"found": False, "malicious": False}
            return {
                "found": True,
                "malicious": True,
                "threat": data.get("threat", ""),
                "tags": data.get("tags", []),
                "firstseen": data.get("firstseen", ""),
                "url_count": data.get("url_count", 0),
            }
        except Exception as exc:
            logger.warning("URLhaus query failed for %s: %s", v, exc)
            return None

    return _cached(cache_key, _fetch, _TTL["urlhaus"])


# ── AlienVault OTX ──────────────────────────────────────────────────

def get_otx_pulse(ioc_value: str, ioc_type: str, config_path: Optional[str] = None) -> Optional[dict]:
    """Consulta pulsos de OTX para un IOC."""
    cfg = _load_config(config_path)
    api_key = cfg.get("otx_api_key", "")
    if not api_key:
        return None

    v = _normalize_ioc(ioc_value, ioc_type)
    cache_key = f"otx:{ioc_type}:{v}"

    endpoint_map = {
        "ip": f"https://otx.alienvault.com/api/v1/indicators/IPv4/{v}/general",
        "domain": f"https://otx.alienvault.com/api/v1/indicators/domain/{v}/general",
        "hash": f"https://otx.alienvault.com/api/v1/indicators/file/{v}/general",
        "url": f"https://otx.alienvault.com/api/v1/indicators/url/{v}/general",
    }
    url = endpoint_map.get(ioc_type)
    if not url:
        return None

    def _fetch() -> Optional[dict]:
        _rate_limit_wait("otx")
        try:
            resp = requests.get(url, headers={"X-OTX-API-KEY": api_key}, timeout=15)
            if resp.status_code == 404:
                return {"found": False, "pulse_count": 0}
            resp.raise_for_status()
            data = resp.json()
            return {
                "found": True,
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "reputation": data.get("reputation", 0),
                "tags": [t for t in data.get("pulse_info", {}).get("pulses", [{}])[0].get("tags", [])] if data.get("pulse_info", {}).get("count", 0) > 0 else [],
            }
        except Exception as exc:
            logger.warning("OTX query failed for %s: %s", v, exc)
            return None

    return _cached(cache_key, _fetch, _TTL["otx"])


# ── API unificada ───────────────────────────────────────────────────

def enrich_ioc(ioc_value: str, ioc_type: str, config_path: Optional[str] = None) -> dict[str, Any]:
    """Enriquece un IOC consultando todas las fuentes OSINT disponibles.

    Retorna dict con claves: vt, abuseipdb, urlhaus, otx.
    """
    result = {
        "ioc_value": ioc_value,
        "ioc_type": ioc_type,
        "vt": None,
        "abuseipdb": None,
        "urlhaus": None,
        "otx": None,
    }

    if ioc_type in ("ip", "domain", "hash", "url"):
        result["vt"] = get_virustotal_reputation(ioc_value, ioc_type, config_path)
    if ioc_type == "ip":
        result["abuseipdb"] = get_abuseipdb_reputation(ioc_value, config_path)
    if ioc_type in ("url", "hash"):
        result["urlhaus"] = get_urlhaus_lookup(ioc_value, ioc_type)
    if ioc_type in ("ip", "domain", "hash", "url"):
        result["otx"] = get_otx_pulse(ioc_value, ioc_type, config_path)

    return result


def get_osint_summary(ioc_value: str, ioc_type: str, config_path: Optional[str] = None) -> str:
    """Genera un resumen textual de OSINT para el contexto del LLM."""
    data = enrich_ioc(ioc_value, ioc_type, config_path)
    lines = [f"OSINT para {ioc_value} ({ioc_type}):"]

    vt = data.get("vt")
    if vt:
        if vt.get("found"):
            lines.append(f"  - VirusTotal: {vt.get('malicious', 0)}/{vt.get('total', 0)} motores detectan amenaza.")
        else:
            lines.append("  - VirusTotal: No encontrado.")

    abuse = data.get("abuseipdb")
    if abuse:
        if abuse.get("found"):
            lines.append(f"  - AbuseIPDB: Score {abuse.get('score', 0)}/100, {abuse.get('reports', 0)} reportes.")
        else:
            lines.append("  - AbuseIPDB: No reportado.")

    uh = data.get("urlhaus")
    if uh:
        if uh.get("found"):
            lines.append(f"  - URLhaus: Detectado como malicioso. Tags: {', '.join(uh.get('tags', []))}.")
        else:
            lines.append("  - URLhaus: No encontrado.")

    otx = data.get("otx")
    if otx:
        if otx.get("found"):
            lines.append(f"  - AlienVault OTX: {otx.get('pulse_count', 0)} pulsos asociados.")
        else:
            lines.append("  - AlienVault OTX: Sin pulsos.")

    if not any([vt, abuse, uh, otx]):
        lines.append("  (Sin API keys OSINT configuradas — análisis basado solo en contexto local)")

    return "\n".join(lines)
