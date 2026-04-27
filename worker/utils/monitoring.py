"""Recolecta métricas del sistema para heartbeat. Compatible con Linux/Jetson."""

import logging
import os
import socket
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Intentar importar psutil; si falla, usamos fallbacks
_psutil = None
try:
    import psutil
    _psutil = psutil
except ImportError:
    logger.warning("psutil no instalado. Métricas de CPU/memoria limitadas.")


def _read_file_int(path: str) -> Optional[int]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except (OSError, ValueError, TypeError):
        return None


def _read_thermal_zones() -> list[dict]:
    """Lee zonas térmicas de sysfs (Linux genérico + Jetson)."""
    zones = []
    base = "/sys/class/thermal"
    if not os.path.isdir(base):
        return zones
    try:
        for name in sorted(os.listdir(base)):
            if not name.startswith("thermal_zone"):
                continue
            temp = _read_file_int(os.path.join(base, name, "temp"))
            if temp is None:
                continue
            zones.append({"name": name, "temp_c": temp / 1000.0})
    except OSError:
        pass
    return zones


def _get_jetson_gpu() -> Optional[dict]:
    """Intenta leer GPU load en Jetson via devfreq."""
    devfreq_base = "/sys/class/devfreq"
    if not os.path.isdir(devfreq_base):
        return None
    try:
        for entry in os.listdir(devfreq_base):
            if "gv11b" not in entry and "gpu" not in entry:
                continue
            path = os.path.join(devfreq_base, entry, "load")
            try:
                with open(path, "r", encoding="utf-8") as f:
                    raw = f.read().strip()
                    if "@" in raw:
                        load = int(raw.split("@")[0])
                        return {"name": "Jetson GPU", "load_percent": load}
            except (OSError, ValueError):
                continue
    except OSError:
        pass
    return None


def _safe_psutil_cpu() -> Optional[float]:
    if not _psutil:
        return None
    try:
        return _psutil.cpu_percent(interval=0.5)
    except Exception as exc:
        logger.debug("cpu_percent failed: %s", exc)
        return None


def _safe_psutil_mem() -> Optional[dict]:
    if not _psutil:
        return None
    try:
        mem = _psutil.virtual_memory()
        return {
            "percent": mem.percent,
            "total_mb": mem.total // (1024 * 1024),
            "used_mb": mem.used // (1024 * 1024),
        }
    except Exception as exc:
        logger.debug("virtual_memory failed: %s", exc)
        return None


def _safe_psutil_disk() -> Optional[float]:
    if not _psutil:
        return None
    try:
        disk = _psutil.disk_usage("/")
        return disk.percent
    except Exception as exc:
        logger.debug("disk_usage failed: %s", exc)
        return None


def _safe_boot_time() -> float:
    if _psutil:
        try:
            return _psutil.boot_time()
        except Exception:
            pass
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("btime"):
                    return float(line.split()[1])
    except (OSError, ValueError):
        pass
    return 0.0


def get_available_models(models_dir: str) -> list[str]:
    """Lista archivos .gguf en el directorio de modelos."""
    try:
        if not os.path.isdir(models_dir):
            return []
        files = sorted(
            f for f in os.listdir(models_dir)
            if f.endswith(".gguf") and os.path.isfile(os.path.join(models_dir, f))
        )
        return files
    except Exception as exc:
        logger.debug("Failed to list models: %s", exc)
        return []


def get_metrics() -> dict[str, Any]:
    """Devuelve dict con métricas del sistema. Cada métrica falla de forma aislada."""
    metrics: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "uptime_seconds": max(0, int(time.time() - _safe_boot_time())),
        "cpu_percent": None,
        "memory_percent": None,
        "memory_total_mb": None,
        "memory_used_mb": None,
        "disk_percent": None,
        "temperature_c": None,
        "gpu_info": None,
    }

    cpu = _safe_psutil_cpu()
    if cpu is not None:
        metrics["cpu_percent"] = cpu

    mem = _safe_psutil_mem()
    if mem:
        metrics["memory_percent"] = mem["percent"]
        metrics["memory_total_mb"] = mem["total_mb"]
        metrics["memory_used_mb"] = mem["used_mb"]

    disk = _safe_psutil_disk()
    if disk is not None:
        metrics["disk_percent"] = disk

    try:
        zones = _read_thermal_zones()
        if zones:
            metrics["temperature_c"] = max(z["temp_c"] for z in zones)
    except Exception as exc:
        logger.debug("thermal zones failed: %s", exc)

    try:
        gpu = _get_jetson_gpu()
        if gpu:
            metrics["gpu_info"] = gpu
    except Exception as exc:
        logger.debug("jetson gpu failed: %s", exc)

    return metrics
