"""Recolecta métricas del sistema para heartbeat. Compatible con Linux/Jetson."""

import logging
import os
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
        with open(path, "r") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _read_thermal_zones() -> list[dict]:
    """Lee zonas térmicas de sysfs (Linux genérico + Jetson)."""
    zones = []
    base = "/sys/class/thermal"
    if not os.path.isdir(base):
        return zones
    for name in sorted(os.listdir(base)):
        if not name.startswith("thermal_zone"):
            continue
        zone_path = os.path.join(base, name)
        temp = _read_file_int(os.path.join(zone_path, "temp"))
        if temp is None:
            continue
        # temp está en miligrados
        zones.append({
            "name": name,
            "temp_c": temp / 1000.0,
        })
    return zones


def _get_jetson_gpu() -> Optional[dict]:
    """Intenta leer GPU load en Jetson via devfreq o tegrastats."""
    # Jetson Orin: /sys/class/devfreq/17000000.gv11b/load
    devfreq_paths = []
    devfreq_base = "/sys/class/devfreq"
    if os.path.isdir(devfreq_base):
        for entry in os.listdir(devfreq_base):
            if "gv11b" in entry or "gpu" in entry:
                devfreq_paths.append(os.path.join(devfreq_base, entry, "load"))

    for path in devfreq_paths:
        try:
            with open(path, "r") as f:
                raw = f.read().strip()
                # Formato típico: "@load_freq"
                if "@" in raw:
                    load = int(raw.split("@")[0])
                    return {"name": "Jetson GPU", "load_percent": load}
        except (OSError, ValueError):
            continue
    return None


def get_metrics() -> dict[str, Any]:
    """Devuelve dict con métricas del sistema."""
    metrics: dict[str, Any] = {
        "hostname": os.uname().nodename,
        "uptime_seconds": int(time.time() - _get_boot_time()),
        "cpu_percent": None,
        "memory_percent": None,
        "memory_total_mb": None,
        "memory_used_mb": None,
        "disk_percent": None,
        "temperature_c": None,
        "gpu_info": None,
    }

    if _psutil:
        # CPU
        metrics["cpu_percent"] = _psutil.cpu_percent(interval=0.5)

        # Memoria
        mem = _psutil.virtual_memory()
        metrics["memory_percent"] = mem.percent
        metrics["memory_total_mb"] = mem.total // (1024 * 1024)
        metrics["memory_used_mb"] = mem.used // (1024 * 1024)

        # Disco
        try:
            disk = _psutil.disk_usage("/")
            metrics["disk_percent"] = disk.percent
        except OSError:
            pass

    # Temperatura (tomar la máxima de todas las zonas)
    zones = _read_thermal_zones()
    if zones:
        metrics["temperature_c"] = max(z["temp_c"] for z in zones)

    # GPU Jetson
    gpu = _get_jetson_gpu()
    if gpu:
        metrics["gpu_info"] = gpu

    return metrics


def _get_boot_time() -> float:
    """Tiempo de arranque del sistema."""
    if _psutil:
        return _psutil.boot_time()
    # Fallback: /proc/stat btime
    try:
        with open("/proc/stat", "r") as f:
            for line in f:
                if line.startswith("btime"):
                    return float(line.split()[1])
    except OSError:
        pass
    return 0.0
