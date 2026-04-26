#!/usr/bin/env python3
"""Worker principal de OrinSec.

Consulta periódicamente el hosting por tareas pendientes, las ejecuta
y devuelve los resultados. Todo el tráfico es saliente (Orin → Hosting).
"""

import configparser
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from typing import Optional

from utils.api_client import ApiClient
from utils.monitoring import get_metrics
from tasks.cve_search import CveSearchTask

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(BASE_DIR, "config.ini")
CURRENT_MODEL_FILE = os.path.join(BASE_DIR, ".current_model")

# Registry de tareas disponibles
TASK_REGISTRY = {
    "cve_search": CveSearchTask,
}


def setup_logging(config: configparser.ConfigParser) -> None:
    log_file = config.get("worker", "log_file", fallback="/var/log/orinsec_worker.log")
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def _save_current_model(model: str) -> None:
    """Persiste el modelo activo para sobrevivir reinicios del worker."""
    try:
        with open(CURRENT_MODEL_FILE, "w", encoding="utf-8") as f:
            f.write(model)
    except Exception:
        pass


def _load_current_model(config: configparser.ConfigParser) -> str:
    """Lee modelo persistido o cae en config.ini."""
    try:
        if os.path.exists(CURRENT_MODEL_FILE):
            with open(CURRENT_MODEL_FILE, "r", encoding="utf-8") as f:
                model = f.read().strip()
                if model:
                    return model
    except Exception:
        pass
    return config.get("llm", "model", fallback="unknown")


def _llama_server_is_ready(host: str, port: str) -> bool:
    """Verifica si llama-server responde a peticiones."""
    import requests
    for url in [f"http://{host}:{port}/health", f"http://{host}:{port}/v1/models"]:
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                return True
        except Exception:
            pass
    return False


def _llama_server_pid() -> Optional[int]:
    """Devuelve el PID de llama-server si está corriendo, o None."""
    try:
        result = subprocess.run(
            ["pgrep", "-f", "llama-server"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return int(result.stdout.strip().split()[0])
    except Exception:
        pass
    return None


def _restart_llama_server(config: configparser.ConfigParser, model: str, logger: logging.Logger) -> bool:
    """Asegura que llama-server esté corriendo con el modelo indicado.

    Si ya hay un proceso cargando, espera hasta 120s sin matarlo.
    Solo reinicia si no hay proceso o si no responde después de 120s.
    """
    try:
        exe = config.get("llama_server", "executable_path", fallback="llama-server")
        models_dir = config.get("llama_server", "models_dir", fallback="./models/")
        ctx = config.get("llama_server", "context_size", fallback="8192")
        host = config.get("llama_server", "host", fallback="0.0.0.0")
        port = config.get("llama_server", "port", fallback="8080")
        extra = config.get("llama_server", "extra_args", fallback="")

        # Buscar config específica del modelo
        model_name = os.path.splitext(model)[0]
        model_section = f"model_{model_name}"
        if model_section in config.sections():
            ctx = config.get(model_section, "context_size", fallback=ctx)
            extra = config.get(model_section, "extra_args", fallback=extra)
            logger.info("Usando config específica del modelo: %s (ctx=%s)", model_section, ctx)

        # Resolve executable path
        if not os.path.isabs(exe):
            resolved = shutil.which(exe)
            if resolved:
                exe = resolved
            elif os.path.exists(os.path.join(BASE_DIR, exe)):
                exe = os.path.join(BASE_DIR, exe)

        model_path = os.path.join(models_dir, model)
        if not os.path.isabs(model_path):
            model_path = os.path.join(BASE_DIR, model_path)

        if not os.path.exists(model_path):
            logger.error("Modelo no encontrado: %s", model_path)
            return False

        # Verificar si ya hay un proceso corriendo
        existing_pid = _llama_server_pid()
        if existing_pid:
            logger.info("llama-server ya está corriendo (PID %d). Verificando que responda...", existing_pid)
            for attempt in range(1, 61):
                if _llama_server_is_ready(host, port):
                    logger.info("llama-server respondiendo correctamente.")
                    return True
                time.sleep(2)
                if attempt % 10 == 0:
                    logger.info("Esperando llama-server... (%d/60)", attempt)
            logger.warning("llama-server no responde después de 120s. Reiniciando...")
            subprocess.run(["pkill", "-9", "-f", "llama-server"], capture_output=True)
            time.sleep(2)
        else:
            logger.info("No hay llama-server corriendo. Iniciando...")

        # Build args
        args = [exe, "-m", model_path, "-c", ctx, "--host", host, "--port", port]
        if extra:
            args.extend(extra.split())

        # Start new llama-server
        logger.info("Iniciando llama-server: %s", " ".join(args))
        subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        # Wait for server to be ready (poll every 2s, up to 120s)
        logger.info("Esperando a que llama-server esté listo...")
        for attempt in range(1, 61):
            time.sleep(2)
            if _llama_server_is_ready(host, port):
                logger.info("llama-server listo y respondiendo después de %ds.", attempt * 2)
                return True
            if attempt % 10 == 0:
                logger.info("Esperando llama-server... (%d/60)", attempt)

        logger.warning("llama-server iniciado pero no responde después de 120s.")
        return True

    except Exception as exc:
        logger.exception("Error reiniciando llama-server: %s", exc)
        return False


def apply_command(config_path: str, command: dict, logger: logging.Logger) -> bool:
    """Procesa un comando recibido del hosting.

    Retorna True solo si el worker completo debe reiniciarse (systemd).
    change_model ya no reinicia el worker — solo reinicia llama-server.
    """
    cmd = command.get("command")
    payload = command.get("payload") or {}

    if cmd == "restart":
        logger.info("Comando recibido: restart. Saliendo para reinicio por systemd.")
        return True

    if cmd == "change_model":
        model = payload.get("model") if payload else None
        if not model:
            logger.warning("Comando change_model sin payload válido")
            return False

        config = configparser.ConfigParser()
        config.read(config_path)
        old_model = config.get("llm", "model", fallback="unknown")
        config.set("llm", "model", model)

        with open(config_path, "w", encoding="utf-8") as f:
            config.write(f)

        _save_current_model(model)
        logger.info("Modelo cambiado en config: %s → %s", old_model, model)

        # Restart llama-server with new model (no reiniciar el worker)
        if _restart_llama_server(config, model, logger):
            logger.info("llama-server reiniciado con nuevo modelo. Worker continúa.")
        else:
            logger.error("No se pudo reiniciar llama-server con el nuevo modelo.")
        return False

    logger.warning("Comando desconocido: %s", cmd)
    return False


def main(config_path: Optional[str] = None) -> None:
    config = configparser.ConfigParser()
    config.read(config_path or DEFAULT_CONFIG)

    setup_logging(config)
    logger = logging.getLogger("worker")
    logger.info("OrinSec worker iniciado (v2)")

    # Asegurar que llama-server esté corriendo al inicio
    server_url = config.get("llm", "server_url", fallback="http://localhost:8080")
    try:
        from urllib.parse import urlparse
        parsed = urlparse(server_url)
        host = parsed.hostname or "localhost"
        port = str(parsed.port or "8080")
    except Exception:
        host, port = "localhost", "8080"

    current_model = _load_current_model(config)
    if not _llama_server_is_ready(host, port):
        logger.warning("llama-server no responde. Intentando iniciar automáticamente...")
        if _restart_llama_server(config, current_model, logger):
            logger.info("llama-server iniciado correctamente al arranque del worker.")
        else:
            logger.error("No se pudo iniciar llama-server automáticamente. Las tareas de LLM fallarán.")
    else:
        logger.info("llama-server ya está respondiendo en %s:%s", host, port)

    api = ApiClient(config_path or DEFAULT_CONFIG)
    poll_interval = config.getint("worker", "poll_interval", fallback=15)
    task_timeout = config.getint("worker", "task_timeout", fallback=120)
    heartbeat_interval = config.getint("worker", "heartbeat_interval", fallback=30)

    # Contador para heartbeat (no enviamos en cada poll)
    last_heartbeat = 0.0
    last_model = current_model

    while True:
        try:
            # ── 1. Heartbeat ──────────────────────────────────────────────
            now = time.time()
            if now - last_heartbeat >= heartbeat_interval:
                try:
                    metrics = get_metrics()
                    metrics["model_loaded"] = last_model
                    metrics["status"] = "online"
                    if api.send_heartbeat(metrics):
                        logger.debug("Heartbeat enviado")
                        last_heartbeat = now
                    else:
                        logger.warning("Heartbeat rechazado por el hosting")
                except Exception as exc:
                    logger.warning("Error enviando heartbeat: %s", exc)

            # ── 2. Comandos remotos ───────────────────────────────────────
            try:
                commands = api.get_commands()
                for cmd in commands:
                    if apply_command(config_path or DEFAULT_CONFIG, cmd, logger):
                        # Reinicio controlado: systemd levantará el proceso nuevo
                        sys.exit(0)
                # Releer config por si cambió el modelo (change_model no reinicia worker)
                config.read(config_path or DEFAULT_CONFIG)
                last_model = _load_current_model(config)
            except Exception as exc:
                logger.warning("Error consultando comandos: %s", exc)

            # ── 3. Tareas pendientes ──────────────────────────────────────
            try:
                tasks = api.get_pending_tasks()
            except Exception as exc:
                logger.error("Error consultando tareas: %s", exc)
                time.sleep(poll_interval)
                continue

            if not tasks:
                logger.debug("Sin tareas pendientes")
                time.sleep(poll_interval)
                continue

            for task in tasks:
                task_id = task.get("id")
                task_type = task.get("task_type")
                input_data = task.get("input_data", "{}")

                logger.info("Procesando tarea %s (tipo: %s)", task_id, task_type)

                # Verificar llama-server antes de cada tarea (protege contra OOM/crash)
                if not _llama_server_is_ready(host, port):
                    logger.warning("llama-server no responde antes de tarea %s. Reiniciando...", task_id)
                    if not _restart_llama_server(config, last_model, logger):
                        logger.error("No se pudo reiniciar llama-server. Saltando tarea %s.", task_id)
                        continue

                # Reclamar
                if not api.claim_task(task_id):
                    logger.warning("No se pudo reclamar tarea %s", task_id)
                    continue

                # Ejecutar
                task_class = TASK_REGISTRY.get(task_type)
                if not task_class:
                    logger.error("Tipo de tarea desconocido: %s", task_type)
                    api.send_error(task_id, f"Tipo de tarea desconocido: {task_type}")
                    continue

                try:
                    data = json.loads(input_data) if isinstance(input_data, str) else input_data
                    runner = task_class(config_path or DEFAULT_CONFIG)

                    # Timeout manual simple
                    start = time.time()
                    result = runner.execute(data)
                    elapsed = time.time() - start

                    if elapsed > task_timeout:
                        logger.warning("Tarea %s excedió timeout (%ss)", task_id, elapsed)

                    api.send_result(
                        task_id,
                        result_html=result.get("result_html", ""),
                        result_text=result.get("result_text", ""),
                    )
                    logger.info("Tarea %s completada en %.1fs", task_id, elapsed)

                except Exception as exc:
                    logger.exception("Error ejecutando tarea %s", task_id)
                    api.send_error(task_id, str(exc))

            time.sleep(poll_interval)

        except KeyboardInterrupt:
            logger.info("Worker detenido por usuario")
            break
        except Exception as exc:
            logger.exception("Error inesperado en el loop principal: %s", exc)
            time.sleep(poll_interval)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
