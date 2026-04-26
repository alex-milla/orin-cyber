#!/usr/bin/env python3
"""Worker principal de OrinSec.

Consulta periódicamente el hosting por tareas pendientes, las ejecuta
y devuelve los resultados. Todo el tráfico es saliente (Orin → Hosting).
"""

import configparser
import logging
import os
import sys
import time
from typing import Optional

from utils.api_client import ApiClient
from tasks.cve_search import CveSearchTask

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(BASE_DIR, "config.ini")

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


def main(config_path: Optional[str] = None) -> None:
    config = configparser.ConfigParser()
    config.read(config_path or DEFAULT_CONFIG)

    setup_logging(config)
    logger = logging.getLogger("worker")
    logger.info("OrinSec worker iniciado")

    api = ApiClient(config_path or DEFAULT_CONFIG)
    poll_interval = config.getint("worker", "poll_interval", fallback=15)
    task_timeout = config.getint("worker", "task_timeout", fallback=120)

    while True:
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
                import json
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


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
