"""Clase base para tareas del worker."""

import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class BaseTask(ABC):
    task_type: str = ""

    @abstractmethod
    def execute(self, input_data: dict[str, Any]) -> dict[str, str]:
        """
        Ejecuta la tarea y devuelve un dict con:
        - result_html: str
        - result_text: str
        """
        pass
