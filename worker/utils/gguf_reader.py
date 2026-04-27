"""
Lector de metadatos GGUF.
Extrae información del header de archivos .gguf para auto-configuración.
Requiere: pip install gguf>=0.10
"""
import os
from typing import Dict, Any, Optional


def _get_field(reader, key: str, default: Any = None) -> Any:
    """Extrae un campo del header GGUF de forma segura."""
    try:
        field = reader.get_field(key)
        if field is None:
            return default
        # Los valores pueden ser escalares o listas
        val = field.parts[0] if field.parts else default
        return val if val is not None else default
    except Exception:
        return default


def read_gguf_metadata(path: str) -> Optional[Dict[str, Any]]:
    """Lee metadatos de un archivo .gguf.

    Retorna dict con:
        - architecture (str)
        - name (str)
        - basename (str)
        - size_label (str)          -- ej. "4B", "9B"
        - param_count (int|None)    -- estimación o del header
        - max_context (int|None)    -- context_length del modelo
        - file_size_mb (float)
        - quantization (str|None)   -- ej. "Q4_K_M"
        - vocab_size (int|None)
        - block_count (int|None)
        - embedding_length (int|None)
    """
    try:
        from gguf import GGUFReader
    except ImportError:
        raise RuntimeError(
            "La librería 'gguf' no está instalada. "
            "Ejecuta: pip install gguf>=0.10"
        ) from None

    if not os.path.exists(path):
        return None

    try:
        reader = GGUFReader(path)
    except Exception as exc:
        raise RuntimeError(f"No se pudo leer GGUF header de {path}: {exc}") from exc

    arch = _get_field(reader, "general.architecture", "")
    name = _get_field(reader, "general.name", "")
    basename = _get_field(reader, "general.basename", "")
    quantization = _get_field(reader, "general.file_type", None)
    max_context = _get_field(reader, f"{arch}.context_length", None)
    if max_context is None:
        max_context = _get_field(reader, "llama.context_length", None)
    embedding_length = _get_field(reader, f"{arch}.embedding_length", None)
    if embedding_length is None:
        embedding_length = _get_field(reader, "llama.embedding_length", None)
    block_count = _get_field(reader, f"{arch}.block_count", None)
    if block_count is None:
        block_count = _get_field(reader, "llama.block_count", None)
    vocab_size = _get_field(reader, f"{arch}.vocab_size", None)
    if vocab_size is None:
        vocab_size = _get_field(reader, "llama.vocab_size", None)

    # Estimar parámetros si el header no lo tiene directamente
    param_count = _get_field(reader, "general.parameter_count", None)
    if param_count is None and block_count and embedding_length:
        # Heurística estándar transformer: ~12 * n_layers * d_model^2 / (1024^3) en miles de millones
        # Simplificación: 2 * vocab_size * d_model + 12 * n_layers * d_model^2
        # Usamos una aproximación más ligera:
        # ~2 * n_layers * d_model^2  (cuenta parámetros de attention + FFN)
        try:
            d_model = int(embedding_length)
            n_layers = int(block_count)
            # Aproximación razonable para la mayoría de arquitecturas
            estimated = 2 * n_layers * d_model * d_model
            # Ajuste para vocab embedding
            if vocab_size:
                estimated += int(vocab_size) * d_model
            param_count = estimated
        except Exception:
            param_count = None

    # Determinar size_label (ej. "4B") a partir del param_count
    size_label = ""
    if param_count:
        billions = param_count / 1e9
        if billions >= 1:
            size_label = f"{billions:.1f}B".replace(".0B", "B")
        elif billions >= 0.1:
            size_label = f"{billions * 1000:.0f}M"
        else:
            size_label = f"{param_count:.0e}"
    elif basename:
        # Fallback: extraer número + B/M del nombre del archivo
        import re
        m = re.search(r'(\d+(?:\.\d+)?)\s?([BM])', basename)
        if m:
            size_label = f"{m.group(1)}{m.group(2)}"

    file_size_mb = os.path.getsize(path) / (1024 * 1024)

    return {
        "architecture": arch,
        "name": name or basename or os.path.basename(path),
        "basename": basename,
        "size_label": size_label,
        "param_count": param_count,
        "max_context": max_context,
        "file_size_mb": round(file_size_mb, 1),
        "quantization": quantization,
        "vocab_size": vocab_size,
        "block_count": block_count,
        "embedding_length": embedding_length,
    }


def get_quantization_name(file_type: int) -> str:
    """Mapea general.file_type (int) a nombre legible de cuantización."""
    mapping = {
        1: "F32",
        2: "F16",
        3: "Q4_0",
        4: "Q4_1",
        5: "Q4_1_SOME_F16",  # legacy
        6: "Q8_0",
        7: "Q5_0",
        8: "Q5_1",
        9: "Q2_K",
        10: "Q3_K_S",
        11: "Q3_K_M",
        12: "Q3_K_L",
        13: "Q4_K_S",
        14: "Q4_K_M",
        15: "Q5_K_S",
        16: "Q5_K_M",
        17: "Q6_K",
        18: "Q8_K",
    }
    return mapping.get(file_type, f"UNKNOWN({file_type})")
