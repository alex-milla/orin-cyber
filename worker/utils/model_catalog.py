"""
Catálogo auto-generado de modelos GGUF.
Genera worker/data/models.json a partir de los headers GGUF encontrados.
Se cachea por mtime para evitar releer archivos sin cambios.
"""
import json
import os
import time
from typing import Dict, Any, List, Optional

from utils.gguf_reader import read_gguf_metadata, get_quantization_name


def _catalog_path(data_dir: str = "./data") -> str:
    return os.path.join(data_dir, "models.json")


def _load_catalog(data_dir: str = "./data") -> Dict[str, Any]:
    """Carga el catálogo existente o retorna estructura vacía."""
    path = _catalog_path(data_dir)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"version": 1, "generated_at": None, "models": {}}


def _to_native(obj: Any) -> Any:
    """Convierte valores numpy a tipos nativos de Python recursivamente.

    gguf>=0.18 devuelve np.str_, np.int64, etc. json.dump no los soporta.
    Usamos duck-typing (.item() / .tolist()) para no depender de numpy.
    """
    if hasattr(obj, "item") and callable(getattr(obj, "item")):
        return obj.item()
    if hasattr(obj, "tolist") and callable(getattr(obj, "tolist")):
        return obj.tolist()
    if isinstance(obj, dict):
        return {k: _to_native(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_native(v) for v in obj]
    return obj


def _save_catalog(catalog: Dict[str, Any], data_dir: str = "./data") -> None:
    path = _catalog_path(data_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    catalog["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_to_native(catalog), f, indent=2, ensure_ascii=False)


def _recommended_context(file_size_mb: float, max_context: Optional[int]) -> int:
    """Heurística de contexto recomendado según tamaño del modelo y VRAM disponible.

    Jetson Orin Nano 8GB compartidos. Sistema usa ~1.5GB.
    Regla conservadora para mitigar bug de fragmentación CUDA en JetPack r36.4.7.
    """
    if file_size_mb <= 3000:
        ctx = 4096
    elif file_size_mb <= 5000:
        ctx = 2048
    else:
        ctx = 1536

    if max_context is not None:
        ctx = min(ctx, int(max_context))
    return ctx


def _expected_load_seconds(file_size_mb: float) -> int:
    """Estimación de segundos para cargar el modelo en llama-server.

    Aproximación empírica en Jetson Orin Nano con almacenamiento SD:
    ~2.5 s/GB para los primeros 3GB, luego se degrada un poco.
    """
    gb = file_size_mb / 1024
    if gb <= 3:
        return max(5, int(gb * 2.5))
    return max(10, int(3 * 2.5 + (gb - 3) * 3.5))


def _extra_args_for_arch(arch: str) -> str:
    """Devuelve argumentos extra recomendados según arquitectura del modelo.

    Flags conservadores para mitigar OOM/fragmentación en Jetson Orin Nano
    con JetPack r36.4.7. Phi-3/Phi-4 crashea con flash attention en build b8932.
    """
    base = "--cache-type-k q8_0 --cache-type-v q8_0 --batch-size 256 --ubatch-size 256 --no-mmap --mlock"
    if arch.lower().startswith("phi"):
        return base
    return f"-fa on {base}"


def _model_entry_from_metadata(meta: Dict[str, Any]) -> Dict[str, Any]:
    """Construye la entrada del catálogo a partir de metadatos GGUF."""
    file_size = meta.get("file_size_mb", 0)
    max_ctx = meta.get("max_context")
    return {
        "architecture": meta.get("architecture", ""),
        "name": meta.get("name", ""),
        "basename": meta.get("basename", ""),
        "size_label": meta.get("size_label", ""),
        "param_count": meta.get("param_count"),
        "quantization": get_quantization_name(meta["quantization"])
        if isinstance(meta.get("quantization"), int)
        else (meta.get("quantization") or ""),
        "recommended_context": _recommended_context(file_size, max_ctx),
        "expected_load_seconds": _expected_load_seconds(file_size),
        "extra_args": _extra_args_for_arch(meta.get("architecture", "")),
        "file_size_mb": file_size,
        "max_context": max_ctx,
        "block_count": meta.get("block_count"),
        "embedding_length": meta.get("embedding_length"),
        "vocab_size": meta.get("vocab_size"),
    }


def scan_and_update_catalog(
    models_dir: str,
    data_dir: str = "./data",
    logger=None,
) -> Dict[str, Any]:
    """Escanea models_dir, lee headers GGUF y genera/actualiza models.json.

    Retorna el catálogo actualizado.
    """
    catalog = _load_catalog(data_dir)
    existing = catalog.get("models", {})
    updated = False

    if not os.path.isdir(models_dir):
        if logger:
            logger.warning("models_dir no existe: %s", models_dir)
        return catalog

    current_files = set()
    for fname in sorted(os.listdir(models_dir)):
        if not fname.lower().endswith(".gguf"):
            continue
        path = os.path.join(models_dir, fname)
        mtime = os.path.getmtime(path)
        current_files.add(fname)

        # Cache por mtime
        entry = existing.get(fname)
        if entry and entry.get("_mtime") == mtime:
            continue

        if logger:
            logger.info("Analizando GGUF: %s", fname)

        try:
            meta = read_gguf_metadata(path)
        except Exception as exc:
            if logger:
                logger.warning("No se pudo leer %s: %s", fname, exc)
            continue

        if meta is None:
            continue

        entry = _model_entry_from_metadata(meta)
        entry["_mtime"] = mtime
        existing[fname] = entry
        updated = True

        if logger:
            logger.info(
                "Catálogo actualizado: %s (%s, ctx=%d, ~%ds carga)",
                fname,
                entry.get("size_label", "?"),
                entry["recommended_context"],
                entry["expected_load_seconds"],
            )

    # Eliminar entradas de modelos que ya no existen
    for fname in list(existing.keys()):
        if fname not in current_files:
            del existing[fname]
            updated = True
            if logger:
                logger.info("Modelo eliminado del catálogo: %s", fname)

    catalog["models"] = existing
    if updated:
        _save_catalog(catalog, data_dir)
    return catalog


def get_model_info(model_name: str, data_dir: str = "./data") -> Optional[Dict[str, Any]]:
    """Obtiene la info de un modelo desde el catálogo."""
    catalog = _load_catalog(data_dir)
    return catalog.get("models", {}).get(model_name)
