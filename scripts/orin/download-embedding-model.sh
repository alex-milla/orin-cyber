#!/bin/bash
# OrinSec RAG Phase 2 — Script de descarga del modelo de embeddings
# Ejecutar en la Jetson Orin Nano como usuario orinsec

set -euo pipefail

MODEL_DIR="${1:-/home/orinsec/models}"
MODEL_NAME="bge-small-en-v1.5-q8_0.gguf"
HF_REPO="BAAI/bge-small-en-v1.5"

# URL directa de HuggingFace (si existe GGUF preconvertido)
# Si no existe, se usará llama.cpp para convertir
GGUF_URL="https://huggingface.co/ChristianAzinn/bge-small-en-v1.5-gguf/resolve/main/bge-small-en-v1.5-q8_0.gguf"

echo "=========================================="
echo "  OrinSec — Descarga modelo embeddings"
echo "=========================================="
echo "Directorio destino: $MODEL_DIR"
echo "Modelo: $MODEL_NAME"
echo ""

mkdir -p "$MODEL_DIR"
cd "$MODEL_DIR"

if [ -f "$MODEL_NAME" ]; then
    echo "✓ El modelo ya existe: $MODEL_DIR/$MODEL_NAME"
    ls -lh "$MODEL_NAME"
    exit 0
fi

echo "→ Descargando $MODEL_NAME..."

# Intentar descarga directa del GGUF preconvertido
if command -v wget &>/dev/null; then
    wget --show-progress -O "$MODEL_NAME" "$GGUF_URL" || true
elif command -v curl &>/dev/null; then
    curl -L --progress-bar -o "$MODEL_NAME" "$GGUF_URL" || true
fi

if [ -f "$MODEL_NAME" ] && [ -s "$MODEL_NAME" ]; then
    echo "✓ Descarga completada: $MODEL_DIR/$MODEL_NAME"
    ls -lh "$MODEL_NAME"
    echo ""
    echo "→ Verificando integridad (magic bytes)..."
    file "$MODEL_NAME"
    head -c 4 "$MODEL_NAME" | xxd | head -1
    echo ""
    echo "✅ Listo. El modelo está en $MODEL_DIR/$MODEL_NAME"
    exit 0
fi

# Fallback: descargar desde HuggingFace con huggingface-cli
if command -v huggingface-cli &>/dev/null; then
    echo "→ Intentando descarga con huggingface-cli..."
    huggingface-cli download "$HF_REPO" --local-dir ./hf_tmp || true
    
    if [ -d "./hf_tmp" ]; then
        echo "→ Convirtiendo a GGUF con llama.cpp..."
        if [ -d "/home/orinsec/llama.cpp" ]; then
            python3 /home/orinsec/llama.cpp/convert-hf-to-gguf.py \
                ./hf_tmp \
                --outfile "$MODEL_NAME" \
                --outtype q8_0
        else
            echo "❌ llama.cpp no encontrado en /home/orinsec/llama.cpp"
            echo "   Clónalo primero: git clone https://github.com/ggml-org/llama.cpp"
            rm -rf ./hf_tmp
            exit 1
        fi
        rm -rf ./hf_tmp
        
        if [ -f "$MODEL_NAME" ]; then
            echo "✓ Conversión completada: $MODEL_DIR/$MODEL_NAME"
            ls -lh "$MODEL_NAME"
            exit 0
        fi
    fi
fi

echo ""
echo "❌ Error: no se pudo descargar ni convertir el modelo."
echo ""
echo "Opciones manuales:"
echo "  1. Descargar directo: wget -O $MODEL_NAME '$GGUF_URL'"
echo "  2. O desde HF: huggingface-cli download BAAI/bge-small-en-v1.5 --local-dir ./hf"
echo "  3. O convertir: python llama.cpp/convert-hf-to-gguf.py ./hf --outfile $MODEL_NAME --outtype q8_0"
echo ""
exit 1
