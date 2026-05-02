#!/bin/bash
# OrinSec RAG Phase 2 — Instalación del servicio de embeddings
# Ejecutar como root en la Jetson Orin Nano

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="$SCRIPT_DIR/orinsec-embeddings.service"
MODEL_DIR="/home/orinsec/models"

echo "=========================================="
echo "  OrinSec — Setup Embeddings Service"
echo "=========================================="
echo ""

# Verificar que existe el modelo
if [ ! -f "$MODEL_DIR/bge-small-en-v1.5-q8_0.gguf" ]; then
    echo "⚠️  Modelo no encontrado en $MODEL_DIR"
    echo "   Ejecuta primero: ./download-embedding-model.sh"
    exit 1
fi

# Verificar llama-server
if [ ! -x "/home/orinsec/llama.cpp/build/bin/llama-server" ]; then
    echo "❌ llama-server no encontrado en /home/orinsec/llama.cpp/build/bin/llama-server"
    echo "   Compila llama.cpp primero."
    exit 1
fi

# Verificar usuario
if ! id orinsec &>/dev/null; then
    echo "→ Creando usuario orinsec..."
    useradd -r -m -s /bin/bash orinsec || true
fi

# Copiar servicio
echo "→ Instalando servicio systemd..."
cp "$SERVICE_FILE" /etc/systemd/system/orinsec-embeddings.service

# Permisos
chown orinsec:orinsec "$MODEL_DIR/bge-small-en-v1.5-q8_0.gguf"

# Recargar e iniciar
systemctl daemon-reload
systemctl enable orinsec-embeddings.service
systemctl restart orinsec-embeddings.service

echo ""
echo "✅ Servicio instalado y arrancado."
echo ""
echo "Comandos útiles:"
echo "  sudo systemctl status orinsec-embeddings"
echo "  sudo journalctl -u orinsec-embeddings -f"
echo "  curl http://127.0.0.1:8081/health"
echo ""
