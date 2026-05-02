#!/bin/bash
# OrinSec RAG Phase 2 — Script maestro de instalación
# Este script orquesta todos los pasos de la Fase 2 en la Orin Nano.
# Ejecutar como root en la Jetson Orin Nano.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIN_DIR="$SCRIPT_DIR/orin"

echo "=========================================="
echo "  OrinSec RAG — Fase 2 Setup Completo"
echo "=========================================="
echo ""
echo "Este script instala:"
echo "  1. Modelo de embeddings (bge-small-en-v1.5-q8_0.gguf)"
echo "  2. Servicio systemd orinsec-embeddings (:8081)"
echo "  3. Túnel Cloudflare para embed-orin.cyberintelligence.dev"
echo ""

# ========== PRE-CHECKS ==========
if [ "$EUID" -ne 0 ]; then
    echo "❌ Este script debe ejecutarse como root (sudo)"
    exit 1
fi

if [ ! -d "/home/orinsec/llama.cpp" ]; then
    echo "⚠️  /home/orinsec/llama.cpp no encontrado."
    echo "   Asegúrate de que llama.cpp esté compilado en esa ruta."
    read -p "¿Continuar de todos modos? (s/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Ss]$ ]]; then
        exit 1
    fi
fi

# ========== PASO 1: MODELO ==========
echo ""
echo "[1/3] Descargando modelo de embeddings..."
bash "$ORIN_DIR/download-embedding-model.sh"

# ========== PASO 2: SERVICIO SYSTEMD ==========
echo ""
echo "[2/3] Instalando servicio systemd..."
bash "$ORIN_DIR/setup-embeddings-service.sh"

# ========== PASO 3: TÚNEL CLOUDFLARE ==========
echo ""
echo "[3/3] Configurando túnel Cloudflare..."
echo ""
echo "⚠️  ATENCIÓN: Para crear el túnel necesitas:"
echo "   - cloudflared instalado y autenticado"
echo "   - Dominio configurado en Cloudflare"
echo ""
read -p "¿Configurar túnel Cloudflare ahora? (s/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Ss]$ ]]; then
    read -p "Nombre del túnel [orinsec-embed]: " tunnel_name
    tunnel_name="${tunnel_name:-orinsec-embed}"
    read -p "Dominio [embed-orin.cyberintelligence.dev]: " tunnel_domain
    tunnel_domain="${tunnel_domain:-embed-orin.cyberintelligence.dev}"
    bash "$ORIN_DIR/setup-cloudflare-tunnel.sh" "$tunnel_name" "$tunnel_domain"
else
    echo "   (Omitido. Puedes ejecutar setup-cloudflare-tunnel.sh más tarde)"
fi

# ========== VERIFICACIÓN ==========
echo ""
echo "=========================================="
echo "  Verificación"
echo "=========================================="
echo ""

sleep 2

if systemctl is-active --quiet orinsec-embeddings; then
    echo "✅ orinsec-embeddings.service: ACTIVO"
else
    echo "❌ orinsec-embeddings.service: INACTIVO"
    echo "   sudo systemctl status orinsec-embeddings"
fi

if curl -sf http://127.0.0.1:8081/health >/dev/null 2>&1; then
    echo "✅ Health check localhost:8081: OK"
else
    echo "⚠️  Health check localhost:8081: SIN RESPUESTA"
    echo "   (El servicio puede estar iniciando, espera 10s)"
fi

echo ""
echo "=========================================="
echo "  ✅ Fase 2 completada en la Orin Nano"
echo "=========================================="
echo ""
echo "Próximo paso: en el servidor de hosting ejecuta:"
echo "  bash scripts/orin/setup-sqlite-vec.sh"
echo ""
echo "Y actualiza hosting/includes/config.php:"
echo "  define('LOCAL_EMBED_URL', 'https://embed-orin.cyberintelligence.dev');"
echo ""
