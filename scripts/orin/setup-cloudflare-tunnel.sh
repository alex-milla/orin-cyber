#!/bin/bash
# OrinSec RAG Phase 2 — Configuración del túnel Cloudflare para embeddings
# Ejecutar como root en la Jetson Orin Nano

set -euo pipefail

TUNNEL_NAME="${1:-orinsec-embed}"
TUNNEL_DOMAIN="${2:-embed-orin.cyberintelligence.dev}"
LOCAL_PORT=8081

echo "=========================================="
echo "  OrinSec — Setup Cloudflare Tunnel"
echo "=========================================="
echo "Nombre del túnel: $TUNNEL_NAME"
echo "Dominio: $TUNNEL_DOMAIN"
echo "Puerto local: $LOCAL_PORT"
echo ""

if ! command -v cloudflared &>/dev/null; then
    echo "❌ cloudflared no instalado. Instálalo primero:"
    echo "   wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
    echo "   sudo mv cloudflared-linux-arm64 /usr/local/bin/cloudflared"
    echo "   sudo chmod +x /usr/local/bin/cloudflared"
    exit 1
fi

# Verificar si ya existe el túnel
if cloudflared tunnel list | grep -q "$TUNNEL_NAME"; then
    echo "✓ El túnel '$TUNNEL_NAME' ya existe."
else
    echo "→ Creando túnel '$TUNNEL_NAME'..."
    cloudflared tunnel create "$TUNNEL_NAME"
fi

TUNNEL_ID=$(cloudflared tunnel list | grep "$TUNNEL_NAME" | awk '{print $1}')

echo "→ Tunnel ID: $TUNNEL_ID"

# Configurar DNS CNAME
echo "→ Configurando DNS CNAME $TUNNEL_DOMAIN..."
cloudflared tunnel route dns "$TUNNEL_NAME" "$TUNNEL_DOMAIN" || true

# Crear config.yml
echo "→ Escribiendo /root/.cloudflared/${TUNNEL_ID}.json y config.yml..."

cat > /root/.cloudflared/config.yml <<EOF
tunnel: ${TUNNEL_ID}
credentials-file: /root/.cloudflared/${TUNNEL_ID}.json

ingress:
  - hostname: ${TUNNEL_DOMAIN}
    service: http://localhost:${LOCAL_PORT}
  - service: http_status:404
EOF

# Instalar como servicio
if [ ! -f /etc/systemd/system/cloudflared-embed.service ]; then
    echo "→ Instalando servicio systemd..."
    cloudflared service install --config /root/.cloudflared/config.yml
    mv /etc/systemd/system/cloudflared.service /etc/systemd/system/cloudflared-embed.service || true
    systemctl daemon-reload
    systemctl enable cloudflared-embed
    systemctl start cloudflared-embed
else
    systemctl restart cloudflared-embed
fi

echo ""
echo "✅ Túnel configurado."
echo ""
echo "Verificación:"
echo "  curl https://${TUNNEL_DOMAIN}/health"
echo ""
echo "Comandos útiles:"
echo "  sudo systemctl status cloudflared-embed"
echo "  sudo journalctl -u cloudflared-embed -f"
echo ""
