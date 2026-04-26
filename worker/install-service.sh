#!/bin/bash
# Instala el servicio systemd de OrinSec Worker

set -e

SERVICE_NAME="orinsec-worker"
SERVICE_FILE="orinsec-worker.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_FILE}"

echo "=== OrinSec Worker — Instalador de servicio systemd ==="

# Verificar que somos root
if [ "$EUID" -ne 0 ]; then
    echo "Este script debe ejecutarse con sudo."
    exit 1
fi

# Verificar que el servicio existe en el directorio actual
if [ ! -f "$SERVICE_FILE" ]; then
    echo "Error: No se encontró $SERVICE_FILE en el directorio actual."
    echo "Ejecutá este script desde ~/orinsec/worker/"
    exit 1
fi

# Copiar servicio
cp "$SERVICE_FILE" "$SERVICE_PATH"
chmod 644 "$SERVICE_PATH"

# Recargar systemd
systemctl daemon-reload

# Habilitar para inicio automático
systemctl enable "$SERVICE_NAME"

# Iniciar servicio
systemctl restart "$SERVICE_NAME"

echo ""
echo "✅ Servicio instalado y iniciado."
echo ""
echo "Comandos útiles:"
echo "  sudo systemctl status $SERVICE_NAME    # Ver estado"
echo "  sudo systemctl stop $SERVICE_NAME      # Detener"
echo "  sudo systemctl start $SERVICE_NAME     # Iniciar"
echo "  sudo systemctl restart $SERVICE_NAME   # Reiniciar"
echo "  sudo journalctl -u $SERVICE_NAME -f    # Ver logs en tiempo real"
echo ""
