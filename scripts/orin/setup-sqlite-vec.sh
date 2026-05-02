#!/bin/bash
# OrinSec RAG Phase 2 — Instalación de sqlite-vec en el hosting
# Ejecutar en el servidor de hosting (PHP/SQLite)

set -euo pipefail

PHP_VERSION="${1:-8.2}"
EXTENSIONS_DIR="$(php -r 'echo ini_get("extension_dir");')"

echo "=========================================="
echo "  OrinSec — Setup sqlite-vec"
echo "=========================================="
echo "PHP version: $PHP_VERSION"
echo "Extension dir: $EXTENSIONS_DIR"
echo ""

# Detectar OS
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64) PLATFORM="x86_64-linux" ;;
            aarch64|arm64) PLATFORM="aarch64-linux" ;;
            *) echo "❌ Arquitectura no soportada: $ARCH"; exit 1 ;;
        esac
        ;;
    Darwin)
        case "$ARCH" in
            x86_64) PLATFORM="x86_64-darwin" ;;
            arm64) PLATFORM="aarch64-darwin" ;;
            *) echo "❌ Arquitectura no soportada: $ARCH"; exit 1 ;;
        esac
        ;;
    *)
        echo "❌ SO no soportado: $OS"
        exit 1
        ;;
esac

echo "→ Plataforma detectada: $PLATFORM"

# Descargar sqlite-vec dinámico
VEC_VERSION="0.1.6"
VEC_URL="https://github.com/asg017/sqlite-vec/releases/download/v${VEC_VERSION}/sqlite-vec-${VEC_VERSION}-${PLATFORM}.tar.gz"

echo "→ Descargando sqlite-vec v${VEC_VERSION}..."
cd /tmp
wget -q "$VEC_URL" -O sqlite-vec.tar.gz
tar -xzf sqlite-vec.tar.gz

echo "→ Instalando extensión..."
cp sqlite-vec.so "$EXTENSIONS_DIR/" || cp vec0.so "$EXTENSIONS_DIR/" || {
    echo "⚠️  No se pudo copiar a $EXTENSIONS_DIR"
    echo "   Copia manualmente: cp /tmp/sqlite-vec.so $EXTENSIONS_DIR/"
}

echo "→ Verificando..."
php -r "
\$db = new SQLite3(':memory:');
\$db->loadExtension('sqlite-vec');
echo 'sqlite-vec cargado OK\n';
\$db->exec('CREATE VIRTUAL TABLE test USING vec0(id INTEGER PRIMARY KEY, embedding FLOAT[4]);');
echo 'Tabla virtual creada OK\n';
"

echo ""
echo "✅ sqlite-vec instalado."
echo ""
echo "Nota: asegúrate de que tu php.ini tenga:"
echo "  extension=sqlite-vec.so"
echo "  sqlite3.extension_dir = $EXTENSIONS_DIR"
echo ""
