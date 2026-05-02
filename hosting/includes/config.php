<?php
declare(strict_types=1);

/**
 * Configuración global del hosting OrinSec
 */

if (PHP_SAPI === 'cli') {
    define('BASE_DIR', dirname(__DIR__, 1));
} else {
    define('BASE_DIR', dirname(__DIR__, 1));
}

define('DATA_DIR', BASE_DIR . '/data');
define('DB_PATH', DATA_DIR . '/orinsec.db');

if (!defined('API_KEY_HEADER')) {
    define('API_KEY_HEADER', 'X-API-Key');
}

define('RATE_LIMIT_SECONDS', 1);
date_default_timezone_set('Europe/Madrid');

// URL pública del llama-server (Cloudflare Tunnel desde el Orin Nano)
// Se usa para el chat y otras funciones que requieren conexión directa al modelo local
define('LOCAL_LLM_URL', 'https://chat-orin.cyberintelligence.dev');

// URL del servicio de embeddings (mismo Orin, distinto puerto/túnel)
// Fase 2: cambiar a https://embed-orin.cyberintelligence.dev cuando el túnel esté listo
define('LOCAL_EMBED_URL', 'http://127.0.0.1:8081');

// Configuración del modelo de embeddings
define('EMBEDDING_MODEL', 'bge-small-en-v1.5');
define('EMBEDDING_DIM', 384);

// Política de overflow de cola RAG: 'reject_429' | 'cloud_fallback' | 'sync_only_degraded'
define('RAG_OVERFLOW_POLICY', 'reject_429');

// Clave maestra para cifrado de API keys de proveedores externos
// Generar una vez con: bin2hex(random_bytes(32))
// En producción, leer de variable de entorno o archivo fuera del docroot
if (!defined('MASTER_ENCRYPTION_KEY')) {
    define('MASTER_ENCRYPTION_KEY', getenv('ORINSEC_MASTER_KEY') ?: 'CAMBIAR_ESTO_EN_PRODUCCION_64_HEX_CHARS__');
}
