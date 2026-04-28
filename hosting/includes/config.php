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

// Clave maestra para cifrado de API keys de proveedores externos
// Generar una vez con: bin2hex(random_bytes(32))
// En producción, leer de variable de entorno o archivo fuera del docroot
if (!defined('MASTER_ENCRYPTION_KEY')) {
    define('MASTER_ENCRYPTION_KEY', getenv('ORINSEC_MASTER_KEY') ?: 'CAMBIAR_ESTO_EN_PRODUCCION_64_HEX_CHARS__');
}
