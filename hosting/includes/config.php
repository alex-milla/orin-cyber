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
