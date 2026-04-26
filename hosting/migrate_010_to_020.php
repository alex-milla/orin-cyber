<?php
declare(strict_types=1);
/**
 * Migración: añade tablas para worker monitoring y control remoto.
 * Ejecutar una sola vez tras actualizar a v0.2.0+.
 */
require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';

try {
    $db = Database::getInstance();

    $db->exec("CREATE TABLE IF NOT EXISTS worker_heartbeats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_key_id INTEGER NOT NULL,
        hostname TEXT,
        ip_address TEXT,
        cpu_percent REAL,
        memory_percent REAL,
        memory_total_mb INTEGER,
        memory_used_mb INTEGER,
        gpu_info TEXT,
        temperature_c REAL,
        disk_percent REAL,
        model_loaded TEXT,
        uptime_seconds INTEGER,
        status TEXT DEFAULT 'online',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
    )");

    $db->exec("CREATE INDEX IF NOT EXISTS idx_heartbeat_api_key ON worker_heartbeats(api_key_id)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_heartbeat_created ON worker_heartbeats(created_at)");

    $db->exec("CREATE TABLE IF NOT EXISTS worker_commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_key_id INTEGER NOT NULL,
        command TEXT NOT NULL,
        payload TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        executed_at DATETIME,
        FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
    )");

    $db->exec("CREATE INDEX IF NOT EXISTS idx_cmd_pending ON worker_commands(api_key_id, executed_at)");

    echo "✅ Migración completada. Tablas worker_heartbeats y worker_commands creadas.\n";
} catch (Exception $e) {
    http_response_code(500);
    echo "❌ Error: " . $e->getMessage() . "\n";
}
