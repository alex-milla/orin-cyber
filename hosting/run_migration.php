<?php
declare(strict_types=1);
/**
 * Script temporal para crear índices faltantes en instalaciones existentes.
 * Ejecutar una sola vez y eliminar inmediatamente después.
 */

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

requireAdmin();

try {
    $db = Database::getInstance();
    $db->exec("CREATE INDEX IF NOT EXISTS idx_tasks_status_created ON tasks(status, created_at)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_apikeys_key_active ON api_keys(api_key, is_active)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_heartbeats_apikey_created ON worker_heartbeats(api_key_id, created_at DESC)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_commands_pending ON worker_commands(api_key_id, executed_at)");
    echo "✅ Índices creados correctamente. Elimina este archivo ahora.\n";
} catch (Throwable $e) {
    echo "❌ Error: " . htmlspecialchars($e->getMessage()) . "\n";
}
