<?php
declare(strict_types=1);
/**
 * Migración: añade índices faltantes en SQLite para instalaciones existentes.
 * Ejecutar una sola vez tras actualizar a v0.5.8+.
 */

require_once __DIR__ . '/../includes/auth.php';
requireAdmin();

require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';

$db = Database::getInstance();

$db->exec("CREATE INDEX IF NOT EXISTS idx_tasks_status_created ON tasks(status, created_at)");
$db->exec("CREATE INDEX IF NOT EXISTS idx_apikeys_key_active ON api_keys(api_key, is_active)");
$db->exec("CREATE INDEX IF NOT EXISTS idx_heartbeats_apikey_created ON worker_heartbeats(api_key_id, created_at DESC)");
$db->exec("CREATE INDEX IF NOT EXISTS idx_commands_pending ON worker_commands(api_key_id, executed_at)");

echo "✅ Índices creados correctamente.\n";
