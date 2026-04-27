<?php
/**
 * Script de diagnóstico temporal: muestra el último heartbeat y recent_logs de cada worker.
 * Accede desde el navegador: https://tudominio.com/hosting/dev/check_logs.php
 */
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';

header('Content-Type: text/plain; charset=utf-8');

echo "=== Últimos heartbeats por worker ===\n\n";

$workers = Database::fetchAll("SELECT id, name, api_key FROM api_keys ORDER BY id");
foreach ($workers as $w) {
    $hb = Database::fetchOne(
        "SELECT created_at, recent_logs, model_loaded FROM worker_heartbeats WHERE api_key_id = ? ORDER BY created_at DESC LIMIT 1",
        [$w['id']]
    );
    echo "Worker: {$w['name']} (ID {$w['id']})\n";
    if ($hb) {
        echo "  Último heartbeat: {$hb['created_at']}\n";
        echo "  Modelo: {$hb['model_loaded']}\n";
        $logs = $hb['recent_logs'] ?? null;
        if ($logs !== null && $logs !== '') {
            echo "  Logs recibidos: " . strlen($logs) . " bytes\n";
            echo "  Primeras 200 chars:\n" . substr($logs, 0, 200) . "\n";
        } else {
            echo "  Logs recibidos: VACÍO o NULL\n";
        }
    } else {
        echo "  Sin heartbeats\n";
    }
    echo "\n";
}
