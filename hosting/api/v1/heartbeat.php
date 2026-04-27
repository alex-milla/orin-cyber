<?php
declare(strict_types=1);
/**
 * Endpoint: worker heartbeat.
 * Recibe métricas del worker y las almacena.
 */
require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/auth.php';

// Validar API key
$keyRow = requireApiKey();
$apiKeyId = $keyRow['id'];

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonResponse(['error' => 'Método no permitido'], 405);
}

$raw = file_get_contents('php://input');
$data = json_decode($raw, true);
if (!is_array($data)) {
    jsonResponse(['error' => 'JSON inválido'], 400);
}

// Validar campos obligatorios mínimos
$hostname = validateInput($data['hostname'] ?? '', 100) ?? 'unknown';
$recentLogs = validateInput($data['recent_logs'] ?? '', 20000);

// Insertar heartbeat
$availableModels = null;
if (isset($data['available_models']) && is_array($data['available_models'])) {
    $availableModels = json_encode($data['available_models']);
}

Database::query(
    "INSERT INTO worker_heartbeats
     (api_key_id, hostname, ip_address, cpu_percent, memory_percent, memory_total_mb, memory_used_mb,
      gpu_info, temperature_c, disk_percent, model_loaded, available_models, uptime_seconds, status, recent_logs)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [
        $apiKeyId,
        $hostname,
        $_SERVER['REMOTE_ADDR'] ?? null,
        filter_float($data['cpu_percent'] ?? null),
        filter_float($data['memory_percent'] ?? null),
        filter_int($data['memory_total_mb'] ?? null),
        filter_int($data['memory_used_mb'] ?? null),
        json_encode($data['gpu_info'] ?? null),
        filter_float($data['temperature_c'] ?? null),
        filter_float($data['disk_percent'] ?? null),
        validateInput($data['model_loaded'] ?? '', 100),
        $availableModels,
        filter_int($data['uptime_seconds'] ?? null),
        validateInput($data['status'] ?? 'online', 20) ?? 'online',
        $recentLogs,
    ]
);

// Limpiar heartbeats antiguos (mantener 7 días)
Database::query(
    "DELETE FROM worker_heartbeats WHERE created_at < datetime('now', '-7 days') AND api_key_id = ?",
    [$apiKeyId]
);

jsonResponse(['success' => true]);

function filter_float($val): ?float {
    if ($val === null || $val === '') return null;
    return is_numeric($val) ? (float)$val : null;
}

function filter_int($val): ?int {
    if ($val === null || $val === '') return null;
    return is_numeric($val) ? (int)$val : null;
}
