<?php
declare(strict_types=1);
/**
 * Endpoint: worker commands.
 * Devuelve comandos pendientes para este worker y los marca como enviados.
 * También permite actualizar el estado de un comando en ejecución.
 */
require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/auth.php';

$keyRow = requireApiKey();
$apiKeyId = $keyRow['id'];

$action = $_GET['action'] ?? '';

if ($action === 'update_status') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonResponse(['error' => 'Método no permitido'], 405);
    }
    $data = getJsonInput();
    $cmdId = filter_var($data['command_id'] ?? 0, FILTER_VALIDATE_INT);
    $status = validateInput($data['status'] ?? '', 20) ?? '';
    $message = isset($data['message']) ? substr((string)$data['message'], 0, 500) : '';

    $allowed = ['pending', 'executing', 'loading', 'ready', 'error'];
    if (!in_array($status, $allowed, true)) {
        jsonResponse(['error' => 'status inválido'], 400);
    }
    if (!$cmdId) {
        jsonResponse(['error' => 'command_id requerido'], 400);
    }

    Database::update('worker_commands', [
        'status' => $status,
        'status_message' => $message,
        'status_updated_at' => date('Y-m-d H:i:s'),
    ], 'id = ? AND api_key_id = ?', [$cmdId, $apiKeyId]);

    jsonResponse(['success' => true]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    jsonResponse(['error' => 'Método no permitido'], 405);
}

// Obtener comandos pendientes (sin executed_at o con status pending/executing)
$commands = Database::fetchAll(
    "SELECT id, command, payload, created_at
     FROM worker_commands
     WHERE api_key_id = ? AND executed_at IS NULL
     ORDER BY created_at ASC",
    [$apiKeyId]
);

// Marcar como enviados (executed_at = ahora) para no reenviarlos
if (!empty($commands)) {
    $ids = array_map(fn($c) => $c['id'], $commands);
    $placeholders = implode(',', array_fill(0, count($ids), '?'));
    Database::query(
        "UPDATE worker_commands SET executed_at = datetime('now') WHERE id IN ($placeholders)",
        $ids
    );
}

jsonResponse([
    'success' => true,
    'commands' => array_map(fn($c) => [
        'id' => $c['id'],
        'command' => $c['command'],
        'payload' => $c['payload'] ? json_decode($c['payload'], true) : null,
        'created_at' => $c['created_at'],
    ], $commands),
]);
