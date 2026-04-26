<?php
declare(strict_types=1);
/**
 * Endpoint: worker commands.
 * Devuelve comandos pendientes para este worker y los marca como enviados.
 */
require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/auth.php';

$keyRow = requireApiKey();
$apiKeyId = $keyRow['id'];

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    jsonResponse(['error' => 'Método no permitido'], 405);
}

// Obtener comandos pendientes
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
