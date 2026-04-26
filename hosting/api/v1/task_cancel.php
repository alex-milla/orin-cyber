<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/../../includes/auth.php';

requireAuth();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonResponse(['error' => 'Método no permitido'], 405);
}

$data = getJsonInput();
$taskId = filter_var($data['task_id'] ?? 0, FILTER_VALIDATE_INT);
$token = $data['csrf_token'] ?? '';

verifyCsrf($token);

if ($taskId <= 0) {
    jsonResponse(['error' => 'task_id requerido'], 400);
}

$updated = Database::update(
    'tasks',
    [
        'status' => 'cancelled',
        'completed_at' => date('Y-m-d H:i:s'),
        'error_message' => 'Cancelada por el usuario'
    ],
    'id = ? AND status IN (?, ?)',
    [$taskId, 'pending', 'processing']
);

if ($updated === 0) {
    jsonResponse(['error' => 'Tarea no encontrada o ya finalizada'], 409);
}

jsonResponse(['success' => true, 'message' => 'Tarea cancelada']);
