<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/functions.php';

requireAuth();

checkRateLimit();

$taskId = isset($_GET['task_id']) ? (int)$_GET['task_id'] : 0;

if ($taskId <= 0) {
    jsonResponse(['error' => 'task_id inválido'], 400);
}

$task = Database::fetchOne(
    'SELECT id, status, result_html, result_text, error_message, created_at, started_at, completed_at 
     FROM tasks WHERE id = ?',
    [$taskId]
);

if (!$task) {
    jsonResponse(['error' => 'Tarea no encontrada'], 404);
}

jsonResponse([
    'id' => $task['id'],
    'status' => $task['status'],
    'result_html' => $task['result_html'],
    'result_text' => $task['result_text'],
    'error_message' => $task['error_message'],
    'created_at' => $task['created_at'],
    'started_at' => $task['started_at'],
    'completed_at' => $task['completed_at']
]);
