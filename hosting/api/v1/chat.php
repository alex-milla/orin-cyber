<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';

header('Content-Type: application/json');

// Capturar cualquier error PHP y devolverlo como JSON en vez de HTML
set_error_handler(function ($severity, $message, $file, $line) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'PHP Error: ' . $message]);
    exit;
});

set_exception_handler(function ($exception) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Exception: ' . $exception->getMessage()]);
    exit;
});

try {
    requireAuth();

    $method = $_SERVER['REQUEST_METHOD'];

    // ── POST: crear nueva petición de chat ──────────────────────────
    if ($method === 'POST') {
        $raw = file_get_contents('php://input');
        $data = json_decode($raw, true) ?: [];
        $message = trim($data['message'] ?? '');
        $systemPrompt = trim($data['system_prompt'] ?? '');

        if ($message === '') {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Mensaje vacío']);
            exit;
        }

        $inputData = json_encode([
            'message' => $message,
            'system_prompt' => $systemPrompt,
        ]);

        $taskId = Database::insert('tasks', [
            'task_type' => 'chat',
            'input_data' => $inputData,
            'status' => 'pending',
        ]);

        echo json_encode(['success' => true, 'task_id' => $taskId]);
        exit;
    }

    // ── GET: consultar estado/resultado de una tarea ────────────────
    if ($method === 'GET') {
        $taskId = isset($_GET['task_id']) ? (int)$_GET['task_id'] : 0;
        if ($taskId <= 0) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'task_id requerido']);
            exit;
        }

        $row = Database::fetchOne(
            "SELECT status, result_text, error_message, created_at, completed_at FROM tasks WHERE id = ?",
            [$taskId]
        );

        if (!$row) {
            http_response_code(404);
            echo json_encode(['success' => false, 'error' => 'Tarea no encontrada']);
            exit;
        }

        echo json_encode([
            'success' => true,
            'task_id' => $taskId,
            'status' => $row['status'],
            'response' => $row['result_text'] ?? null,
            'error' => $row['error_message'] ?? null,
            'created_at' => $row['created_at'],
            'completed_at' => $row['completed_at'],
        ]);
        exit;
    }

    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Método no permitido']);

} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Server error: ' . $e->getMessage()]);
}
