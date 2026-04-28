<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/crypto.php';
require_once __DIR__ . '/includes/external_client.php';
require_once __DIR__ . '/includes/virtual_worker.php';
require_once __DIR__ . '/includes/tasks/cve_search_task.php';
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();
header('Content-Type: application/json');

// Validar CSRF
$csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf_token'] ?? '');
verifyCsrf($csrf);

// Auto-timeout tareas atascadas (>15 min)
Database::query(
    "UPDATE tasks SET status = 'error', error_message = ?
     WHERE status = 'processing' AND assignment LIKE 'provider:%'
       AND started_at < datetime('now', '-15 minutes')",
    ['Timeout: proveedor externo no respondió']
);

// Buscar una tarea pendiente virtual
$task = Database::fetchOne(
    "SELECT id, task_type, input_data, assignment
     FROM tasks
     WHERE status = 'pending' AND assignment LIKE 'provider:%'
     ORDER BY created_at ASC LIMIT 1"
);

if (!$task) {
    echo json_encode(['success' => true, 'processed' => 0]);
    exit;
}

// Reclamarla atómicamente
$claimed = Database::update('tasks',
    ['status' => 'processing', 'started_at' => date('Y-m-d H:i:s')],
    'id = ? AND status = ?', [$task['id'], 'pending']
);
if ($claimed === 0) {
    echo json_encode(['success' => true, 'processed' => 0]);
    exit;
}

// Parsear assignment: provider:{id}:{model_id}
$parts = explode(':', $task['assignment'], 3);
if (count($parts) !== 3 || $parts[0] !== 'provider') {
    Database::update('tasks',
        ['status' => 'error', 'error_message' => 'Assignment inválido: ' . $task['assignment']],
        'id = ?', [$task['id']]
    );
    echo json_encode(['success' => false, 'error' => 'Assignment inválido']);
    exit;
}

$providerId = (int)$parts[1];
$modelId = $parts[2];

try {
    $worker = new VirtualWorker($providerId, $modelId, null);

    $taskClass = match ($task['task_type']) {
        'cve_search' => CveSearchTaskPhp::class,
        default => throw new RuntimeException("task_type desconocido: {$task['task_type']}"),
    };

    $instance = new $taskClass($worker);
    $input = json_decode($task['input_data'], true) ?: [];
    $result = $instance->run($input);

    Database::update('tasks', [
        'status'       => 'completed',
        'completed_at' => date('Y-m-d H:i:s'),
        'result_html'  => $result['result_html'] ?? '',
        'result_text'  => $result['result_text'] ?? '',
        'executed_by'  => "OpenRouter → {$modelId}",
    ], 'id = ?', [$task['id']]);

    echo json_encode(['success' => true, 'processed' => 1, 'task_id' => $task['id']]);

} catch (Throwable $e) {
    Database::update('tasks', [
        'status'        => 'error',
        'completed_at'  => date('Y-m-d H:i:s'),
        'error_message' => $e->getMessage(),
    ], 'id = ?', [$task['id']]);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
