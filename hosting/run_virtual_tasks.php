<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('CLI only');
}

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/crypto.php';
require_once __DIR__ . '/includes/external_client.php';
require_once __DIR__ . '/includes/virtual_worker.php';
require_once __DIR__ . '/includes/tasks/cve_search_task.php';

$LOCK = sys_get_temp_dir() . '/orin_virtual_worker.lock';
$fp = fopen($LOCK, 'c');
if (!$fp || !flock($fp, LOCK_EX | LOCK_NB)) {
    exit("Otra instancia ya está corriendo\n");
}

// Auto-timeout de tareas atascadas (>15 min)
Database::query(
    "UPDATE tasks SET status = 'error', error_message = ?
     WHERE status = 'processing' AND assignment LIKE 'provider:%'
       AND started_at < datetime('now', '-15 minutes')",
    ['Timeout: proveedor externo no respondió']
);

// Cargar 1 tarea pendiente virtual
$task = Database::fetchOne(
    "SELECT id, task_type, input_data, assignment
     FROM tasks
     WHERE status = 'pending' AND assignment LIKE 'provider:%'
     ORDER BY created_at ASC LIMIT 1"
);

if (!$task) {
    flock($fp, LOCK_UN);
    exit("Sin tareas pendientes\n");
}

// Reclamarla atómicamente
$claimed = Database::update('tasks',
    ['status' => 'processing', 'started_at' => date('Y-m-d H:i:s')],
    'id = ? AND status = ?', [$task['id'], 'pending']
);
if ($claimed === 0) {
    flock($fp, LOCK_UN);
    exit("Otra instancia ya la reclamó\n");
}

// Parsear assignment: provider:{id}:{model_id}
$parts = explode(':', $task['assignment'], 3);
if (count($parts) !== 3 || $parts[0] !== 'provider') {
    Database::update('tasks',
        ['status' => 'error', 'error_message' => 'Assignment inválido: ' . $task['assignment']],
        'id = ?', [$task['id']]
    );
    flock($fp, LOCK_UN);
    exit("Assignment inválido\n");
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
    ], 'id = ?', [$task['id']]);

    echo "Task {$task['id']} OK\n";

} catch (Throwable $e) {
    Database::update('tasks', [
        'status'        => 'error',
        'completed_at'  => date('Y-m-d H:i:s'),
        'error_message' => $e->getMessage(),
    ], 'id = ?', [$task['id']]);
    echo "Task {$task['id']} ERROR: {$e->getMessage()}\n";
}

flock($fp, LOCK_UN);
