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

// Obtener nombre real del proveedor para executed_by
$provider = Database::fetchOne("SELECT label FROM external_providers WHERE id = ?", [$providerId]);
$providerLabel = $provider['label'] ?? 'Cloud';
$executedBy = "{$providerLabel} → {$modelId}";

function runVirtualTask(int $taskId, int $providerId, string $modelId, array $taskData): array {
    $worker = new VirtualWorker($providerId, $modelId, null);
    $taskClass = match ($taskData['task_type']) {
        'cve_search' => CveSearchTaskPhp::class,
        default => throw new RuntimeException("task_type desconocido: {$taskData['task_type']}"),
    };
    $instance = new $taskClass($worker);
    $input = json_decode($taskData['input_data'], true) ?: [];
    return $instance->run($input);
}

try {
    $result = runVirtualTask($task['id'], $providerId, $modelId, $task);

    $html = ($result['result_html'] ?? '') . '<div class="cve-footer small" style="margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border);color:var(--text-muted);">🤖 Generado por: ' . htmlspecialchars($executedBy) . '</div>';

    Database::update('tasks', [
        'status'       => 'completed',
        'completed_at' => date('Y-m-d H:i:s'),
        'result_html'  => $html,
        'result_text'  => $result['result_text'] ?? '',
        'executed_by'  => $executedBy,
    ], 'id = ?', [$task['id']]);

    echo "Task {$task['id']} OK\n";

} catch (Throwable $e) {
    $errMsg = $e->getMessage();

    // Fallback: si es error recuperable, intentar con otro modelo del mismo proveedor
    $recoverable = str_contains($errMsg, 'No endpoints found')
                || str_contains($errMsg, 'Model not found')
                || str_contains($errMsg, 'Rate limit')
                || str_contains($errMsg, 'Too many requests')
                || str_contains($errMsg, 'Provider returned error');

    if ($recoverable) {
        $fallback = Database::fetchOne(
            "SELECT model_id, label FROM external_models
             WHERE provider_id = ? AND model_id != ? AND is_active = 1
             ORDER BY RANDOM() LIMIT 1",
            [$providerId, $modelId]
        );
        if ($fallback) {
            $fallbackModelId = $fallback['model_id'];
            $fallbackExecutedBy = "{$providerLabel} → {$fallbackModelId} (fallback desde {$modelId})";
            try {
                sleep(2);
                $result = runVirtualTask($task['id'], $providerId, $fallbackModelId, $task);

                $html = ($result['result_html'] ?? '') . '<div class="cve-footer small" style="margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border);color:var(--text-muted);">🤖 Generado por: ' . htmlspecialchars($fallbackExecutedBy) . '</div>';

                Database::update('tasks', [
                    'status'       => 'completed',
                    'completed_at' => date('Y-m-d H:i:s'),
                    'result_html'  => $html,
                    'result_text'  => $result['result_text'] ?? '',
                    'executed_by'  => $fallbackExecutedBy,
                ], 'id = ?', [$task['id']]);

                echo "Task {$task['id']} OK (fallback to {$fallbackModelId})\n";
                flock($fp, LOCK_UN);
                exit(0);
            } catch (Throwable $e2) {
                $errMsg = $e2->getMessage();
            }
        }
    }

    Database::update('tasks', [
        'status'        => 'error',
        'completed_at'  => date('Y-m-d H:i:s'),
        'error_message' => $errMsg,
        'executed_by'   => $executedBy,
    ], 'id = ?', [$task['id']]);
    echo "Task {$task['id']} ERROR: {$errMsg}\n";
}

flock($fp, LOCK_UN);
