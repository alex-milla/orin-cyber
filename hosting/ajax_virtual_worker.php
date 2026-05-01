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

// Obtener nombre real del proveedor para executed_by
$provider = Database::fetchOne("SELECT label FROM external_providers WHERE id = ?", [$providerId]);
$providerLabel = $provider['label'] ?? 'Cloud';
$executedBy = "{$providerLabel} → {$modelId}";

function runVirtualTask(int $taskId, int $providerId, string $modelId, array $taskData): array {
    $worker = new VirtualWorker($providerId, $modelId, null);
    if ($taskData['task_type'] === 'cve_search') {
        $taskClass = CveSearchTaskPhp::class;
    } else {
        throw new RuntimeException("task_type desconocido: {$taskData['task_type']}");
    }
    $instance = new $taskClass($worker);
    $input = json_decode($taskData['input_data'], true) ?: [];
    return $instance->run($input);
}

try {
    $result = runVirtualTask($task['id'], $providerId, $modelId, $task);

    $html = ($result['result_html'] ?? '') . '<div class="cve-footer small" style="margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border);color:var(--text-muted);">🤖 Generado por: ' . htmlspecialchars($executedBy) . '</div>';

    Database::update('tasks', [
        'status'          => 'completed',
        'completed_at'    => date('Y-m-d H:i:s'),
        'result_html'     => $html,
        'result_text'     => $result['result_text'] ?? '',
        'executed_by'     => $executedBy,
        'cvss_base_score' => $result['cvss_base_score'] ?? null,
        'cvss_severity'   => $result['cvss_severity'] ?? null,
    ], 'id = ?', [$task['id']]);

    echo json_encode(['success' => true, 'processed' => 1, 'task_id' => $task['id']]);

} catch (Throwable $e) {
    $errMsg = $e->getMessage();

    // Fallback: si es error recuperable (no endpoints, rate limit, etc.), intentar con otro modelo
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
                // Pequeña espera para no bombardear la API si fue rate limit
                sleep(2);
                $result = runVirtualTask($task['id'], $providerId, $fallbackModelId, $task);

                $html = ($result['result_html'] ?? '') . '<div class="cve-footer small" style="margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border);color:var(--text-muted);">🤖 Generado por: ' . htmlspecialchars($fallbackExecutedBy) . '</div>';

                Database::update('tasks', [
                    'status'          => 'completed',
                    'completed_at'    => date('Y-m-d H:i:s'),
                    'result_html'     => $html,
                    'result_text'     => $result['result_text'] ?? '',
                    'executed_by'     => $fallbackExecutedBy,
                    'cvss_base_score' => $result['cvss_base_score'] ?? null,
                    'cvss_severity'   => $result['cvss_severity'] ?? null,
                ], 'id = ?', [$task['id']]);

                echo json_encode(['success' => true, 'processed' => 1, 'task_id' => $task['id'], 'fallback' => true]);
                exit;
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
    echo json_encode(['success' => false, 'error' => $errMsg]);
}
