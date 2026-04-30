<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/functions.php';

session_start();
if (!isLoggedIn()) {
    jsonResponse(['error' => 'No autorizado'], 401);
}

$action = $_GET['action'] ?? '';

switch ($action) {
    case 'sync':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            jsonResponse(['error' => 'Método no permitido'], 405);
        }
        verifyCsrf();
        $data = getJsonInput();
        $workspaceId = trim($data['workspace_id'] ?? '');
        $days = min(max((int)($data['days'] ?? 7), 1), 30);
        $incidentId = trim($data['incident_id'] ?? '');

        if (!$workspaceId) {
            jsonResponse(['error' => 'workspace_id requerido'], 400);
        }

        $taskInput = json_encode([
            'workspace_id' => $workspaceId,
            'days' => $days,
            'incident_id' => $incidentId,
        ]);
        $taskId = Database::insert('tasks', [
            'task_type' => 'azure_sync',
            'input_data' => $taskInput,
            'status' => 'pending',
        ]);

        jsonResponse(['success' => true, 'task_id' => $taskId, 'message' => 'Sync en curso. El worker procesará la consulta a Sentinel.']);
        break;

    case 'status':
        $taskId = (int)($_GET['task_id'] ?? 0);
        if (!$taskId) {
            jsonResponse(['error' => 'task_id requerido'], 400);
        }
        $task = Database::fetchOne("SELECT id, status, result_html, error_message FROM tasks WHERE id = ? AND task_type = 'azure_sync'", [$taskId]);
        if (!$task) {
            jsonResponse(['error' => 'Tarea no encontrada'], 404);
        }
        jsonResponse(['success' => true, 'task' => $task]);
        break;

    case 'hunting_queries':
        $incidentId = $_GET['incident_id'] ?? '';
        if (!$incidentId) {
            jsonResponse(['error' => 'incident_id requerido'], 400);
        }
        $queries = Database::fetchAll(
            "SELECT * FROM hunting_queries WHERE incident_id = ? ORDER BY created_at DESC",
            [$incidentId]
        );
        jsonResponse(['success' => true, 'queries' => $queries]);
        break;

    default:
        jsonResponse(['error' => 'Acción no válida'], 400);
}
