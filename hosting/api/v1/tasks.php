<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/auth.php';

$keyRow = requireApiKey();

// Rate limiting específico para API del worker
$ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
$rateKey = 'api_rate_' . md5($ip);
$now = time();
$lockFile = DATA_DIR . '/.' . $rateKey . '.tmp';
$lastTime = file_exists($lockFile) ? (int)file_get_contents($lockFile) : 0;
if (($now - $lastTime) < 1) {
    jsonResponse(['error' => 'Rate limit exceeded'], 429);
}
file_put_contents($lockFile, (string)$now);

// Actualizar last_used de la API key
Database::query("UPDATE api_keys SET last_used = ? WHERE id = ?", [date('Y-m-d H:i:s'), $keyRow['id']]);

$action = $_GET['action'] ?? '';

// Auto-timeout tareas atascadas en processing (>15 min sin respuesta)
Database::query(
    "UPDATE tasks SET status = 'error', error_message = ?
     WHERE status = 'processing' AND started_at < datetime('now', '-15 minutes')",
    ['Timeout: el worker no respondió dentro del tiempo límite (15 min)']
);

switch ($action) {
    case 'pending':
        $task = Database::fetchOne(
            "SELECT id, task_type, input_data, status, created_at 
             FROM tasks 
             WHERE status = 'pending' 
             ORDER BY created_at ASC 
             LIMIT 1"
        );
        
        if (!$task) {
            jsonResponse(['tasks' => []]);
        }
        
        jsonResponse(['tasks' => [$task]]);
        break;

    case 'claim':
        $data = getJsonInput();
        $taskId = filter_var($data['task_id'] ?? 0, FILTER_VALIDATE_INT);
        
        if ($taskId <= 0) {
            jsonResponse(['error' => 'task_id requerido'], 400);
        }
        
        $updated = Database::update('tasks', [
            'status' => 'processing',
            'started_at' => date('Y-m-d H:i:s')
        ], 'id = ? AND status = ?', [$taskId, 'pending']);
        
        if ($updated === 0) {
            jsonResponse(['error' => 'Tarea no encontrada o ya reclamada'], 409);
        }
        
        jsonResponse(['success' => true, 'message' => 'Tarea reclamada']);
        break;

    case 'result':
        $data = getJsonInput();
        $taskId = filter_var($data['task_id'] ?? 0, FILTER_VALIDATE_INT);
        
        if ($taskId <= 0) {
            jsonResponse(['error' => 'task_id requerido'], 400);
        }
        
        $updateData = [
            'status' => 'completed',
            'completed_at' => date('Y-m-d H:i:s')
        ];
        
        if (isset($data['result_html']) && is_string($data['result_html'])) {
            $updateData['result_html'] = $data['result_html'];
        }
        if (isset($data['result_text']) && is_string($data['result_text'])) {
            $updateData['result_text'] = $data['result_text'];
        }
        if (isset($data['error_message']) && is_string($data['error_message'])) {
            $updateData['status'] = 'error';
            $updateData['error_message'] = $data['error_message'];
            unset($updateData['completed_at']);
        }
        
        Database::update('tasks', $updateData, 'id = ?', [$taskId]);
        
        jsonResponse(['success' => true, 'message' => 'Resultado recibido']);
        break;

    case 'cancel':
        $data = getJsonInput();
        $taskId = filter_var($data['task_id'] ?? 0, FILTER_VALIDATE_INT);
        
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
        break;

    default:
        jsonResponse(['error' => 'Acción no válida. Use pending, claim, result o cancel'], 400);
}
