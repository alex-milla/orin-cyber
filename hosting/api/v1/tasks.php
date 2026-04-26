<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/auth.php';

requireApiKey();

$action = $_GET['action'] ?? '';

switch ($action) {
    case 'pending':
        // Devuelve la tarea pendiente más antigua
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
        $taskId = (int) ($data['task_id'] ?? 0);
        
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
        $taskId = (int) ($data['task_id'] ?? 0);
        
        if ($taskId <= 0) {
            jsonResponse(['error' => 'task_id requerido'], 400);
        }
        
        $updateData = [
            'status' => 'completed',
            'completed_at' => date('Y-m-d H:i:s')
        ];
        
        if (isset($data['result_html'])) {
            $updateData['result_html'] = $data['result_html'];
        }
        if (isset($data['result_text'])) {
            $updateData['result_text'] = $data['result_text'];
        }
        if (isset($data['error_message'])) {
            $updateData['status'] = 'error';
            $updateData['error_message'] = $data['error_message'];
            unset($updateData['completed_at']);
        }
        
        Database::update('tasks', $updateData, 'id = ?', [$taskId]);
        
        jsonResponse(['success' => true, 'message' => 'Resultado recibido']);
        break;

    default:
        jsonResponse(['error' => 'Acción no válida. Use pending, claim o result'], 400);
}
