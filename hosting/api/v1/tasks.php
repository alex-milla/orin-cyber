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
            "SELECT id, task_type, input_data, status, created_at, assignment
             FROM tasks
             WHERE status = 'pending'
               AND (assignment = 'worker' OR assignment IS NULL)
               AND assignment NOT LIKE 'provider:%'
             ORDER BY created_at ASC LIMIT 1"
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

        $executedBy = 'Worker local';
        $html = $data['result_html'] ?? '';
        if ($html) {
            $html .= '<div class="cve-footer small" style="margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border);color:var(--text-muted);">🤖 Generado por: ' . $executedBy . '</div>';
        }
        
        $updateData = [
            'status' => 'completed',
            'completed_at' => date('Y-m-d H:i:s'),
            'executed_by' => $executedBy,
            'result_html' => $html,
            'result_text' => $data['result_text'] ?? null,
        ];

        if (isset($data['cvss_score']) && is_numeric($data['cvss_score'])) {
            $updateData['cvss_base_score'] = (float)$data['cvss_score'];
        }
        if (isset($data['severity']) && is_string($data['severity'])) {
            $updateData['cvss_severity'] = strtoupper($data['severity']);
        }
        
        if (isset($data['error_message']) && is_string($data['error_message'])) {
            $updateData['status'] = 'error';
            $updateData['error_message'] = $data['error_message'];
            unset($updateData['completed_at']);
        }
        
        Database::update('tasks', $updateData, 'id = ?', [$taskId]);

        // ── Post-procesamiento para tareas Blue Team ─────────────────────
        $task = Database::fetchOne("SELECT task_type, input_data FROM tasks WHERE id = ?", [$taskId]);
        if ($task && $task['task_type'] === 'incident_analysis') {
            $input = json_decode($task['input_data'] ?? '{}', true);
            $incidentId = $input['incident_id'] ?? '';
            if ($incidentId) {
                $btUpdate = [
                    'result_html' => $html,
                    'result_text' => $data['result_text'] ?? null,
                ];
                if (isset($data['blue_team_verdict']) && is_string($data['blue_team_verdict'])) {
                    $v = $data['blue_team_verdict'];
                    if (in_array($v, ['True Positive', 'False Positive', 'Needs Review'], true)) {
                        $btUpdate['llm_verdict'] = $v;
                    }
                }
                if (isset($data['blue_team_mitre_tactic']) && is_string($data['blue_team_mitre_tactic'])) {
                    $btUpdate['mitre_tactic'] = $data['blue_team_mitre_tactic'];
                }
                if (isset($data['blue_team_classification']) && is_string($data['blue_team_classification'])) {
                    $c = $data['blue_team_classification'];
                    if (in_array($c, ['GENERICO', 'DIRIGIDO'], true)) {
                        $btUpdate['description'] = ($btUpdate['description'] ?? '') . "\nClasificación: {$c}";
                    }
                }
                Database::update('incidents', $btUpdate, 'incident_id = ?', [$incidentId]);

                // Guardar queries KQL de hunting
                if (isset($data['hunting_queries']) && is_string($data['hunting_queries'])) {
                    $hqs = json_decode($data['hunting_queries'], true);
                    if (is_array($hqs)) {
                        foreach ($hqs as $hq) {
                            if (!empty($hq['kql'])) {
                                Database::query(
                                    "INSERT OR IGNORE INTO hunting_queries (incident_id, query_type, query_text, description) VALUES (?, ?, ?, ?)",
                                    [$incidentId, $hq['type'] ?? 'kql', $hq['kql'], 'Auto-generada para ' . ($hq['target'] ?? '')]
                                );
                            }
                        }
                    }
                }
            }
        }

        // ── Post-procesamiento para tareas Azure Sync ────────────────────
        if ($task && $task['task_type'] === 'azure_sync') {
            $input = json_decode($task['input_data'] ?? '{}', true);
            if (isset($data['azure_sync_extracted']) && is_string($data['azure_sync_extracted'])) {
                $incidents = json_decode($data['azure_sync_extracted'], true);
                if (is_array($incidents)) {
                    foreach ($incidents as $inc) {
                        if (empty($inc['incident_id'])) continue;
                        $existing = Database::fetchOne("SELECT 1 FROM incidents WHERE incident_id = ?", [$inc['incident_id']]);
                        if (!$existing) {
                            Database::insert('incidents', [
                                'incident_id' => $inc['incident_id'],
                                'sentinel_number' => $inc['sentinel_number'] ?? null,
                                'title' => $inc['title'] ?? '',
                                'description' => $inc['description'] ?? '',
                                'severity' => $inc['severity'] ?? 'Medium',
                                'status' => $inc['status'] ?? 'open',
                                'source' => 'sentinel',
                                'created_time' => $inc['created_time'] ?? date('Y-m-d H:i:s'),
                                'raw_data' => $inc['raw_data'] ?? '',
                            ]);
                        }
                    }
                }
            }
        }

        jsonResponse(['success' => true, 'message' => 'Resultado recibido']);
        break;

    case 'cancel':
        $data = getJsonInput();
        $taskId = filter_var($data['task_id'] ?? 0, FILTER_VALIDATE_INT);
        $result = cancelTaskById($taskId);
        if (!$result['ok']) {
            jsonResponse(['error' => $result['error']], $result['code']);
        }
        jsonResponse(['success' => true, 'message' => 'Tarea cancelada']);
        break;

    case 'config':
        $pref = Database::fetchOne("SELECT value FROM config WHERE key = 'preferred_model'");
        jsonResponse([
            'success' => true,
            'preferred_model' => $pref['value'] ?? null,
        ]);
        break;

    default:
        jsonResponse(['error' => 'Acción no válida. Use pending, claim, result, cancel o config'], 400);
}
