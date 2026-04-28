<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/functions.php';

requireAdmin();

$action = $_GET['action'] ?? '';

// Verificar CSRF para todas las acciones
$token = $_POST['csrf_token'] ?? ($_GET['csrf_token'] ?? '');
if (!hash_equals($_SESSION['csrf_token'] ?? '', $token)) {
    jsonResponse(['error' => 'Token CSRF inválido'], 403);
}

switch ($action) {
    case 'add_user':
        $username = validateInput($_POST['username'] ?? '', 64);
        $password = $_POST['password'] ?? '';
        $isAdmin = !empty($_POST['is_admin']);

        if (!$username || strlen($username) < 3) {
            jsonResponse(['error' => 'Usuario inválido (mínimo 3 caracteres)'], 400);
        }
        if (strlen($password) < 8) {
            jsonResponse(['error' => 'La contraseña debe tener al menos 8 caracteres'], 400);
        }

        if (registerUser($username, $password, $isAdmin)) {
            jsonResponse(['success' => true]);
        } else {
            jsonResponse(['error' => 'No se pudo crear el usuario (¿ya existe?)'], 409);
        }
        break;

    case 'save_github_pat':
        $pat = trim($_POST['pat'] ?? '');
        // Aceptar tokens clásicos (ghp_xxx) y fine-grained (github_pat_xxx)
        if ($pat !== '' && !preg_match('/^(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})$/', $pat)) {
            jsonResponse(['error' => 'El token no tiene el formato válido de un GitHub PAT'], 400);
        }
        Database::query("INSERT OR REPLACE INTO config (key, value) VALUES ('github_pat', ?)", [$pat]);
        jsonResponse(['success' => true]);
        break;

    case 'toggle_registration':
        $current = Database::fetchOne("SELECT value FROM config WHERE key = 'allow_registration'");
        $newValue = ($current && $current['value'] === '1') ? '0' : '1';
        Database::query("INSERT OR REPLACE INTO config (key, value) VALUES ('allow_registration', ?)", [$newValue]);
        jsonResponse(['success' => true, 'enabled' => $newValue === '1']);
        break;

    case 'save_default_executor':
        $executor = $_POST['executor'] ?? '';
        if ($executor !== 'worker' && !str_starts_with($executor, 'provider:')) {
            jsonResponse(['error' => 'Ejecutor no válido'], 400);
        }
        Database::query("INSERT OR REPLACE INTO config (key, value) VALUES ('default_task_executor', ?)", [$executor]);
        jsonResponse(['success' => true]);
        break;

    case 'add_api_key':
        $name = validateInput($_POST['name'] ?? '', 100);
        if (!$name || strlen($name) < 2) {
            jsonResponse(['error' => 'Nombre inválido'], 400);
        }
        $newKey = generateSecureToken(32);
        try {
            Database::insert('api_keys', ['name' => $name, 'api_key' => $newKey]);
            jsonResponse(['success' => true, 'api_key' => $newKey]);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'No se pudo crear la API key'], 500);
        }
        break;

    case 'revoke_api_key':
        $id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
        if (!$id) jsonResponse(['error' => 'ID inválido'], 400);
        Database::update('api_keys', ['is_active' => 0], 'id = ?', [$id]);
        jsonResponse(['success' => true]);
        break;

    case 'activate_api_key':
        $id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
        if (!$id) jsonResponse(['error' => 'ID inválido'], 400);
        Database::update('api_keys', ['is_active' => 1], 'id = ?', [$id]);
        jsonResponse(['success' => true]);
        break;

    case 'regenerate_api_key':
        $id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
        if (!$id) jsonResponse(['error' => 'ID inválido'], 400);
        $newKey = generateSecureToken(32);
        Database::update('api_keys', ['api_key' => $newKey], 'id = ?', [$id]);
        jsonResponse(['success' => true, 'api_key' => $newKey]);
        break;

    case 'delete_api_key':
        $id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
        if (!$id) jsonResponse(['error' => 'ID inválido'], 400);
        Database::query("DELETE FROM api_keys WHERE id = ?", [$id]);
        jsonResponse(['success' => true]);
        break;

    case 'send_worker_command':
        $apiKeyId = filter_input(INPUT_POST, 'api_key_id', FILTER_VALIDATE_INT);
        $command = validateInput($_POST['command'] ?? '', 50);
        $payload = $_POST['payload'] ?? '';

        if (!$apiKeyId) {
            jsonResponse(['error' => 'Worker no válido'], 400);
        }
        if (!in_array($command, ['change_model', 'restart'], true)) {
            jsonResponse(['error' => 'Comando no válido'], 400);
        }

        // Validar que el payload sea JSON válido (o vacío)
        if ($payload !== '' && json_decode($payload) === null && json_last_error() !== JSON_ERROR_NONE) {
            jsonResponse(['error' => 'Payload JSON inválido'], 400);
        }

        $cmdId = Database::insert('worker_commands', [
            'api_key_id' => $apiKeyId,
            'command' => $command,
            'payload' => $payload !== '' ? $payload : null,
        ]);
        jsonResponse(['success' => true, 'command_id' => $cmdId]);
        break;

    case 'command_status':
        $cmdId = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
        if (!$cmdId) {
            jsonResponse(['error' => 'ID requerido'], 400);
        }
        $cmd = Database::fetchOne(
            "SELECT status, status_message, status_updated_at FROM worker_commands WHERE id = ?",
            [$cmdId]
        );
        if (!$cmd) {
            jsonResponse(['error' => 'Comando no encontrado'], 404);
        }
        jsonResponse([
            'success' => true,
            'status' => $cmd['status'] ?: 'pending',
            'message' => $cmd['status_message'] ?? '',
            'updated_at' => $cmd['status_updated_at'] ?? '',
        ]);
        break;

    case 'worker_logs':
        $apiKeyId = filter_input(INPUT_GET, 'api_key_id', FILTER_VALIDATE_INT);
        if (!$apiKeyId) {
            jsonResponse(['error' => 'api_key_id requerido'], 400);
        }
        $hb = Database::fetchOne(
            "SELECT recent_logs FROM worker_heartbeats WHERE api_key_id = ? ORDER BY created_at DESC LIMIT 1",
            [$apiKeyId]
        );
        jsonResponse([
            'success' => true,
            'recent_logs' => $hb['recent_logs'] ?? '',
        ]);
        break;

    case 'cancel_task':
        $taskId = filter_input(INPUT_POST, 'task_id', FILTER_VALIDATE_INT);
        $result = cancelTaskById($taskId);
        if (!$result['ok']) {
            jsonResponse(['error' => $result['error']], $result['code']);
        }
        jsonResponse(['success' => true, 'message' => 'Tarea cancelada']);
        break;

    case 'add_alert_subscription':
        $type = validateInput($_POST['type'] ?? '', 20);
        $value = validateInput($_POST['value'] ?? '', 100);
        $threshold = validateInput($_POST['severity_threshold'] ?? '', 20);

        if (!in_array($type, ['product', 'vendor', 'keyword', 'severity'], true)) {
            jsonResponse(['error' => 'Tipo de suscripción inválido'], 400);
        }
        if (!$value || strlen($value) < 2) {
            jsonResponse(['error' => 'Valor inválido (mínimo 2 caracteres)'], 400);
        }

        try {
            Database::insert('alert_subscriptions', [
                'type' => $type,
                'value' => $value,
                'severity_threshold' => $threshold ?: 'LOW',
                'active' => 1,
            ]);
            jsonResponse(['success' => true]);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'No se pudo crear la suscripción'], 500);
        }
        break;

    default:
        jsonResponse(['error' => 'Acción no válida'], 400);
}
