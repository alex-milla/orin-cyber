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

    case 'toggle_registration':
        $current = Database::fetchOne("SELECT value FROM config WHERE key = 'allow_registration'");
        $newValue = ($current && $current['value'] === '1') ? '0' : '1';
        Database::query("INSERT OR REPLACE INTO config (key, value) VALUES ('allow_registration', ?)", [$newValue]);
        jsonResponse(['success' => true, 'enabled' => $newValue === '1']);
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

    default:
        jsonResponse(['error' => 'Acción no válida'], 400);
}
