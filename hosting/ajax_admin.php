<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/functions.php';

requireAdmin();

$action = $_GET['action'] ?? '';

// Verificar CSRF para acciones destructivas
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

    default:
        jsonResponse(['error' => 'Acción no válida'], 400);
}
