<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/functions.php';

requireAdmin();

$action = $_GET['action'] ?? '';

switch ($action) {
    case 'add_user':
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $isAdmin = !empty($_POST['is_admin']);

        if ($username === '' || $password === '') {
            jsonResponse(['error' => 'Usuario y contraseña requeridos'], 400);
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
