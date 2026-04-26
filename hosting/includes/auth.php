<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/functions.php';

session_start();

function isLoggedIn(): bool {
    return isset($_SESSION['user_id']) && $_SESSION['user_id'] > 0;
}

function requireAuth(): void {
    if (!isLoggedIn()) {
        if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
            jsonResponse(['error' => 'No autenticado'], 401);
        }
        header('Location: login.php');
        exit;
    }
}

function loginUser(string $username, string $password): bool {
    $user = Database::fetchOne(
        'SELECT id, password_hash FROM users WHERE username = ?',
        [$username]
    );
    if (!$user) {
        return false;
    }
    if (!password_verify($password, $user['password_hash'])) {
        return false;
    }
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $username;
    return true;
}

function logoutUser(): void {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $params['path'],
            'secure' => $params['secure'],
            'httponly' => $params['httponly'],
            'samesite' => 'Strict'
        ]);
    }
    session_destroy();
}

function registerUser(string $username, string $password): bool {
    $hash = password_hash($password, PASSWORD_BCRYPT);
    try {
        Database::insert('users', [
            'username' => $username,
            'password_hash' => $hash
        ]);
        return true;
    } catch (PDOException $e) {
        return false;
    }
}
