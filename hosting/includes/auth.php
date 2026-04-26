<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/functions.php';

// Configurar cookies de sesión ANTES de session_start()
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');

session_start();

function isLoggedIn(): bool {
    return isset($_SESSION['user_id']) && $_SESSION['user_id'] > 0;
}

function isAdmin(): bool {
    return isLoggedIn() && !empty($_SESSION['is_admin']);
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

function requireAdmin(): void {
    requireAuth();
    if (!isAdmin()) {
        if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
            jsonResponse(['error' => 'Acceso denegado'], 403);
        }
        header('Location: index.php');
        exit;
    }
}

function loginUser(string $username, string $password): array {
    // Anti brute-force
    if (!checkBruteForce($username)) {
        return ['success' => false, 'error' => 'Demasiados intentos. Espera 5 minutos.'];
    }

    $user = Database::fetchOne(
        'SELECT id, password_hash, is_admin FROM users WHERE username = ?',
        [$username]
    );
    
    if (!$user || !password_verify($password, $user['password_hash'])) {
        return ['success' => false, 'error' => 'Usuario o contraseña incorrectos.'];
    }
    
    // Login exitoso: limpiar intentos fallidos y regenerar ID de sesión
    clearBruteForce($username);
    session_regenerate_id(true);
    
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $username;
    $_SESSION['is_admin'] = (bool) $user['is_admin'];
    
    return ['success' => true];
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

function registerUser(string $username, string $password, bool $admin = false): bool {
    $hash = password_hash($password, PASSWORD_BCRYPT);
    try {
        Database::insert('users', [
            'username' => $username,
            'password_hash' => $hash,
            'is_admin' => $admin ? 1 : 0
        ]);
        return true;
    } catch (PDOException $e) {
        return false;
    }
}
