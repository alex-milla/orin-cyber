<?php
declare(strict_types=1);

/* ================================================================
   RESPUESTAS Y TOKENS
   ================================================================ */

function jsonResponse(array $data, int $statusCode = 200): never {
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

function generateSecureToken(int $length = 32): string {
    return bin2hex(random_bytes($length / 2));
}

/* ================================================================
   CSRF PROTECTION
   ================================================================ */

function csrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = generateSecureToken(32);
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrf(?string $token): void {
    $expected = $_SESSION['csrf_token'] ?? '';
    if (empty($expected) || !hash_equals($expected, (string) $token)) {
        jsonResponse(['error' => 'Token CSRF inválido'], 403);
    }
}

function csrfInput(): string {
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrfToken(), ENT_QUOTES, 'UTF-8') . '">';
}

/* ================================================================
   SANITIZACIÓN
   ================================================================ */

function sanitizeString(?string $input): string {
    if ($input === null) return '';
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

function validateInput(string $input, int $maxLength = 255, string $allowedPattern = '/^[\w\s\-.@:]+$/u'): ?string {
    $clean = trim($input);
    if (strlen($clean) > $maxLength) {
        return null;
    }
    if ($clean !== '' && !preg_match($allowedPattern, $clean)) {
        return null;
    }
    return $clean;
}

function getJsonInput(): array {
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        jsonResponse(['error' => 'JSON inválido'], 400);
    }
    return $data;
}

/* ================================================================
   RATE LIMITING (general)
   ================================================================ */

function checkRateLimit(int $seconds = 1): void {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
    $key = 'rate_limit_' . md5($ip);
    $now = time();
    $lockFile = DATA_DIR . '/.' . $key . '.tmp';
    $lastTime = file_exists($lockFile) ? (int)file_get_contents($lockFile) : 0;
    if (($now - $lastTime) < $seconds) {
        jsonResponse(['error' => 'Rate limit exceeded'], 429);
    }
    file_put_contents($lockFile, (string)$now);
}

/* ================================================================
   BRUTE FORCE PROTECTION (login)
   ================================================================ */

function checkBruteForce(string $identifier, int $maxAttempts = 5, int $windowSeconds = 300): bool {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
    $key = 'brute_' . md5($identifier . '_' . $ip);
    $lockFile = DATA_DIR . '/.' . $key . '.json';
    $now = time();

    $attempts = [];
    if (file_exists($lockFile)) {
        $data = json_decode(file_get_contents($lockFile), true);
        if (is_array($data)) {
            $attempts = array_filter($data, fn($t) => ($now - $t) < $windowSeconds);
        }
    }

    if (count($attempts) >= $maxAttempts) {
        return false; // bloqueado
    }

    $attempts[] = $now;
    file_put_contents($lockFile, json_encode($attempts));
    return true;
}

function clearBruteForce(string $identifier): void {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
    $key = 'brute_' . md5($identifier . '_' . $ip);
    $lockFile = DATA_DIR . '/.' . $key . '.json';
    if (file_exists($lockFile)) {
        unlink($lockFile);
    }
}
