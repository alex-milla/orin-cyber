<?php
declare(strict_types=1);

function jsonResponse(array $data, int $statusCode = 200): never {
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

function generateSecureToken(int $length = 32): string {
    return bin2hex(random_bytes($length / 2));
}

function sanitizeString(?string $input): string {
    if ($input === null) return '';
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

function getJsonInput(): array {
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        jsonResponse(['error' => 'JSON inválido'], 400);
    }
    return $data;
}

function checkRateLimit(): void {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
    $key = 'rate_limit_' . md5($ip);
    $now = time();
    $lockFile = DATA_DIR . '/.' . $key . '.tmp';
    $lastTime = file_exists($lockFile) ? (int)file_get_contents($lockFile) : 0;
    if (($now - $lastTime) < RATE_LIMIT_SECONDS) {
        jsonResponse(['error' => 'Rate limit exceeded'], 429);
    }
    file_put_contents($lockFile, (string)$now);
}
