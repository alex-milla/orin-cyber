<?php
declare(strict_types=1);

/* ================================================================
   POLYFILLS PHP 7.4+ (compatibilidad con < PHP 8)
   ================================================================ */

if (!function_exists('str_contains')) {
    function str_contains(string $haystack, string $needle): bool {
        return $needle === '' || strpos($haystack, $needle) !== false;
    }
}
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool {
        return strpos($haystack, $needle) === 0;
    }
}
if (!function_exists('str_ends_with')) {
    function str_ends_with(string $haystack, string $needle): bool {
        return $needle === '' || substr($haystack, -strlen($needle)) === $needle;
    }
}

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

function sanitizeReportHtml(?string $html): string {
    if (!$html) return '';
    $allowedTags = '<p><br><hr><h1><h2><h3><h4><h5><h6><ul><ol><li>'
                 . '<strong><em><b><i><a><code><pre><blockquote>'
                 . '<div><span><table><thead><tbody><tr><th><td>';
    $html = strip_tags($html, $allowedTags);
    $html = preg_replace('/\s*on[a-z]+\s*=\s*"[^"]*"/i', '', $html);
    $html = preg_replace("/\s*on[a-z]+\s*=\s*'[^']*'/i", '', $html);
    $html = preg_replace('/\s*on[a-z]+\s*=\s*[^\s>]+/i', '', $html);
    $html = preg_replace('/(href|src)\s*=\s*["\']?\s*javascript:/i', '$1="#"', $html);
    return $html;
}

/* ================================================================
   RATE LIMITING (general)
   ================================================================ */

function checkRateLimit(int $seconds = 1): void {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
    $key = 'rate_limit_' . md5($ip);
    $now = time();
    $lockFile = DATA_DIR . '/.' . $key . '.tmp';

    $fp = fopen($lockFile, 'c+');
    if (!$fp) return;
    if (!flock($fp, LOCK_EX)) { fclose($fp); return; }

    $content = stream_get_contents($fp);
    $lastTime = $content !== false && $content !== '' ? (int)$content : 0;

    if (($now - $lastTime) < $seconds) {
        flock($fp, LOCK_UN);
        fclose($fp);
        jsonResponse(['error' => 'Rate limit exceeded'], 429);
    }

    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, (string)$now);
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
}

/* ================================================================
   BRUTE FORCE PROTECTION (login)
   ================================================================ */

function checkBruteForce(string $identifier, int $maxAttempts = 5, int $windowSeconds = 300): bool {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
    $key = 'brute_' . md5($identifier . '_' . $ip);
    $lockFile = DATA_DIR . '/.' . $key . '.json';
    $now = time();

    $fp = fopen($lockFile, 'c+');
    if (!$fp) return true; // fail open: no bloquear login si no se puede escribir
    if (!flock($fp, LOCK_EX)) { fclose($fp); return true; }

    $content = stream_get_contents($fp);
    $attempts = [];
    if ($content !== false && $content !== '') {
        $data = json_decode($content, true);
        if (is_array($data)) {
            $attempts = array_filter($data, fn($t) => ($now - $t) < $windowSeconds);
        }
    }

    if (count($attempts) >= $maxAttempts) {
        flock($fp, LOCK_UN);
        fclose($fp);
        return false; // bloqueado
    }

    $attempts[] = $now;
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($attempts));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return true;
}

function cancelTaskById(int $taskId): array {
    if ($taskId <= 0) {
        return ['ok' => false, 'error' => 'task_id requerido', 'code' => 400];
    }
    $updated = Database::update(
        'tasks',
        [
            'status' => 'cancelled',
            'completed_at' => date('Y-m-d H:i:s'),
            'error_message' => 'Cancelada por el usuario'
        ],
        'id = ? AND status IN (?, ?)',
        [$taskId, 'pending', 'processing']
    );
    if ($updated === 0) {
        return ['ok' => false, 'error' => 'Tarea no encontrada o ya finalizada', 'code' => 409];
    }
    return ['ok' => true];
}

function deleteTaskById(int $taskId): array {
    if ($taskId <= 0) {
        return ['ok' => false, 'error' => 'task_id requerido', 'code' => 400];
    }
    // Solo permitir borrar tareas finalizadas (completed, error, cancelled)
    $task = Database::fetchOne("SELECT status FROM tasks WHERE id = ?", [$taskId]);
    if (!$task) {
        return ['ok' => false, 'error' => 'Tarea no encontrada', 'code' => 404];
    }
    if (!in_array($task['status'], ['completed', 'error', 'cancelled'], true)) {
        return ['ok' => false, 'error' => 'No se puede eliminar una tarea en curso. Cancela primero.', 'code' => 409];
    }
    Database::query("DELETE FROM tasks WHERE id = ?", [$taskId]);
    return ['ok' => true];
}

function createTask(array $data): int {
    $defaults = [
        'task_type' => $data['type'] ?? 'generic',
        'input_data' => $data['input_data'] ?? null,
        'status' => 'pending',
        'assignment' => $data['assignment'] ?? 'worker',
        'priority' => $data['priority'] ?? 5,
        'parent_task_id' => $data['parent_task_id'] ?? null,
        'created_by' => $data['created_by'] ?? null,
        'created_at' => date('Y-m-d H:i:s'),
    ];
    // Sobrescribir defaults con los datos proporcionados
    $insertData = array_merge($defaults, array_diff_key($data, ['type' => 1]));
    if (isset($data['type'])) {
        $insertData['task_type'] = $data['type'];
        unset($insertData['type']);
    }
    return Database::insert('tasks', $insertData);
}

function clearBruteForce(string $identifier): void {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
    $key = 'brute_' . md5($identifier . '_' . $ip);
    $lockFile = DATA_DIR . '/.' . $key . '.json';
    if (file_exists($lockFile)) {
        unlink($lockFile);
    }
}
