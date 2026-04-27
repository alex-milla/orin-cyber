<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/auth.php';

$keyRow = requireApiKey();

// Rate limiting
$ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
$rateKey = 'api_rate_' . md5($ip);
$now = time();
$lockFile = DATA_DIR . '/.' . $rateKey . '.tmp';
$lastTime = file_exists($lockFile) ? (int)file_get_contents($lockFile) : 0;
if (($now - $lastTime) < 1) {
    jsonResponse(['error' => 'Rate limit exceeded'], 429);
}
file_put_contents($lockFile, (string)$now);

$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

// ── GET subscriptions (worker) ─────────────────────────────────────
if ($method === 'GET' && $action === 'subscriptions') {
    $subs = Database::fetchAll(
        "SELECT id, type, value, severity_threshold FROM alert_subscriptions WHERE active = 1"
    );
    jsonResponse(['subscriptions' => $subs]);
    exit;
}

// ── GET list (UI / worker) ─────────────────────────────────────────
if ($method === 'GET' && $action === 'list') {
    $limit = filter_input(INPUT_GET, 'limit', FILTER_VALIDATE_INT) ?: 50;
    $limit = max(1, min($limit, 200));
    $offset = filter_input(INPUT_GET, 'offset', FILTER_VALIDATE_INT) ?: 0;
    $offset = max(0, $offset);
    $unreadOnly = filter_input(INPUT_GET, 'unread', FILTER_VALIDATE_BOOL) ?: false;

    $where = $unreadOnly ? "WHERE read_at IS NULL" : "";
    $alerts = Database::fetchAll(
        "SELECT * FROM alerts {$where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        [$limit, $offset]
    );
    $totalRow = Database::fetchOne(
        "SELECT COUNT(*) as total FROM alerts {$where}"
    );
    $unreadRow = Database::fetchOne(
        "SELECT COUNT(*) as total FROM alerts WHERE read_at IS NULL"
    );

    jsonResponse([
        'alerts' => $alerts,
        'total' => (int)($totalRow['total'] ?? 0),
        'unread' => (int)($unreadRow['total'] ?? 0),
    ]);
    exit;
}

// ── POST mark_read ─────────────────────────────────────────────────
if ($method === 'POST' && $action === 'mark_read') {
    $data = getJsonInput();
    $alertId = filter_var($data['alert_id'] ?? 0, FILTER_VALIDATE_INT);
    if ($alertId <= 0) {
        jsonResponse(['error' => 'alert_id requerido'], 400);
    }
    Database::update('alerts', ['read_at' => date('Y-m-d H:i:s')], 'id = ?', [$alertId]);
    jsonResponse(['success' => true]);
    exit;
}

// ── POST create batch (worker) ─────────────────────────────────────
if ($method === 'POST' && $action === '') {
    $data = getJsonInput();
    $items = $data['alerts'] ?? [];
    if (!is_array($items) || empty($items)) {
        jsonResponse(['error' => 'Se requiere array "alerts"'], 400);
    }

    $created = 0;
    $skipped = 0;
    foreach ($items as $item) {
        $cveId = validateInput($item['cve_id'] ?? '', 50);
        if (!$cveId) continue;

        // Evitar duplicados por cve_id en las últimas 7 días
        $existing = Database::fetchOne(
            "SELECT id FROM alerts WHERE cve_id = ? AND created_at > datetime('now', '-7 days')",
            [$cveId]
        );
        if ($existing) {
            $skipped++;
            continue;
        }

        Database::insert('alerts', [
            'cve_id' => $cveId,
            'title' => validateInput($item['title'] ?? '', 255) ?? '',
            'severity' => validateInput($item['severity'] ?? '', 20),
            'score' => is_numeric($item['score'] ?? null) ? (float)$item['score'] : null,
            'epss_score' => is_numeric($item['epss_score'] ?? null) ? (float)$item['epss_score'] : null,
            'kev' => !empty($item['kev']) ? 1 : 0,
            'source' => validateInput($item['source'] ?? 'NVD', 50) ?? 'NVD',
            'matched_subscription' => validateInput($item['matched_subscription'] ?? '', 255),
        ]);
        $created++;
    }

    jsonResponse(['success' => true, 'created' => $created, 'skipped' => $skipped]);
    exit;
}

jsonResponse(['error' => 'Acción no válida. Use subscriptions, list, mark_read o POST batch'], 400);
