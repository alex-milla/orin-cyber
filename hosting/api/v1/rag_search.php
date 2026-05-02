<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/rag.php';

header('Content-Type: application/json');

// Auth: API key (workers) o sesión
$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
$keyRow = null;
if ($apiKey) {
    try {
        $keyRow = Database::fetchOne("SELECT id, name FROM api_keys WHERE api_key = ? AND is_active = 1", [$apiKey]);
    } catch (Exception $e) {}
}
if (!$keyRow && !isLoggedIn()) {
    jsonResponse(['error' => 'Authentication required'], 401);
}

$method = $_SERVER['REQUEST_METHOD'];
if ($method !== 'POST' && $method !== 'GET') {
    jsonResponse(['error' => 'Method not allowed'], 405);
}

$entity = null;
$k = 5;

if ($method === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $entity = $input['entity'] ?? null;
    $k = min((int)($input['k'] ?? 5), 20);
} else {
    $entity = [
        'subject' => $_GET['subject'] ?? '',
        'value' => $_GET['value'] ?? '',
        'type' => $_GET['type'] ?? '',
        'context' => json_decode($_GET['context'] ?? '{}', true) ?: [],
    ];
    $k = min((int)($_GET['k'] ?? 5), 20);
}

if (!$entity || (empty($entity['subject']) && empty($entity['value']))) {
    jsonResponse(['error' => 'entity requires subject or value'], 400);
}

$start = microtime(true) * 1000;
$similar = searchSimilarIncidents($entity, $k);
$elapsed = (int)((microtime(true) * 1000) - $start);

logRagQuery(buildEntityText($entity), 'api', count($similar), $elapsed);

jsonResponse([
    'success' => true,
    'similar' => $similar,
    'query_time_ms' => $elapsed,
]);
