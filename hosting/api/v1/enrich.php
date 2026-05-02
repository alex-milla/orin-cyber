<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/embedding_client.php';
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/../../includes/rag.php';

header('Content-Type: application/json');

// 1. Autenticación
$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
$keyRow = validateApiKey($apiKey);
if (!$keyRow) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid API key']);
    exit;
}

// 2. Rate limiting
if (!checkRateLimit("enrich_{$apiKey}", limit: 60, windowSec: 60)) {
    http_response_code(429);
    echo json_encode(['error' => 'Rate limit exceeded']);
    exit;
}

// 3. Parseo del body
$input = json_decode(file_get_contents('php://input'), true);
if (!$input || !isset($input['entities']) || !is_array($input['entities'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid request body']);
    exit;
}

$mode = in_array($input['mode'] ?? '', ['sync', 'async', 'hybrid']) ? ($input['mode'] ?? 'hybrid') : 'hybrid';
$entities = $input['entities'];
$options = $input['options'] ?? [];
$k = min((int)($options['k'] ?? 5), 10);

if (count($entities) > 100) {
    http_response_code(400);
    echo json_encode(['error' => 'Too many entities (max 100)']);
    exit;
}

// 4. Overflow check (cola saturada)
$db = db();
$pendingHigh = (int)$db->query("SELECT COUNT(*) FROM tasks WHERE status = 'pending' AND priority <= 2 AND type = 'rag_enrich'")->fetchColumn();
if ($pendingHigh > 50 && $mode !== 'sync') {
    $policy = defined('RAG_OVERFLOW_POLICY') ? RAG_OVERFLOW_POLICY : 'reject_429';
    if ($policy === 'sync_only_degraded') {
        $mode = 'sync';
    } else {
        http_response_code(429);
        echo json_encode([
            'error' => 'Queue saturated',
            'retry_after_seconds' => 30,
        ]);
        exit;
    }
}

$results = [];
$queued = [];
$fromCache = [];

foreach ($entities as $idx => $entity) {
    $cacheKey = computeEnrichCacheKey($entity);

    // Intento de caché
    $cached = getEnrichCache($cacheKey);
    if ($cached) {
        $results[] = array_merge(['entity_index' => $idx, 'status' => 'completed'], $cached);
        $fromCache[] = $idx;
        continue;
    }

    if ($mode === 'sync') {
        // Solo búsqueda vectorial sin LLM
        try {
            $similar = searchSimilarIncidents($entity, $k);
            $response = buildSyncResponse($entity, $similar);
            setEnrichCache($cacheKey, $response, ttlSeconds: 1800);
            $results[] = array_merge(['entity_index' => $idx, 'status' => 'completed'], $response);
        } catch (Exception $e) {
            $results[] = [
                'entity_index' => $idx,
                'status' => 'error',
                'error' => $e->getMessage(),
            ];
        }
    } else {
        // Encolar para análisis con LLM
        $taskId = createTask([
            'type' => 'rag_enrich',
            'priority' => 1,
            'input_data' => json_encode([
                'entity' => $entity,
                'options' => $options,
                'cache_key' => $cacheKey,
            ]),
            'assignment' => 'worker',
            'created_by' => $keyRow['user_id'] ?? null,
        ]);
        $results[] = [
            'entity_index' => $idx,
            'status' => 'queued',
            'task_id' => $taskId,
        ];
        $queued[] = $idx;
    }
}

echo json_encode([
    'request_id' => generateRequestId(),
    'results' => $results,
    'from_cache' => $fromCache,
    'queued' => $queued,
    'rate_limit' => getRateLimitInfo("enrich_{$apiKey}"),
], JSON_UNESCAPED_UNICODE);
