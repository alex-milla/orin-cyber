<?php
declare(strict_types=1);

/**
 * Endpoint interno/externo para búsqueda de incidentes similares.
 * Usado por:
 *   - El worker (RagEnrichTask) para obtener casos similares antes de llamar al LLM.
 *   - La web UI (rag_incidents.php) para búsqueda interactiva.
 *   - Sentinel/KQL en modo sync (enrich.php lo usa indirectamente).
 */

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/rag.php';

header('Content-Type: application/json');

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

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonResponse(['error' => 'POST required'], 405);
}

$input = json_decode(file_get_contents('php://input'), true);
$entity = $input['entity'] ?? ($input['search'] ?? null);
$k = min((int)($input['k'] ?? 5), 10);

if (!$entity || empty($entity['subject'] ?? $entity['value'] ?? $entity['search_text'] ?? '')) {
    jsonResponse(['error' => 'entity or search required'], 400);
}

// Normalizar formato
if (!empty($entity['search_text'])) {
    $entity = [
        'type' => $entity['type'] ?? 'incident',
        'subject' => $entity['search_text'],
        'value' => $entity['search_text'],
        'context' => [],
    ];
}

try {
    $similar = searchSimilarIncidents($entity, $k);
    jsonResponse(['success' => true, 'similar' => $similar, 'count' => count($similar)]);
} catch (Exception $e) {
    http_response_code(500);
    jsonResponse(['error' => 'Search failed: ' . $e->getMessage()], 500);
}
