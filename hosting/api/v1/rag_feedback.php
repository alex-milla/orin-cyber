<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/rag.php';

header('Content-Type: application/json');

// Auth: API key (workers) o sesión (usuarios web)
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

// ── GET: listar embeddings indexados ────────────────────────────────
if ($method === 'GET') {
    $limit = min((int)($_GET['limit'] ?? 20), 100);
    $rows = Database::fetchAll(
        "SELECT ie.id, ie.incident_id, ie.summary, ie.verdict, ie.severity,
                ie.mitre_tactic, ie.classification, ie.closed_at, ie.closed_by,
                ie.embedding_model, ie.embedding_dim
         FROM incident_embeddings ie
         ORDER BY ie.closed_at DESC
         LIMIT ?",
        [$limit]
    );
    jsonResponse(['success' => true, 'count' => count($rows), 'embeddings' => $rows]);
}

// ── POST: guardar feedback (incidente cerrado) ──────────────────────
if ($method === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    if (!$input || empty($input['summary'])) {
        jsonResponse(['error' => 'summary required'], 400);
    }

    $summary = trim((string)$input['summary']);
    if (strlen($summary) < 5) {
        jsonResponse(['error' => 'summary too short'], 400);
    }

    $textToEmbed = buildIncidentText($input);
    $embeddingModel = 'bge-small-en-v1.5';
    $embeddingDim = 384;

    try {
        $id = Database::insert('incident_embeddings', [
            'incident_id'     => $input['incident_id'] ?? null,
            'summary'         => $textToEmbed,
            'verdict'         => $input['verdict'] ?? null,
            'severity'        => $input['severity'] ?? null,
            'mitre_tactic'    => $input['mitre_tactic'] ?? null,
            'mitre_technique' => $input['mitre_technique'] ?? null,
            'classification'  => $input['classification'] ?? null,
            'entities_json'   => json_encode($input['entities'] ?? []),
            'closed_at'       => $input['closed_at'] ?? date('Y-m-d H:i:s'),
            'closed_by'       => $input['closed_by'] ?? ($_SESSION['username'] ?? 'system'),
            'embedding_model' => $embeddingModel,
            'embedding_dim'   => $embeddingDim,
        ]);

        jsonResponse([
            'success' => true,
            'embedding_id' => $id,
            'incident_id' => $input['incident_id'] ?? null,
            'embedding_model' => $embeddingModel,
            'embedding_dim' => $embeddingDim,
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        jsonResponse(['error' => 'Database error: ' . $e->getMessage()], 500);
    }
}

jsonResponse(['error' => 'Method not allowed'], 405);
