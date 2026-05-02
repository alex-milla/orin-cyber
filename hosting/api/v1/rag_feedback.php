<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/rag.php';
require_once __DIR__ . '/../../includes/embedding_client.php';

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
    $embeddingModel = defined('EMBEDDING_MODEL') ? EMBEDDING_MODEL : 'bge-small-en-v1.5';
    $embeddingDim = defined('EMBEDDING_DIM') ? EMBEDDING_DIM : 384;

    $db = db();
    try {
        $db->beginTransaction();

        // 1. Insertar metadatos
        $stmt = $db->prepare("
            INSERT INTO incident_embeddings
                (incident_id, summary, verdict, severity, mitre_tactic,
                 mitre_technique, classification, entities_json, closed_at,
                 closed_by, embedding_model, embedding_dim)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $input['incident_id'] ?? null,
            $textToEmbed,
            $input['verdict'] ?? null,
            $input['severity'] ?? null,
            $input['mitre_tactic'] ?? null,
            $input['mitre_technique'] ?? null,
            $input['classification'] ?? null,
            json_encode($input['entities'] ?? []),
            $input['closed_at'] ?? date('Y-m-d H:i:s'),
            $input['closed_by'] ?? ($_SESSION['username'] ?? 'system'),
            $embeddingModel,
            $embeddingDim,
        ]);
        $embeddingId = (int)$db->lastInsertId();

        // 2. Generar embedding y guardar en tabla virtual sqlite-vec (si está disponible)
        try {
            $client = new EmbeddingClient();
            $embedding = $client->embedOne($textToEmbed);
            if (!empty($embedding)) {
                // Verificar si sqlite-vec está disponible
                $hasVec = false;
                try {
                    $db->query("SELECT 1 FROM incident_embeddings_vec LIMIT 1");
                    $hasVec = true;
                } catch (Exception $e) {
                    // sqlite-vec no disponible todavía
                }

                if ($hasVec) {
                    $stmtVec = $db->prepare("INSERT INTO incident_embeddings_vec (id, embedding) VALUES (?, ?)");
                    $stmtVec->execute([$embeddingId, json_encode($embedding)]);
                    $embeddingDim = count($embedding);
                }
            }
        } catch (Exception $embedErr) {
            // Log pero no fallar: el texto ya está indexado, el vector se puede regenerar luego
            error_log("Embedding generation failed for incident {$input['incident_id'] ?? 'new'}: " . $embedErr->getMessage());
        }

        $db->commit();

        // 3. Invalidar caché de enriquecimientos relacionados
        invalidateEnrichCacheForEntities($input['entities'] ?? []);

        jsonResponse([
            'success' => true,
            'embedding_id' => $embeddingId,
            'incident_id' => $input['incident_id'] ?? null,
            'embedding_model' => $embeddingModel,
            'embedding_dim' => $embeddingDim,
        ]);
    } catch (Exception $e) {
        if ($db->inTransaction()) $db->rollBack();
        http_response_code(500);
        jsonResponse(['error' => 'Database error: ' . $e->getMessage()], 500);
    }
}

jsonResponse(['error' => 'Method not allowed'], 405);
