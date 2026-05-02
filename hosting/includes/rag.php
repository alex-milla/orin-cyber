<?php
/**
 * Motor RAG (Retrieval-Augmented Generation) de OrinSec.
 * Fase 1: búsqueda full-text (LIKE).
 * Fase 2: búsqueda vectorial con sqlite-vec + embeddings.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/embedding_client.php';

/**
 * Detecta si sqlite-vec está disponible en la conexión actual.
 */
function isVecAvailable(): bool {
    try {
        $db = db();
        $db->query("SELECT 1 FROM incident_embeddings_vec LIMIT 1");
        return true;
    } catch (Exception $e) {
        return false;
    }
}

/**
 * Inicializa sqlite-vec en una conexión PDO (llamar una vez por conexión).
 */
function initVecExtension(): void {
    try {
        $db = db();
        // Intentar cargar la extensión dinámica
        $extDir = ini_get('extension_dir');
        $possiblePaths = [
            $extDir . '/sqlite-vec.so',
            $extDir . '/vec0.so',
            '/usr/lib/php/sqlite-vec.so',
            '/usr/local/lib/php/sqlite-vec.so',
        ];
        foreach ($possiblePaths as $path) {
            if (file_exists($path)) {
                $db->loadExtension($path);
                break;
            }
        }
    } catch (Exception $e) {
        // Silencioso: si no está disponible, fallback a LIKE
    }
}

/**
 * Búsqueda de incidentes similares.
 * Fase 1: LIKE fallback. Fase 2: KNN vectorial con sqlite-vec.
 */
function searchSimilarIncidents(array $entity, int $k = 5): array {
    // Intentar búsqueda vectorial si sqlite-vec está disponible
    if (isVecAvailable()) {
        try {
            return searchSimilarIncidentsVector($entity, $k);
        } catch (Exception $e) {
            error_log("Vector search failed, falling back to text search: " . $e->getMessage());
        }
    }
    return searchSimilarIncidentsText($entity, $k);
}

/**
 * Búsqueda vectorial con sqlite-vec (Fase 2).
 */
function searchSimilarIncidentsVector(array $entity, int $k = 5): array {
    $client = new EmbeddingClient();
    $query = buildEntityText($entity);
    $embedding = $client->embedOne($query);

    if (empty($embedding)) {
        return [];
    }

    $db = db();
    $sql = "
        SELECT
            ie.incident_id,
            ie.summary,
            ie.verdict,
            ie.severity,
            ie.mitre_tactic,
            ie.classification,
            ie.closed_at,
            v.distance
        FROM incident_embeddings_vec v
        JOIN incident_embeddings ie ON ie.id = v.id
        WHERE v.embedding MATCH ?
          AND k = ?
        ORDER BY v.distance ASC
    ";

    $stmt = $db->prepare($sql);
    $stmt->execute([
        json_encode($embedding),
        $k,
    ]);

    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    return array_map(function($r) {
        $r['similarity'] = 1 - (float)$r['distance'];
        return $r;
    }, $rows);
}

/**
 * Búsqueda full-text por LIKE (Fase 1 fallback).
 */
function searchSimilarIncidentsText(array $entity, int $k = 5): array {
    $type = $entity['type'] ?? 'incident';
    $subject = $entity['subject'] ?? '';
    $value = $entity['value'] ?? '';

    $queryText = trim($subject . ' ' . $value);
    if (strlen($queryText) < 2) {
        return [];
    }

    $words = preg_split('/\s+/', $queryText, -1, PREG_SPLIT_NO_EMPTY);
    $words = array_filter($words, fn($w) => strlen($w) >= 2);
    if (empty($words)) {
        return [];
    }

    // Construir condiciones LIKE para cada palabra
    $conditions = [];
    $params = [];
    foreach ($words as $word) {
        $conditions[] = "ie.summary LIKE ?";
        $params[] = '%' . $word . '%';
    }
    $where = implode(' OR ', $conditions);

    $sql = "
        SELECT
            ie.id as incident_id,
            ie.summary,
            ie.verdict,
            ie.severity,
            ie.mitre_tactic,
            ie.classification,
            ie.closed_at,
            0.5 as similarity
        FROM incident_embeddings ie
        WHERE ($where)
        ORDER BY ie.closed_at DESC
        LIMIT ?
    ";

    $params[] = $k;
    $stmt = db()->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function buildEntityText(array $entity): string {
    $parts = [
        $entity['subject'] ?? '',
        $entity['value'] ?? '',
    ];
    $ctx = $entity['context'] ?? [];
    foreach (['rule_name', 'host', 'user', 'severity'] as $field) {
        if (!empty($ctx[$field])) {
            $parts[] = "{$field}: {$ctx[$field]}";
        }
    }
    return trim(implode(' | ', array_filter($parts)));
}

function buildIncidentText(array $input): string {
    $parts = [
        "[{$input['verdict']}] " . ($input['summary'] ?? ''),
    ];
    if (!empty($input['mitre_tactic'])) {
        $parts[] = "MITRE: {$input['mitre_tactic']} / " . ($input['mitre_technique'] ?? '');
    }
    if (!empty($input['classification'])) {
        $parts[] = "Tipo: {$input['classification']}";
    }
    foreach ($input['entities'] ?? [] as $ent) {
        $parts[] = "[{$ent['type']}] {$ent['value']}";
    }
    if (!empty($input['notes'])) {
        $parts[] = "Notas: {$input['notes']}";
    }
    return implode("\n", $parts);
}

function logRagQuery(string $query, string $source, int $resultsCount, int $latencyMs): void {
    try {
        Database::insert('rag_query_log', [
            'query' => $query,
            'source' => $source,
            'results_count' => $resultsCount,
            'latency_ms' => $latencyMs,
        ]);
    } catch (Exception $e) {
        // Silencioso
    }
}

function getRagStats(): array {
    $db = db();
    $total = (int)$db->query("SELECT COUNT(*) FROM incident_embeddings")->fetchColumn();
    $last7d = (int)$db->query("SELECT COUNT(*) FROM incident_embeddings WHERE closed_at >= datetime('now', '-7 days')")->fetchColumn();
    $last30d = (int)$db->query("SELECT COUNT(*) FROM incident_embeddings WHERE closed_at >= datetime('now', '-30 days')")->fetchColumn();
    $totalQueries = (int)$db->query("SELECT COUNT(*) FROM rag_query_log")->fetchColumn();

    $byVerdict = [];
    $rows = $db->query("SELECT verdict, COUNT(*) as c FROM incident_embeddings GROUP BY verdict")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as $r) {
        $byVerdict[$r['verdict'] ?? 'unknown'] = (int)$r['c'];
    }

    $bySeverity = [];
    $rows = $db->query("SELECT severity, COUNT(*) as c FROM incident_embeddings GROUP BY severity")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as $r) {
        $bySeverity[$r['severity'] ?? 'unknown'] = (int)$r['c'];
    }

    return [
        'total_embeddings' => $total,
        'last_7d' => $last7d,
        'last_30d' => $last30d,
        'total_queries' => $totalQueries,
        'by_verdict' => $byVerdict,
        'by_severity' => $bySeverity,
    ];
}

function getRecentEmbeddings(int $limit = 10): array {
    return Database::fetchAll(
        "SELECT * FROM incident_embeddings ORDER BY closed_at DESC LIMIT ?",
        [$limit]
    );
}

// ── Caché de enriquecimientos ─────────────────────────────────────────

function computeEnrichCacheKey(array $entity): string {
    $normalized = [
        'subject' => strtolower(trim($entity['subject'] ?? '')),
        'value' => strtolower(trim($entity['value'] ?? '')),
        'type' => $entity['type'] ?? '',
    ];
    return hash('sha256', json_encode($normalized));
}

function getEnrichCache(string $cacheKey): ?array {
    try {
        $row = Database::fetchOne(
            "SELECT response_json FROM enrich_cache WHERE cache_key = ? AND expires_at > datetime('now')",
            [$cacheKey]
        );
        if ($row) {
            return json_decode($row['response_json'], true);
        }
    } catch (Exception $e) {
        // Silencioso
    }
    return null;
}

function setEnrichCache(string $cacheKey, array $response, int $ttlSeconds = 1800): void {
    try {
        Database::insert('enrich_cache', [
            'cache_key' => $cacheKey,
            'response_json' => json_encode($response),
            'expires_at' => date('Y-m-d H:i:s', time() + $ttlSeconds),
        ]);
    } catch (Exception $e) {
        // Si falla (ej. tabla no existe), silencioso
    }
}

function invalidateEnrichCacheForEntities(array $entities): void {
    if (empty($entities)) return;
    try {
        $db = db();
        $stmt = $db->query("SELECT id, response_json FROM enrich_cache");
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as $row) {
            $data = json_decode($row['response_json'] ?? '{}', true);
            $similarCases = $data['similar_cases'] ?? [];
            foreach ($entities as $ent) {
                $val = strtolower(trim($ent['value'] ?? ''));
                if (!$val) continue;
                foreach ($similarCases as $case) {
                    $caseSummary = strtolower($case['summary'] ?? '');
                    $caseVerdict = strtolower($case['verdict'] ?? '');
                    if (str_contains($caseSummary, $val) || str_contains($caseVerdict, $val)) {
                        $db->prepare("DELETE FROM enrich_cache WHERE id = ?")
                           ->execute([$row['id']]);
                        break 2;
                    }
                }
            }
        }
    } catch (Exception $e) {
        // Silencioso
    }
}

function buildSyncResponse(array $entity, array $similar): array {
    if (empty($similar)) {
        return [
            'verdict' => 'inconclusive',
            'score' => 0.5,
            'confidence' => 'low',
            'recommendation' => 'Sin histórico previo. Investigar manualmente.',
            'similar_cases' => [],
            'mitre_tactic' => null,
            'mitre_technique' => null,
            'kql_hunting' => null,
        ];
    }

    $verdicts = array_column($similar, 'verdict');
    $tp = count(array_filter($verdicts, fn($v) => strtoupper($v) === 'TP'));
    $fp = count(array_filter($verdicts, fn($v) => strtoupper($v) === 'FP'));

    if ($fp > $tp * 2) {
        $v = 'likely_false_positive';
        $score = 0.3;
    } elseif ($tp > $fp) {
        $v = 'likely_true_positive';
        $score = 0.8;
    } else {
        $v = 'inconclusive';
        $score = 0.5;
    }

    return [
        'verdict' => $v,
        'score' => $score,
        'confidence' => 'medium',
        'recommendation' => count($similar) . ' casos similares: ' . $tp . ' TP / ' . $fp . ' FP',
        'similar_cases' => array_slice($similar, 0, 5),
        'mitre_tactic' => $similar[0]['mitre_tactic'] ?? null,
        'mitre_technique' => null,
        'kql_hunting' => null,
    ];
}

function generateRequestId(): string {
    return 'req_' . bin2hex(random_bytes(8));
}

function getRateLimitInfo(string $key): array {
    return [
        'remaining' => 60,
        'reset_at' => date('c', time() + 60),
    ];
}
