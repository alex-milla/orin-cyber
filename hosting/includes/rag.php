<?php
declare(strict_types=1);

/**
 * RAG — Retrieval-Augmented Generation para incidentes históricos
 * Fase 1: búsqueda basada en texto (MVP). Fase 2: sqlite-vec + embeddings.
 */

require_once __DIR__ . '/db.php';

/**
 * Busca incidentes similares por texto/keywords (MVP Fase 1).
 * En Fase 2 se reemplazará por búsqueda vectorial con sqlite-vec.
 */
function searchSimilarIncidents(array $entity, int $k = 5): array {
    $queryText = buildEntityText($entity);

    // Tokenizar palabras clave del query
    $keywords = preg_split('/[\s|,.;:\-]+/', strtolower($queryText), -1, PREG_SPLIT_NO_EMPTY);
    $keywords = array_filter($keywords, fn($w) => strlen($w) > 2);
    $keywords = array_unique(array_slice($keywords, 0, 20));

    if (empty($keywords)) {
        return [];
    }

    // Construir WHERE con LIKE por cada keyword
    $whereParts = [];
    $params = [];
    foreach ($keywords as $word) {
        $whereParts[] = "LOWER(summary) LIKE ?";
        $params[] = '%' . $word . '%';
    }
    $whereSql = implode(' OR ', $whereParts);

    $sql = "SELECT
                ie.id,
                ie.incident_id,
                ie.summary,
                ie.verdict,
                ie.severity,
                ie.mitre_tactic,
                ie.classification,
                ie.closed_at,
                ie.entities_json,
                (" . implode(' + ', array_fill(0, count($keywords), "CASE WHEN LOWER(summary) LIKE ? THEN 1 ELSE 0 END")) . ") AS score
            FROM incident_embeddings ie
            WHERE ($whereSql) AND ie.verdict IS NOT NULL
            ORDER BY score DESC, ie.closed_at DESC
            LIMIT ?";

    foreach ($keywords as $word) {
        $params[] = '%' . $word . '%';
    }
    $params[] = $k;

    $rows = Database::fetchAll($sql, $params);
    $maxScore = max(array_column($rows, 'score') ?: [1]);

    return array_map(function ($r) use ($maxScore) {
        $sim = $maxScore > 0 ? round($r['score'] / $maxScore, 2) : 0;
        return [
            'id' => $r['id'],
            'incident_id' => $r['incident_id'],
            'summary' => $r['summary'],
            'verdict' => $r['verdict'],
            'severity' => $r['severity'],
            'mitre_tactic' => $r['mitre_tactic'],
            'classification' => $r['classification'],
            'closed_at' => $r['closed_at'],
            'entities_json' => $r['entities_json'],
            'similarity' => $sim,
            'score' => (int)$r['score'],
        ];
    }, $rows);
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
    $parts = [];
    if (!empty($input['summary'])) {
        $parts[] = "[" . ($input['verdict'] ?? '?') . "] " . $input['summary'];
    }
    if (!empty($input['mitre_tactic'])) {
        $parts[] = "MITRE: {$input['mitre_tactic']}";
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

function getRagStats(): array {
    $total = Database::fetchOne("SELECT COUNT(*) as c FROM incident_embeddings");
    $byVerdict = Database::fetchAll("SELECT verdict, COUNT(*) as c FROM incident_embeddings WHERE verdict IS NOT NULL GROUP BY verdict");
    $bySeverity = Database::fetchAll("SELECT severity, COUNT(*) as c FROM incident_embeddings WHERE severity IS NOT NULL GROUP BY severity");
    $queries = Database::fetchOne("SELECT COUNT(*) as c FROM rag_query_log");
    $last7 = Database::fetchOne("SELECT COUNT(*) as c FROM incident_embeddings WHERE closed_at > datetime('now', '-7 days')");
    $last30 = Database::fetchOne("SELECT COUNT(*) as c FROM incident_embeddings WHERE closed_at > datetime('now', '-30 days')");

    return [
        'total_embeddings' => (int)($total['c'] ?? 0),
        'last_7d' => (int)($last7['c'] ?? 0),
        'last_30d' => (int)($last30['c'] ?? 0),
        'by_verdict' => array_column($byVerdict, 'c', 'verdict'),
        'by_severity' => array_column($bySeverity, 'c', 'severity'),
        'total_queries' => (int)($queries['c'] ?? 0),
    ];
}

function getRecentEmbeddings(int $limit = 20): array {
    return Database::fetchAll(
        "SELECT ie.*, i.title as incident_title, i.status as incident_status
         FROM incident_embeddings ie
         LEFT JOIN incidents i ON i.incident_id = ie.incident_id
         ORDER BY ie.closed_at DESC
         LIMIT ?",
        [$limit]
    );
}

function logRagQuery(string $queryText, string $queryType, int $resultsCount, ?int $responseTimeMs = null): void {
    try {
        Database::insert('rag_query_log', [
            'query_text' => $queryText,
            'query_type' => $queryType,
            'results_count' => $resultsCount,
            'response_time_ms' => $responseTimeMs,
        ]);
    } catch (Exception $e) {
        error_log('RAG query log failed: ' . $e->getMessage());
    }
}
