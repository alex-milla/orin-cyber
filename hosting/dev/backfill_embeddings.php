<?php
declare(strict_types=1);

/**
 * Backfill de embeddings históricos.
 * Genera embeddings para todos los incidentes cerrados existentes que no tengan embedding.
 *
 * Uso:
 *   php backfill_embeddings.php --dry-run          (solo muestra cuántos faltan)
 *   php backfill_embeddings.php --limit=50         (procesa 50 incidentes)
 *   php backfill_embeddings.php                    (procesa todos)
 */

require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/rag.php';
require_once __DIR__ . '/../includes/embedding_client.php';

$dryRun = in_array('--dry-run', $argv, true);
$limit = null;
foreach ($argv as $arg) {
    if (str_starts_with($arg, '--limit=')) {
        $limit = (int) substr($arg, 8);
    }
}

$db = db();

// Incidentes cerrados sin embedding
$sql = "
    SELECT i.* FROM incidents i
    LEFT JOIN incident_embeddings ie ON ie.incident_id = i.incident_id
    WHERE i.status = 'closed'
      AND ie.id IS NULL
";
if ($limit) {
    $sql .= " LIMIT {$limit}";
}

$rows = $db->query($sql)->fetchAll(PDO::FETCH_ASSOC);
$total = count($rows);

echo "=== OrinSec — Backfill de embeddings ===\n";
echo "Incidentes cerrados sin embedding: {$total}\n";

if ($dryRun) {
    echo "(Dry-run: no se modificará nada)\n";
    exit(0);
}

if ($total === 0) {
    echo "✅ Nada que hacer. Todos los incidentes cerrados ya tienen embedding.\n";
    exit(0);
}

$client = new EmbeddingClient();
$ok = 0;
$fail = 0;

foreach ($rows as $idx => $row) {
    $num = $idx + 1;
    echo "[{$num}/{$total}] Incidente #{$row['incident_id']}... ";

    $input = [
        'incident_id' => $row['incident_id'],
        'summary' => $row['title'] . ". " . ($row['description'] ?? ''),
        'verdict' => $row['llm_verdict'] ?? 'TP',
        'severity' => $row['severity'] ?? 'medium',
        'mitre_tactic' => $row['mitre_tactic'] ?? null,
        'mitre_technique' => $row['mitre_technique'] ?? null,
        'classification' => $row['classification'] ?? 'GENERICO',
        'entities' => json_decode($row['entities_json'] ?? '[]', true) ?: [],
        'closed_by' => $row['closed_by'] ?? 'system',
        'closed_at' => $row['created_at'] ?? date('Y-m-d H:i:s'),
    ];

    $textToEmbed = buildIncidentText($input);

    try {
        $embedding = $client->embedOne($textToEmbed);
        $embeddingDim = count($embedding);

        $db->beginTransaction();

        $stmt = $db->prepare("
            INSERT INTO incident_embeddings
                (incident_id, summary, verdict, severity, mitre_tactic,
                 mitre_technique, classification, entities_json, closed_at,
                 closed_by, embedding_model, embedding_dim)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $input['incident_id'],
            $textToEmbed,
            $input['verdict'],
            $input['severity'],
            $input['mitre_tactic'],
            $input['mitre_technique'],
            $input['classification'],
            json_encode($input['entities']),
            $input['closed_at'],
            $input['closed_by'],
            EMBEDDING_MODEL,
            $embeddingDim,
        ]);
        $embeddingId = (int)$db->lastInsertId();

        if (isVecAvailable() && !empty($embedding)) {
            $stmtVec = $db->prepare("INSERT INTO incident_embeddings_vec (id, embedding) VALUES (?, ?)");
            $stmtVec->execute([$embeddingId, json_encode($embedding)]);
        }

        $db->commit();
        echo "OK (dim={$embeddingDim})\n";
        $ok++;
    } catch (Exception $e) {
        if ($db->inTransaction()) $db->rollBack();
        echo "FAIL: " . $e->getMessage() . "\n";
        $fail++;
    }
}

echo "\n=== Resumen ===\n";
echo "✅ OK: {$ok}\n";
echo "❌ Fallidos: {$fail}\n";
echo "Total procesados: " . ($ok + $fail) . "\n";
