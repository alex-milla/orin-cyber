<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

$pageTitle = 'Blue Team Intelligence';

$message = '';
$error = '';

// ── Procesar upload de CSV ──────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['incident_csv'])) {
    $file = $_FILES['incident_csv'];
    $incidentId = sanitizeString($_POST['incident_id'] ?? '');
    $title = sanitizeString($_POST['incident_title'] ?? 'Incidente sin título');
    $severity = sanitizeString($_POST['incident_severity'] ?? 'Medium');
    $source = sanitizeString($_POST['incident_source'] ?? 'manual');

    if ($file['error'] !== UPLOAD_ERR_OK) {
        $error = 'Error al subir el archivo: código ' . $file['error'];
    } elseif (empty($incidentId)) {
        $error = 'El ID de incidente es obligatorio.';
    } else {
        $csvData = file_get_contents($file['tmp_name']);
        if ($csvData === false || strlen($csvData) === 0) {
            $error = 'El archivo está vacío o no se pudo leer.';
        } else {
            try {
                // Insertar o actualizar incidente
                $existing = Database::fetchOne("SELECT 1 FROM incidents WHERE incident_id = ?", [$incidentId]);
                if ($existing) {
                    Database::update('incidents', [
                        'title' => $title,
                        'severity' => $severity,
                        'source' => $source,
                        'raw_data' => $csvData,
                        'status' => 'open',
                    ], 'incident_id = ?', [$incidentId]);
                } else {
                    Database::insert('incidents', [
                        'incident_id' => $incidentId,
                        'title' => $title,
                        'severity' => $severity,
                        'source' => $source,
                        'raw_data' => $csvData,
                        'status' => 'open',
                        'created_time' => date('Y-m-d H:i:s'),
                    ]);
                }

                // Extraer entidades básicas del CSV para pre-poblar
                _extractAndStoreEntities($incidentId, $csvData);

                // Crear tarea de análisis
                $taskInput = json_encode([
                    'incident_id' => $incidentId,
                    'title' => $title,
                    'severity' => $severity,
                    'csv_data' => $csvData,
                ]);
                $taskId = Database::insert('tasks', [
                    'task_type' => 'incident_analysis',
                    'input_data' => $taskInput,
                    'status' => 'pending',
                ]);

                // Vincular tarea con incidente
                Database::update('incidents', ['blue_team_task_id' => $taskId], 'incident_id = ?', [$incidentId]);

                $message = "Incidente {$incidentId} registrado. Análisis en curso (tarea #{$taskId}).";
            } catch (Exception $e) {
                $error = 'Error al procesar: ' . $e->getMessage();
            }
        }
    }
}

// ── Extraer entidades del CSV y guardarlas ──────────────────────────
function _extractAndStoreEntities(string $incidentId, string $csvData): void {
    $lines = str_getcsv($csvData, "\n");
    if (count($lines) < 2) return;

    $headers = str_getcsv($lines[0]);
    $allText = implode(' ', $lines);

    // Regex simples para entidades comunes en CSV de Sentinel
    $patterns = [
        'ip' => '/(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)/',
        'email' => '/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/',
        'domain' => '/(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|gov|edu|es|mx|co)/i',
        'hash_sha256' => '/\b[a-fA-F0-9]{64}\b/',
        'hash_md5' => '/\b[a-fA-F0-9]{32}\b/',
    ];

    foreach ($patterns as $etype => $pattern) {
        if (preg_match_all($pattern, $allText, $matches)) {
            $unique = array_unique($matches[0]);
            foreach ($unique as $val) {
                $val = strtolower(trim($val));
                if (strlen($val) < 3) continue;
                if ($etype === 'ip' && (strpos($val, '127.') === 0 || strpos($val, '0.') === 0)) continue;

                // Insertar entidad si no existe
                $dbType = match($etype) {
                    'ip' => 'ip',
                    'email' => 'user',
                    'domain' => 'domain',
                    'hash_sha256', 'hash_md5' => 'hash',
                    default => 'related',
                };

                try {
                    Database::query(
                        "INSERT OR IGNORE INTO entities (entity_type, entity_value) VALUES (?, ?)",
                        [$dbType, $val]
                    );
                    Database::query(
                        "INSERT OR IGNORE INTO incident_entities (incident_id, entity_value, role) VALUES (?, ?, ?)",
                        [$incidentId, $val, 'related']
                    );
                } catch (Exception $e) {
                    // Ignorar duplicados
                }
            }
        }
    }
}

// ── Cargar incidentes recientes ─────────────────────────────────────
$recentIncidents = Database::fetchAll(
    "SELECT * FROM incidents ORDER BY created_time DESC LIMIT 20"
);

$recentEntities = Database::fetchAll(
    "SELECT * FROM entities ORDER BY current_risk_score DESC, total_incidents DESC LIMIT 20"
);

// ── Conteos ─────────────────────────────────────────────────────────
$totalIncidents = Database::fetchOne("SELECT COUNT(*) as c FROM incidents")['c'] ?? 0;
$totalEntities = Database::fetchOne("SELECT COUNT(*) as c FROM entities")['c'] ?? 0;
$pendingAnalysis = Database::fetchOne(
    "SELECT COUNT(*) as c FROM tasks WHERE task_type = 'incident_analysis' AND status = 'pending'"
)['c'] ?? 0;
$processingAnalysis = Database::fetchOne(
    "SELECT COUNT(*) as c FROM tasks WHERE task_type = 'incident_analysis' AND status = 'processing'"
)['c'] ?? 0;

require_once __DIR__ . '/templates/header.php';
?>

<div class="page-header">
    <h2>🛡️ Blue Team Intelligence</h2>
    <p>Análisis de incidentes, tracking de entidades e inteligencia de IOCs.</p>
</div>

<?php if ($message): ?>
<div class="alert alert-success"><?php echo htmlspecialchars($message); ?></div>
<?php endif; ?>
<?php if ($error): ?>
<div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
<?php endif; ?>

<!-- ── Tarjetas de resumen ─────────────────────────────────────────── -->
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:1.5rem;">
    <div class="card" style="text-align:center;">
        <div style="font-size:1.8rem;font-weight:700;color:var(--primary);"><?php echo $totalIncidents; ?></div>
        <div style="color:var(--text-muted);font-size:.9rem;">Incidentes</div>
    </div>
    <div class="card" style="text-align:center;">
        <div style="font-size:1.8rem;font-weight:700;color:var(--primary);"><?php echo $totalEntities; ?></div>
        <div style="color:var(--text-muted);font-size:.9rem;">Entidades</div>
    </div>
    <div class="card" style="text-align:center;">
        <div style="font-size:1.8rem;font-weight:700;color:var(--accent);"><?php echo $pendingAnalysis; ?></div>
        <div style="color:var(--text-muted);font-size:.9rem;">Pendientes</div>
    </div>
    <div class="card" style="text-align:center;">
        <div style="font-size:1.8rem;font-weight:700;color:var(--warning);"><?php echo $processingAnalysis; ?></div>
        <div style="color:var(--text-muted);font-size:.9rem;">En análisis</div>
    </div>
</div>

<!-- ── Formulario de upload ────────────────────────────────────────── -->
<div class="card" style="margin-bottom:1.5rem;">
    <h3>📤 Subir Incidente desde Sentinel</h3>
    <form method="POST" action="" enctype="multipart/form-data" style="margin-top:1rem;">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;">
            <div>
                <label>ID de Incidente *</label>
                <input type="text" name="incident_id" placeholder="INC-25234" required style="width:100%;">
            </div>
            <div>
                <label>Título</label>
                <input type="text" name="incident_title" placeholder="Logon anómalo desde IP externa" style="width:100%;">
            </div>
            <div>
                <label>Severidad</label>
                <select name="incident_severity" style="width:100%;">
                    <option value="Low">Low</option>
                    <option value="Medium" selected>Medium</option>
                    <option value="High">High</option>
                    <option value="Critical">Critical</option>
                </select>
            </div>
            <div>
                <label>Fuente</label>
                <select name="incident_source" style="width:100%;">
                    <option value="manual">Manual / CSV</option>
                    <option value="sentinel">Microsoft Sentinel</option>
                </select>
            </div>
        </div>
        <div style="margin-top:1rem;">
            <label>Archivo CSV exportado de Sentinel *</label>
            <input type="file" name="incident_csv" accept=".csv,.json" required style="width:100%;padding:.5rem;border:2px dashed var(--border);border-radius:var(--radius-sm);background:var(--surface);">
        </div>
        <div style="margin-top:1rem;">
            <button type="submit" class="btn btn-primary">🔍 Analizar Incidente</button>
        </div>
    </form>
</div>

<!-- ── Tabla de incidentes recientes ───────────────────────────────── -->
<div class="card" style="margin-bottom:1.5rem;">
    <h3>📋 Incidentes Recientes</h3>
    <?php if (empty($recentIncidents)): ?>
        <p style="color:var(--text-muted);">No hay incidentes registrados todavía. Sube tu primer CSV arriba.</p>
    <?php else: ?>
    <div style="overflow-x:auto;">
        <table class="data-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Título</th>
                    <th>Severidad</th>
                    <th>Estado</th>
                    <th>Veredicto LLM</th>
                    <th>Fecha</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($recentIncidents as $inc): ?>
                <tr>
                    <td><code><?php echo htmlspecialchars($inc['incident_id']); ?></code></td>
                    <td><?php echo htmlspecialchars($inc['title'] ?? ''); ?></td>
                    <td>
                        <?php
                        $sevColor = match(strtoupper($inc['severity'] ?? '')) {
                            'CRITICAL' => '#c62828',
                            'HIGH' => '#f57c00',
                            'MEDIUM' => '#f9a825',
                            'LOW' => '#2e7d32',
                            default => '#78909c',
                        };
                        ?>
                        <span style="display:inline-block;background:<?php echo $sevColor; ?>;color:#fff;padding:.15rem .5rem;border-radius:4px;font-size:.8rem;font-weight:600;"><?php echo htmlspecialchars($inc['severity'] ?? 'N/A'); ?></span>
                    </td>
                    <td>
                        <?php
                        $statusLabel = match($inc['status'] ?? 'open') {
                            'open' => '🟡 Abierto',
                            'closed' => '🔴 Cerrado',
                            'investigating' => '🔵 Investigando',
                            default => $inc['status'],
                        };
                        echo $statusLabel;
                        ?>
                    </td>
                    <td>
                        <?php if ($inc['llm_verdict']): ?>
                            <?php
                            $vColor = match($inc['llm_verdict']) {
                                'True Positive' => '#c62828',
                                'False Positive' => '#2e7d32',
                                'Needs Review' => '#f57c00',
                                default => '#78909c',
                            };
                            ?>
                            <span style="display:inline-block;background:<?php echo $vColor; ?>;color:#fff;padding:.15rem .5rem;border-radius:4px;font-size:.8rem;font-weight:600;"><?php echo htmlspecialchars($inc['llm_verdict']); ?></span>
                        <?php else: ?>
                            <em style="color:var(--text-muted);">Pendiente</em>
                        <?php endif; ?>
                    </td>
                    <td style="font-size:.85rem;color:var(--text-muted);"><?php echo htmlspecialchars(substr($inc['created_time'] ?? '', 0, 16)); ?></td>
                    <td>
                        <?php if ($inc['blue_team_task_id']): ?>
                        <a href="task_result.php?id=<?php echo (int)$inc['blue_team_task_id']; ?>" class="btn btn-sm">Ver</a>
                        <?php else: ?>
                        <em class="small" style="color:var(--text-muted);">—</em>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>

<!-- ── Tabla de entidades ──────────────────────────────────────────── -->
<div class="card">
    <h3>🔍 Entidades Monitoreadas</h3>
    <?php if (empty($recentEntities)): ?>
        <p style="color:var(--text-muted);">No hay entidades registradas todavía.</p>
    <?php else: ?>
    <div style="overflow-x:auto;">
        <table class="data-table">
            <thead>
                <tr>
                    <th>Tipo</th>
                    <th>Valor</th>
                    <th>Incidentes</th>
                    <th>Risk Score</th>
                    <th>First Seen</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($recentEntities as $ent): ?>
                <tr>
                    <td><span class="badge"><?php echo htmlspecialchars($ent['entity_type'] ?? ''); ?></span></td>
                    <td><code><?php echo htmlspecialchars($ent['entity_value']); ?></code></td>
                    <td style="text-align:center;"><?php echo (int)($ent['total_incidents'] ?? 0); ?></td>
                    <td>
                        <?php
                        $risk = (float)($ent['current_risk_score'] ?? 0);
                        $riskColor = $risk > 0.8 ? '#c62828' : ($risk > 0.5 ? '#f57c00' : '#2e7d32');
                        ?>
                        <div style="display:flex;align-items:center;gap:.5rem;">
                            <div style="flex:1;background:var(--bg);border-radius:4px;height:8px;overflow:hidden;">
                                <div style="width:<?php echo round($risk * 100); ?>%;background:<?php echo $riskColor; ?>;height:100%;"></div>
                            </div>
                            <span style="font-size:.8rem;font-weight:600;color:<?php echo $riskColor; ?>;"><?php echo round($risk * 100); ?>%</span>
                        </div>
                    </td>
                    <td style="font-size:.85rem;color:var(--text-muted);"><?php echo htmlspecialchars(substr($ent['first_seen'] ?? '', 0, 16)); ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>

<?php require_once __DIR__ . '/templates/footer.php'; ?>
