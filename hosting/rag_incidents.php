<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/rag.php';

requireAuth();

$stats = getRagStats();
$recentEmbeddings = getRecentEmbeddings(10);

// Búsqueda
$searchResults = [];
$searchQuery = '';
$searchType = 'incident';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['search_text'])) {
    $token = $_POST['csrf_token'] ?? '';
    if (!empty($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token)) {
        $searchQuery = trim($_POST['search_text']);
        $searchType = in_array($_POST['search_type'] ?? '', ['incident','ip','hash','domain','user','url']) ? ($_POST['search_type'] ?? 'incident') : 'incident';
        if (strlen($searchQuery) >= 3) {
            $entity = [
                'subject' => $searchQuery,
                'value' => $searchQuery,
                'type' => $searchType,
                'context' => [],
            ];
            $start = microtime(true) * 1000;
            $searchResults = searchSimilarIncidents($entity, 10);
            $elapsed = (int)((microtime(true) * 1000) - $start);
            logRagQuery($searchQuery, 'web', count($searchResults), $elapsed);
        }
    }
}

// Veredicto badge helper
function verdictBadge(?string $v): string {
    return match (strtoupper($v ?? '')) {
        'TP', 'TRUE POSITIVE' => '<span class="badge severity-critical">TP</span>',
        'FP', 'FALSE POSITIVE' => '<span class="badge severity-low">FP</span>',
        'NEEDS REVIEW' => '<span class="badge severity-medium">Revisar</span>',
        default => '<span class="badge">' . htmlspecialchars(ucfirst(strtolower($v ?? '—'))) . '</span>',
    };
}

function severityBadge(?string $s): string {
    $class = match (strtoupper($s ?? '')) {
        'CRITICAL' => 'severity-critical',
        'HIGH' => 'severity-high',
        'MEDIUM' => 'severity-medium',
        'LOW' => 'severity-low',
        default => '',
    };
    return $class ? '<span class="badge ' . $class . '">' . htmlspecialchars(strtoupper($s)) . '</span>' : '<span class="badge">—</span>';
}

$pageTitle = '🧠 RAG Incidentes Históricos — OrinSec';
require __DIR__ . '/templates/header.php';
?>

<div class="welcome-banner" style="background: linear-gradient(135deg, #1a237e 0%, #5c6bc0 100%);">
    <h2>🧠 Memoria Histórica de Incidentes</h2>
    <p>Consulta casos similares de incidentes cerrados para enriquecer análisis y acelerar la toma de decisiones.</p>
</div>

<!-- KPIs -->
<div class="kpi-grid">
    <div class="kpi-card kpi-primary">
        <div class="kpi-icon">📚</div>
        <div class="kpi-value"><?php echo number_format($stats['total_embeddings']); ?></div>
        <div class="kpi-label">Incidentes indexados</div>
    </div>
    <div class="kpi-card kpi-success">
        <div class="kpi-icon">📅</div>
        <div class="kpi-value"><?php echo $stats['last_7d']; ?></div>
        <div class="kpi-label">Últimos 7 días</div>
    </div>
    <div class="kpi-card kpi-accent">
        <div class="kpi-icon">🔍</div>
        <div class="kpi-value"><?php echo number_format($stats['total_queries']); ?></div>
        <div class="kpi-label">Consultas realizadas</div>
    </div>
    <div class="kpi-card kpi-warning">
        <div class="kpi-icon">📊</div>
        <div class="kpi-value"><?php echo $stats['last_30d']; ?></div>
        <div class="kpi-label">Indexados 30 días</div>
    </div>
</div>

<!-- Distribución por veredicto -->
<div class="dashboard-grid">
    <div class="widget">
        <h3>📊 Por veredicto</h3>
        <?php if (empty($stats['by_verdict'])): ?>
            <p class="empty-state">Sin datos aún.</p>
        <?php else:
            $maxV = max($stats['by_verdict']);
        ?>
        <div class="mini-bar-chart">
            <?php foreach ($stats['by_verdict'] as $verdict => $count):
                $pct = $maxV > 0 ? round(($count / $maxV) * 100) : 0;
                $color = match (strtoupper($verdict)) {
                    'TP', 'TRUE POSITIVE' => 'bar-critical',
                    'FP', 'FALSE POSITIVE' => 'bar-low',
                    default => 'bar-medium',
                };
            ?>
            <div class="mini-bar-row">
                <div class="mini-bar-label"><?php echo htmlspecialchars(strtoupper($verdict)); ?></div>
                <div class="mini-bar-track"><div class="mini-bar-fill <?php echo $color; ?>" style="width:<?php echo $pct; ?>%"></div></div>
                <div class="mini-bar-count"><?php echo (int)$count; ?></div>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </div>
    <div class="widget">
        <h3>⚡ Por severidad</h3>
        <?php if (empty($stats['by_severity'])): ?>
            <p class="empty-state">Sin datos aún.</p>
        <?php else:
            $maxS = max($stats['by_severity']);
            $sevColors = ['CRITICAL'=>'bar-critical','HIGH'=>'bar-high','MEDIUM'=>'bar-medium','LOW'=>'bar-low'];
        ?>
        <div class="mini-bar-chart">
            <?php foreach ($stats['by_severity'] as $sev => $count):
                $pct = $maxS > 0 ? round(($count / $maxS) * 100) : 0;
                $color = $sevColors[strtoupper($sev)] ?? 'bar-info';
            ?>
            <div class="mini-bar-row">
                <div class="mini-bar-label"><?php echo htmlspecialchars(strtoupper($sev)); ?></div>
                <div class="mini-bar-track"><div class="mini-bar-fill <?php echo $color; ?>" style="width:<?php echo $pct; ?>%"></div></div>
                <div class="mini-bar-count"><?php echo (int)$count; ?></div>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </div>
</div>

<!-- Buscador -->
<div class="card">
    <h2>🔍 Buscar incidentes similares</h2>
    <form method="POST" style="display:flex;gap:.75rem;flex-wrap:wrap;align-items:flex-end;">
        <?php echo csrfInput(); ?>
        <div style="flex:1;min-width:260px;">
            <label>Texto / IP / Hash / Dominio</label>
            <input type="text" name="search_text" value="<?php echo htmlspecialchars($searchQuery); ?>" placeholder="Ej: phishing CFO, 192.168.1.45, a3f8b2..." required minlength="3">
        </div>
        <div style="min-width:160px;">
            <label>Tipo de entidad</label>
            <select name="search_type">
                <option value="incident" <?php echo $searchType === 'incident' ? 'selected' : ''; ?>>Incidente (texto libre)</option>
                <option value="ip" <?php echo $searchType === 'ip' ? 'selected' : ''; ?>>IP</option>
                <option value="hash" <?php echo $searchType === 'hash' ? 'selected' : ''; ?>>Hash</option>
                <option value="domain" <?php echo $searchType === 'domain' ? 'selected' : ''; ?>>Dominio</option>
                <option value="url" <?php echo $searchType === 'url' ? 'selected' : ''; ?>>URL</option>
                <option value="user" <?php echo $searchType === 'user' ? 'selected' : ''; ?>>Usuario</option>
            </select>
        </div>
        <button type="submit">Buscar similares</button>
    </form>

    <?php if ($searchQuery): ?>
        <?php if (empty($searchResults)): ?>
            <p class="empty-state" style="margin-top:1rem;">No se encontraron casos similares para «<?php echo htmlspecialchars($searchQuery); ?>». Intenta con términos más genéricos.</p>
        <?php else: ?>
        <div style="margin-top:1.25rem;">
            <p class="small" style="color:var(--text-secondary);margin-bottom:.75rem;"><?php echo count($searchResults); ?> caso(s) similar(es) encontrado(s):</p>
            <div style="display:flex;flex-direction:column;gap:.75rem;">
                <?php foreach ($searchResults as $r): ?>
                <div class="widget" style="padding:1rem 1.25rem;">
                    <div style="display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap;margin-bottom:.5rem;">
                        <div style="display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;">
                            <?php echo verdictBadge($r['verdict']); ?>
                            <?php echo severityBadge($r['severity']); ?>
                            <?php if ($r['classification']): ?><span class="badge"><?php echo htmlspecialchars($r['classification']); ?></span><?php endif; ?>
                            <?php if ($r['mitre_tactic']): ?><span class="badge"><?php echo htmlspecialchars($r['mitre_tactic']); ?></span><?php endif; ?>
                        </div>
                        <span class="small" style="color:var(--text-muted);font-weight:600;">Similitud: <?php echo (int)($r['similarity'] * 100); ?>%</span>
                    </div>
                    <p style="margin:0;font-size:.95rem;line-height:1.5;"><?php echo nl2br(htmlspecialchars(substr($r['summary'], 0, 400))); ?></p>
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:.5rem;flex-wrap:wrap;gap:.5rem;">
                        <span class="small" style="color:var(--text-muted);">Cerrado: <?php echo htmlspecialchars(date('d/m/Y H:i', strtotime($r['closed_at']))); ?></span>
                        <?php if ($r['incident_id']): ?>
                        <a href="blue_team.php" class="small">Ver incidente →</a>
                        <?php endif; ?>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>
    <?php endif; ?>
</div>

<!-- Incidentes indexados recientemente -->
<div class="card">
    <h2>📋 Incidentes indexados recientemente</h2>
    <?php if (empty($recentEmbeddings)): ?>
        <p class="empty-state">No hay incidentes indexados todavía. Cierra incidentes en Blue Team para alimentar la memoria.</p>
    <?php else: ?>
    <div class="table-wrap" style="overflow-x:auto;">
        <table class="widget-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Veredicto</th>
                    <th>Severidad</th>
                    <th>MITRE</th>
                    <th>Resumen</th>
                    <th>Cerrado</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($recentEmbeddings as $row): ?>
                <tr>
                    <td>#<?php echo $row['id']; ?></td>
                    <td><?php echo verdictBadge($row['verdict']); ?></td>
                    <td><?php echo severityBadge($row['severity']); ?></td>
                    <td class="small font-mono"><?php echo htmlspecialchars($row['mitre_tactic'] ?? '—'); ?></td>
                    <td class="small" style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><?php echo htmlspecialchars(substr($row['summary'], 0, 120)); ?></td>
                    <td class="small"><?php echo htmlspecialchars(date('d/m/Y', strtotime($row['closed_at']))); ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>

<!-- Formulario de feedback manual -->
<div class="card">
    <h2>➕ Alimentar memoria (feedback manual)</h2>
    <p class="small" style="color:var(--text-secondary);margin-bottom:1rem;">Indexa un incidente cerrado manualmente para que el RAG lo conozca en futuras consultas. Normalmente esto se hará automáticamente al cerrar un incidente en Blue Team.</p>
    <form method="POST" action="api/v1/rag_feedback.php" id="rag-feedback-form" style="display:none;"></form>
    <form method="POST" action="rag_incidents.php" onsubmit="return submitFeedback(this);">
        <?php echo csrfInput(); ?>
        <input type="hidden" name="action" value="feedback">
        <div class="dashboard-grid">
            <div class="widget" style="padding:1.25rem;">
                <label>Resumen del incidente</label>
                <textarea name="summary" rows="3" placeholder="Ej: Phishing dirigido al CFO. Usuario reportó. Bloqueado en EOP. Sin compromiso." required></textarea>
                <label>Veredicto</label>
                <select name="verdict">
                    <option value="TP">True Positive</option>
                    <option value="FP">False Positive</option>
                    <option value="Needs Review">Needs Review</option>
                </select>
                <label>Severidad</label>
                <select name="severity">
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
            </div>
            <div class="widget" style="padding:1.25rem;">
                <label>Táctica MITRE</label>
                <input type="text" name="mitre_tactic" placeholder="Ej: Initial Access">
                <label>Técnica MITRE</label>
                <input type="text" name="mitre_technique" placeholder="Ej: T1566.001">
                <label>Clasificación</label>
                <select name="classification">
                    <option value="GENERICO">Genérico</option>
                    <option value="DIRIGIDO">Dirigido</option>
                </select>
            </div>
        </div>
        <button type="submit" class="mt-2">Indexar incidente</button>
        <p id="feedback-msg" class="small mt-1"></p>
    </form>
</div>

<script>
async function submitFeedback(form) {
    const fd = new FormData(form);
    const msg = document.getElementById('feedback-msg');
    try {
        const resp = await fetch('api/v1/rag_feedback.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                summary: fd.get('summary'),
                verdict: fd.get('verdict'),
                severity: fd.get('severity'),
                mitre_tactic: fd.get('mitre_tactic'),
                mitre_technique: fd.get('mitre_technique'),
                classification: fd.get('classification'),
                closed_by: '<?php echo htmlspecialchars($_SESSION['username'] ?? 'web'); ?>',
                closed_at: new Date().toISOString(),
            }),
        });
        const data = await resp.json();
        if (data.success) {
            msg.className = 'alert alert-success';
            msg.textContent = '✅ Incidente #' + data.embedding_id + ' indexado correctamente.';
            form.reset();
            setTimeout(() => location.reload(), 1200);
        } else {
            msg.className = 'alert alert-error';
            msg.textContent = data.error || 'Error';
        }
    } catch (err) {
        msg.className = 'alert alert-error';
        msg.textContent = 'Error de red: ' + err.message;
    }
    return false;
}
</script>

<?php require __DIR__ . '/templates/footer.php'; ?>
