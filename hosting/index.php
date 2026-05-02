<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

// ── Estadísticas principales ─────────────────────────────────────────
$taskStats = ['total' => 0, 'pending' => 0, 'processing' => 0, 'completed' => 0, 'error' => 0];
$unreadAlerts = 0;
$openIncidents = 0;
$workerOnline = false;
$workerInfo = null;
$severityDistribution = [];
$recentAlerts = [];
$recentTasks = [];

// URL del chat local (túnel de Cloudflare) — constante definida en config.php
$chatUrl = LOCAL_LLM_URL;

try {
    // Totales por estado de tareas
    $rows = Database::fetchAll("SELECT status, COUNT(*) as cnt FROM tasks GROUP BY status");
    foreach ($rows as $r) {
        $taskStats[$r['status']] = (int)$r['cnt'];
        $taskStats['total'] += (int)$r['cnt'];
    }
} catch (Exception $e) {}

try {
    $row = Database::fetchOne("SELECT COUNT(*) as total FROM alerts WHERE read_at IS NULL");
    $unreadAlerts = (int)($row['total'] ?? 0);
} catch (Exception $e) {}

try {
    $row = Database::fetchOne("SELECT COUNT(*) as total FROM incidents WHERE status = 'open'");
    $openIncidents = (int)($row['total'] ?? 0);
} catch (Exception $e) {}

try {
    $workerInfo = Database::fetchOne(
        "SELECT h.*, k.name as worker_name 
         FROM worker_heartbeats h
         INNER JOIN api_keys k ON k.id = h.api_key_id
         WHERE h.created_at > datetime('now', '-3 minutes')
         ORDER BY h.created_at DESC LIMIT 1"
    );
    $workerOnline = $workerInfo !== null;
} catch (Exception $e) {}

// Distribución de severidad de alertas (últimas 100)
try {
    $severityRows = Database::fetchAll(
        "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity ORDER BY cnt DESC"
    );
    $severityDistribution = $severityRows;
} catch (Exception $e) {}

// Últimas alertas
try {
    $recentAlerts = Database::fetchAll(
        "SELECT id, cve_id, severity, score, created_at, read_at 
         FROM alerts 
         ORDER BY created_at DESC 
         LIMIT 5"
    );
} catch (Exception $e) {}

// Últimas tareas
try {
    $recentTasks = Database::fetchAll(
        "SELECT id, task_type, status, created_at, completed_at 
         FROM tasks 
         ORDER BY created_at DESC 
         LIMIT 10"
    );
} catch (Exception $e) {}

// Helper: color de severidad para badges
function sevClass(?string $sev): string {
    return match (strtoupper($sev ?? '')) {
        'CRITICAL' => 'severity-critical',
        'HIGH'     => 'severity-high',
        'MEDIUM'   => 'severity-medium',
        'LOW'      => 'severity-low',
        default    => 'severity-info',
    };
}

$pageTitle = 'Dashboard — OrinSec';
require __DIR__ . '/templates/header.php';
?>

<!-- Welcome Banner -->
<div class="welcome-banner">
    <h2>👋 Bienvenido, <?php echo htmlspecialchars($_SESSION['username']); ?></h2>
    <p>OrinSec — Centro de operaciones de ciberseguridad asistido por IA local</p>
</div>

<!-- KPIs -->
<div class="kpi-grid">
    <div class="kpi-card kpi-primary">
        <div class="kpi-icon">📋</div>
        <div class="kpi-value"><?php echo $taskStats['total']; ?></div>
        <div class="kpi-label">Tareas totales</div>
        <div class="kpi-meta"><?php echo $taskStats['pending']; ?> pendientes · <?php echo $taskStats['processing']; ?> en curso</div>
    </div>
    <div class="kpi-card kpi-error">
        <div class="kpi-icon">🔔</div>
        <div class="kpi-value"><?php echo $unreadAlerts; ?></div>
        <div class="kpi-label">Alertas sin leer</div>
        <div class="kpi-meta">
            <?php if ($unreadAlerts > 0): ?>
                <a href="alerts.php" style="color:inherit;text-decoration:underline;">Ver alertas →</a>
            <?php else: ?>
                Todo claro
            <?php endif; ?>
        </div>
    </div>
    <div class="kpi-card kpi-warning">
        <div class="kpi-icon">🛡️</div>
        <div class="kpi-value"><?php echo $openIncidents; ?></div>
        <div class="kpi-label">Incidentes abiertos</div>
        <div class="kpi-meta">
            <?php if ($openIncidents > 0): ?>
                <a href="blue_team.php" style="color:inherit;text-decoration:underline;">Revisar →</a>
            <?php else: ?>
                Sin incidentes activos
            <?php endif; ?>
        </div>
    </div>
    <div class="kpi-card <?php echo $workerOnline ? 'kpi-success' : 'kpi-error'; ?>">
        <div class="kpi-icon">🤖</div>
        <div class="kpi-value"><?php echo $workerOnline ? 'Online' : 'Offline'; ?></div>
        <div class="kpi-label">Worker Orin</div>
        <div class="kpi-meta">
            <?php if ($workerOnline && $workerInfo): ?>
                <?php echo htmlspecialchars($workerInfo['worker_name'] ?? 'Worker'); ?> · Modelo <?php echo htmlspecialchars($workerInfo['model_loaded'] ?? '—'); ?>
            <?php else: ?>
                No hay heartbeats recientes
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Grid de widgets -->
<div class="dashboard-grid">
    <!-- Distribución de alertas -->
    <div class="widget">
        <h3>📊 Severidad de alertas</h3>
        <?php if (empty($severityDistribution)): ?>
            <p class="empty-state">No hay alertas registradas todavía.</p>
        <?php else:
            $maxCount = max(array_column($severityDistribution, 'cnt'));
            $sevColors = [
                'CRITICAL' => 'bar-critical',
                'HIGH'     => 'bar-high',
                'MEDIUM'   => 'bar-medium',
                'LOW'      => 'bar-low',
            ];
        ?>
        <div class="mini-bar-chart">
            <?php foreach ($severityDistribution as $sev): 
                $pct = $maxCount > 0 ? round(((int)$sev['cnt'] / $maxCount) * 100) : 0;
                $color = $sevColors[strtoupper($sev['severity'] ?? '')] ?? 'bar-info';
                $label = ucfirst(strtolower($sev['severity'] ?? 'Desconocida'));
            ?>
            <div class="mini-bar-row">
                <div class="mini-bar-label"><?php echo htmlspecialchars($label); ?></div>
                <div class="mini-bar-track">
                    <div class="mini-bar-fill <?php echo $color; ?>" style="width: <?php echo $pct; ?>%;"></div>
                </div>
                <div class="mini-bar-count"><?php echo (int)$sev['cnt']; ?></div>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </div>

    <!-- Estado del worker -->
    <div class="widget">
        <h3>
            🤖 Estado del worker
            <span class="status-pill status-<?php echo $workerOnline ? 'online' : 'offline'; ?>">
                <span class="dot"></span>
                <?php echo $workerOnline ? 'Online' : 'Offline'; ?>
            </span>
        </h3>
        <?php if ($workerOnline && $workerInfo): ?>
        <div class="worker-mini">
            <div class="metric">
                <div class="metric-label">CPU</div>
                <div class="metric-value"><?php echo round((float)$workerInfo['cpu_percent'], 1); ?>%</div>
            </div>
            <div class="metric">
                <div class="metric-label">Memoria</div>
                <div class="metric-value"><?php echo round((float)$workerInfo['memory_percent'], 1); ?>%</div>
            </div>
            <div class="metric">
                <div class="metric-label">Disco</div>
                <div class="metric-value"><?php echo round((float)$workerInfo['disk_percent'], 1); ?>%</div>
            </div>
            <div class="metric">
                <div class="metric-label">Temp</div>
                <div class="metric-value"><?php echo $workerInfo['temperature_c'] !== null ? round((float)$workerInfo['temperature_c'], 1) . '°C' : '—'; ?></div>
            </div>
        </div>
        <p class="small" style="margin-top:0.75rem;color:var(--text-muted);">
            Modelo cargado: <strong style="color:var(--text);"><?php echo htmlspecialchars($workerInfo['model_loaded'] ?? '—'); ?></strong><br>
            Último heartbeat: <?php echo htmlspecialchars($workerInfo['created_at'] ?? '—'); ?>
        </p>
        <?php else: ?>
        <p class="empty-state">El worker no ha enviado heartbeats en los últimos 3 minutos.</p>
        <p style="text-align:center;margin-top:0.5rem;">
            <a href="admin.php?tab=workers" class="btn small">Diagnosticar</a>
        </p>
        <?php endif; ?>
    </div>
</div>

<!-- Accesos rápidos -->
<div class="card">
    <h2>🚀 Acceso rápido</h2>
    <div class="quick-actions">
        <a href="task_cve.php" class="quick-action-btn">
            <span class="qa-icon">🔍</span>
            <span class="qa-label">Búsqueda CVE</span>
            <span class="qa-desc">Consulta vulnerabilidades en NVD, EPSS y CISA KEV</span>
        </a>
        <a href="blue_team.php" class="quick-action-btn">
            <span class="qa-icon">🛡️</span>
            <span class="qa-label">Blue Team</span>
            <span class="qa-desc">Análisis de incidentes, IOCs y queries KQL</span>
        </a>
        <a href="ioc_converter.php" class="quick-action-btn">
            <span class="qa-icon">🔄</span>
            <span class="qa-label">IOC → STIX</span>
            <span class="qa-desc">Convierte indicadores de compromiso a formato STIX 2.1</span>
        </a>
        <a href="<?php echo htmlspecialchars($chatUrl); ?>" class="quick-action-btn" target="_blank" rel="noopener noreferrer">
            <span class="qa-icon">💬</span>
            <span class="qa-label">Chat IA</span>
            <span class="qa-desc">Asistente de ciberseguridad con historial</span>
        </a>
        <a href="alerts.php" class="quick-action-btn">
            <span class="qa-icon">🔔</span>
            <span class="qa-label">Alertas</span>
            <span class="qa-desc">Gestión de alertas y suscripciones</span>
        </a>
        <a href="rag_incidents.php" class="quick-action-btn">
            <span class="qa-icon">🧠</span>
            <span class="qa-label">RAG</span>
            <span class="qa-desc">Memoria histórica de incidentes</span>
        </a>
        <?php if (isAdmin()): ?>
        <a href="admin.php" class="quick-action-btn">
            <span class="qa-icon">⚙️</span>
            <span class="qa-label">Admin</span>
            <span class="qa-desc">Configuración, workers y proveedores</span>
        </a>
        <?php endif; ?>
    </div>
</div>

<!-- Últimas alertas + tareas en grid -->
<div class="dashboard-grid">
    <!-- Últimas alertas -->
    <div class="widget">
        <h3>
            🔔 Últimas alertas
            <a href="alerts.php" class="widget-action">Ver todas →</a>
        </h3>
        <?php if (empty($recentAlerts)): ?>
            <p class="empty-state">No hay alertas recientes.</p>
        <?php else: ?>
            <?php foreach ($recentAlerts as $a): ?>
            <div class="alert-row">
                <span class="badge <?php echo sevClass($a['severity']); ?>"><?php echo htmlspecialchars(strtoupper($a['severity'] ?? '—')); ?></span>
                <span class="alert-title">
                    <a href="task_cve.php?cve=<?php echo urlencode($a['cve_id']); ?>"><?php echo htmlspecialchars($a['cve_id']); ?></a>
                </span>
                <span class="alert-date"><?php echo htmlspecialchars(date('d/m H:i', strtotime($a['created_at']))); ?></span>
            </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>

    <!-- Historial de tareas recientes -->
    <div class="widget">
        <h3>
            📋 Tareas recientes
            <a href="task_cve.php" class="widget-action">Nueva tarea →</a>
        </h3>
        <?php if (empty($recentTasks)): ?>
            <p class="empty-state">No hay tareas todavía.</p>
        <?php else: ?>
            <table class="widget-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Tipo</th>
                        <th>Estado</th>
                        <th>Fecha</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($recentTasks as $t): ?>
                    <tr>
                        <td>#<?php echo $t['id']; ?></td>
                        <td><?php echo htmlspecialchars($t['task_type']); ?></td>
                        <td>
                            <span class="status-pill status-<?php echo $t['status']; ?>">
                                <span class="dot"></span>
                                <?php echo ucfirst(htmlspecialchars($t['status'])); ?>
                            </span>
                        </td>
                        <td class="small" style="white-space:nowrap;"><?php echo htmlspecialchars(date('d/m H:i', strtotime($t['created_at']))); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
