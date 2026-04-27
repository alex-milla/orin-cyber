<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

$error = '';
$success = '';

// ── Marcar como leída ──────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        $error = 'Token inválido.';
    } else {
        $alertId = filter_input(INPUT_POST, 'mark_read', FILTER_VALIDATE_INT);
        if ($alertId) {
            Database::update('alerts', ['read_at' => date('Y-m-d H:i:s')], 'id = ?', [$alertId]);
            $success = 'Alerta marcada como leída.';
        }
        if (isset($_POST['mark_all_read'])) {
            Database::query("UPDATE alerts SET read_at = ? WHERE read_at IS NULL", [date('Y-m-d H:i:s')]);
            $success = 'Todas las alertas marcadas como leídas.';
        }
    }
}

// ── Filtros ────────────────────────────────────────────────────────
$unreadOnly = isset($_GET['unread']) && $_GET['unread'] === '1';
$severityFilter = validateInput($_GET['severity'] ?? '', 20);

$where = [];
$params = [];
if ($unreadOnly) {
    $where[] = "read_at IS NULL";
}
if ($severityFilter && in_array($severityFilter, ['LOW','MEDIUM','HIGH','CRITICAL'])) {
    $where[] = "severity = ?";
    $params[] = $severityFilter;
}

$whereSql = $where ? 'WHERE ' . implode(' AND ', $where) : '';
$alerts = [];
$unreadCount = 0;
try {
    $alerts = Database::fetchAll(
        "SELECT * FROM alerts {$whereSql} ORDER BY created_at DESC LIMIT 100",
        $params
    );
    $unreadRow = Database::fetchOne("SELECT COUNT(*) as total FROM alerts WHERE read_at IS NULL");
    $unreadCount = (int)($unreadRow['total'] ?? 0);
} catch (PDOException $e) {
    $error = 'Error de base de datos: ' . $e->getMessage();
}

$pageTitle = 'Alertas — OrinSec';
require __DIR__ . '/templates/header.php';
?>
<div class="card">
    <h2>🔔 Alertas <?php if ($unreadCount > 0): ?><span style="background:var(--error);color:#fff;border-radius:50%;padding:.15rem .5rem;font-size:.85rem;"><?php echo $unreadCount; ?></span><?php endif; ?></h2>

    <?php if ($error): ?><p class="alert alert-error"><?php echo htmlspecialchars($error); ?></p><?php endif; ?>
    <?php if ($success): ?><p class="alert alert-success"><?php echo htmlspecialchars($success); ?></p><?php endif; ?>

    <div style="display:flex;gap:1rem;align-items:center;flex-wrap:wrap;margin-bottom:1rem;">
        <form method="GET" style="display:flex;gap:.5rem;align-items:center;">
            <label><input type="checkbox" name="unread" value="1" <?php echo $unreadOnly ? 'checked' : ''; ?>> Solo no leídas</label>
            <select name="severity">
                <option value="">Todas severidades</option>
                <option value="CRITICAL" <?php echo $severityFilter === 'CRITICAL' ? 'selected' : ''; ?>>Crítica</option>
                <option value="HIGH" <?php echo $severityFilter === 'HIGH' ? 'selected' : ''; ?>>Alta</option>
                <option value="MEDIUM" <?php echo $severityFilter === 'MEDIUM' ? 'selected' : ''; ?>>Media</option>
                <option value="LOW" <?php echo $severityFilter === 'LOW' ? 'selected' : ''; ?>>Baja</option>
            </select>
            <button type="submit">Filtrar</button>
        </form>
        <?php if ($unreadCount > 0): ?>
        <form method="POST" style="margin-left:auto;">
            <?php echo csrfInput(); ?>
            <button type="submit" name="mark_all_read" class="secondary">Marcar todas como leídas</button>
        </form>
        <?php endif; ?>
    </div>

    <?php if (empty($alerts)): ?>
        <p class="small">No hay alertas que coincidan con los filtros.</p>
    <?php else: ?>
        <table>
            <thead>
                <tr>
                    <th>CVE</th>
                    <th>Severidad</th>
                    <th>Score</th>
                    <th>EPSS</th>
                    <th>CISA KEV</th>
                    <th>Suscripción</th>
                    <th>Fecha</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($alerts as $a): ?>
                <tr <?php echo $a['read_at'] ? '' : 'style="font-weight:600;background:var(--surface);"'; ?>>
                    <td><a href="task_cve.php?cve=<?php echo urlencode($a['cve_id']); ?>"><?php echo htmlspecialchars($a['cve_id']); ?></a></td>
                    <td><?php echo htmlspecialchars($a['severity'] ?? '—'); ?></td>
                    <td><?php echo $a['score'] !== null ? round((float)$a['score'], 1) : '—'; ?></td>
                    <td><?php echo $a['epss_score'] !== null ? round((float)$a['epss_score'] * 100, 2) . '%' : '—'; ?></td>
                    <td><?php echo $a['kev'] ? '✅' : '—'; ?></td>
                    <td class="small"><?php echo htmlspecialchars($a['matched_subscription'] ?? ''); ?></td>
                    <td class="small"><?php echo htmlspecialchars($a['created_at']); ?></td>
                    <td>
                        <?php if (!$a['read_at']): ?>
                        <form method="POST" style="display:inline;">
                            <?php echo csrfInput(); ?>
                            <input type="hidden" name="mark_read" value="<?php echo $a['id']; ?>">
                            <button type="submit" class="small">Leído</button>
                        </form>
                        <?php else: ?>
                        <span class="small" style="color:var(--text-muted);">Leído</span>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<div class="card">
    <h3>⚙️ Gestión de suscripciones</h3>
    <p class="small">Las suscripciones definen qué CVEs generan alertas. El worker ejecuta un escaneo periódico (tarea <code>alert_scan</code>) que busca CVEs recientes coincidentes.</p>
    <p><a href="admin.php?tab=alerts"><button>Administrar suscripciones →</button></a></p>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
