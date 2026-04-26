<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

$taskId = null;
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        $error = 'Token de seguridad inválido. Recarga la página.';
    } else {
        $cveId = validateInput($_POST['cve_id'] ?? '', 50, '/^CVE-\d{4}-\d+$/i') ?: '';
        $product = validateInput($_POST['product'] ?? '', 100);
        $version = validateInput($_POST['version'] ?? '', 50, '/^[\w\s\.\-+_\/]+$/u') ?: '';
        $year = validateInput($_POST['year'] ?? '', 4, '/^\d{0,4}$/') ?: '';
        $severity = validateInput($_POST['severity'] ?? '', 10, '/^(LOW|MEDIUM|HIGH|CRITICAL)?$/') ?: '';
        $maxResults = filter_input(INPUT_POST, 'max_results', FILTER_VALIDATE_INT) ?: 10;
        $maxResults = max(1, min($maxResults, 20));
        
        if (!$cveId && !$product) {
            $error = 'Introduce un CVE ID o un producto/software.';
        } else {
            $input = json_encode([
                'cve_id' => $cveId,
                'product' => $product,
                'version' => $version,
                'year' => $year,
                'severity' => $severity,
                'max_results' => $maxResults
            ], JSON_UNESCAPED_UNICODE);
            
            $newTaskId = Database::insert('tasks', [
                'task_type' => 'cve_search',
                'input_data' => $input,
                'status' => 'pending'
            ]);
            
            // PRG pattern: redirect to avoid duplicate task on refresh
            if ($newTaskId) {
                $_SESSION['last_task_id'] = $newTaskId;
                header('Location: task_cve.php');
                exit;
            }
        }
    }
}

// Restore task ID from PRG redirect
if (isset($_SESSION['last_task_id'])) {
    $taskId = $_SESSION['last_task_id'];
    unset($_SESSION['last_task_id']);
}

// --- Worker status widget data ---
$worker = null;
$workerOnline = false;
try {
    $worker = Database::fetchOne(
        "SELECT * FROM worker_heartbeats ORDER BY created_at DESC LIMIT 1"
    );
    if ($worker && !empty($worker['created_at'])) {
        // SQLite stores CURRENT_TIMESTAMP in UTC; force UTC comparison
        try {
            $heartbeatTime = new DateTime($worker['created_at'], new DateTimeZone('UTC'));
            $now = new DateTime('now', new DateTimeZone('UTC'));
            $workerOnline = ($now->getTimestamp() - $heartbeatTime->getTimestamp()) < 180;
        } catch (Exception $e) {
            $workerOnline = false;
        }
    }
} catch (Exception $e) {
    $worker = null;
}

// --- CVE search history ---
$cveHistory = [];
try {
    $cveHistory = Database::fetchAll(
        "SELECT id, status, created_at FROM tasks WHERE task_type='cve_search' ORDER BY created_at DESC LIMIT 20"
    );
} catch (Exception $e) {
    $cveHistory = [];
}

// --- Recent CVE IDs (from completed tasks) ---
$recentCveRows = [];
try {
    $recentCveRows = Database::fetchAll(
        "SELECT input_data FROM tasks WHERE task_type='cve_search' AND status='completed' ORDER BY created_at DESC LIMIT 30"
    );
} catch (Exception $e) {
    $recentCveRows = [];
}
$recentCves = [];
foreach ($recentCveRows as $row) {
    $data = json_decode($row['input_data'] ?? '{}', true);
    $cid = $data['cve_id'] ?? '';
    if ($cid && !in_array($cid, $recentCves)) {
        $recentCves[] = $cid;
    }
    if (count($recentCves) >= 15) break;
}

// Pre-fill CVE from URL tag click
$prefillCve = validateInput($_GET['cve'] ?? '', 50, '/^CVE-\d{4}-\d+$/i') ?: '';

$pageTitle = 'Búsqueda CVE — OrinSec';
require __DIR__ . '/templates/header.php';
?>
<div class="card">
    <h2>🔍 Búsqueda de vulnerabilidades</h2>
    
    <?php if ($taskId): ?>
        <div id="polling-area" data-task-id="<?php echo $taskId; ?>">
            <p>Tarea <strong>#<?php echo $taskId; ?></strong> creada. Esperando al worker...</p>
            <div class="spinner"></div>
            <div id="status-message" class="small mt-1">Estado: <span class="status-pending">pendiente</span></div>
            <div id="result-area" class="mt-2 hidden">
                <div id="result-content"></div>
                <div class="actions">
                    <button onclick="copyText()">📋 Copiar texto plano</button>
                    <a href="task_result.php?id=<?php echo $taskId; ?>"><button class="secondary">Ver página completa</button></a>
                </div>
            </div>
        </div>
        <script src="assets/js/polling.js"></script>
    <?php else: ?>
        <?php if ($error): ?>
            <p class="alert alert-error"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
        
        <form method="POST" class="form-cve-prominent">
            <?php echo csrfInput(); ?>
            <label for="cve_id">CVE ID</label>
            <input type="text" id="cve_id" name="cve_id" placeholder="Ej: CVE-2024-3393" maxlength="50" pattern="CVE-\d{4}-\d+" title="Formato: CVE-YYYY-NNNNN" value="<?php echo htmlspecialchars($prefillCve); ?>">
            <p class="small">Introduce un CVE ID para búsqueda directa en NVD.</p>
            <button type="submit" class="mt-2">Buscar vulnerabilidad</button>
            
            <button type="button" class="advanced-toggle" onclick="document.getElementById('adv-fields').classList.toggle('open')">⚙️ Búsqueda avanzada ▾</button>
            <div id="adv-fields" class="advanced-fields">
                <label>Producto / Software</label>
                <input type="text" name="product" placeholder="Ej: Apache HTTP Server" maxlength="100">
                
                <label>Versión</label>
                <input type="text" name="version" placeholder="Ej: 2.4.51" maxlength="50">
                
                <label>Año mínimo</label>
                <select name="year">
                    <option value="">Cualquiera</option>
                    <option value="2026">2026</option>
                    <option value="2025">2025</option>
                    <option value="2024">2024</option>
                    <option value="2023">2023</option>
                    <option value="2022">2022</option>
                </select>
                
                <label>Severidad mínima</label>
                <select name="severity">
                    <option value="">Cualquiera</option>
                    <option value="LOW">Baja</option>
                    <option value="MEDIUM">Media</option>
                    <option value="HIGH">Alta</option>
                    <option value="CRITICAL">Crítica</option>
                </select>
                
                <label>Máximo de resultados</label>
                <select name="max_results">
                    <option value="5">5</option>
                    <option value="10" selected>10</option>
                    <option value="20">20</option>
                </select>
            </div>
        </form>
    <?php endif; ?>
</div>

<!-- Worker Status Widget -->
<div class="card">
    <div class="worker-widget" style="margin-top:0;">
        <h3>📡 Estado del Worker</h3>
        <?php if ($worker): ?>
            <div class="worker-grid">
                <div class="metric">
                    <div class="metric-label">Estado</div>
                    <div><span class="status-dot <?php echo $workerOnline ? 'online' : 'offline'; ?>"></span><?php echo $workerOnline ? 'Online' : 'Offline'; ?></div>
                </div>
                <div class="metric">
                    <div class="metric-label">Modelo</div>
                    <div><?php echo htmlspecialchars($worker['model_loaded'] ?? '—'); ?></div>
                </div>
                <div class="metric">
                    <div class="metric-label">CPU</div>
                    <div><?php echo $worker['cpu_percent'] !== null ? round($worker['cpu_percent'], 1) . '%' : '—'; ?></div>
                </div>
                <div class="metric">
                    <div class="metric-label">RAM</div>
                    <div><?php echo $worker['memory_percent'] !== null ? round($worker['memory_percent'], 1) . '%' : '—'; ?></div>
                </div>
                <div class="metric">
                    <div class="metric-label">Último heartbeat</div>
                    <div class="small"><?php echo htmlspecialchars($worker['created_at'] ?? '—'); ?></div>
                </div>
            </div>
            <p class="small mt-1"><a href="admin.php?tab=workers">Ver detalles del worker →</a></p>
        <?php else: ?>
            <p class="small">No hay datos del worker. Asegúrate de que el worker está corriendo en el Orin Nano.</p>
        <?php endif; ?>
    </div>
</div>

<!-- CVE Search History -->
<div class="card">
    <h2>📋 Historial de búsquedas CVE</h2>
    <?php if (empty($cveHistory)): ?>
        <p class="small">No hay búsquedas todavía.</p>
    <?php else: ?>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Estado</th>
                    <th>Creado</th>
                    <th>Acción</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($cveHistory as $t): ?>
                <tr>
                    <td>#<?php echo $t['id']; ?></td>
                    <td class="status-<?php echo $t['status']; ?>"><?php echo ucfirst(htmlspecialchars($t['status'])); ?></td>
                    <td class="small"><?php echo htmlspecialchars($t['created_at']); ?></td>
                    <td>
                        <?php if ($t['status'] === 'completed' || $t['status'] === 'error' || $t['status'] === 'cancelled'): ?>
                            <a href="task_result.php?id=<?php echo $t['id']; ?>">Ver</a>
                        <?php else: ?>
                            <button type="button" class="btn small danger" onclick="cancelTask(<?php echo $t['id']; ?>, '<?php echo $_SESSION['csrf_token']; ?>')">Cancelar</button>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<!-- Recently Searched CVEs -->
<?php if (!empty($recentCves)): ?>
<div class="card">
    <h2>🏷️ CVEs consultados recientemente</h2>
    <p class="small">Haz clic para volver a consultar:</p>
    <div class="cve-tags">
        <?php foreach ($recentCves as $cid): ?>
            <a href="task_cve.php?cve=<?php echo urlencode($cid); ?>" class="cve-tag"><?php echo htmlspecialchars($cid); ?></a>
        <?php endforeach; ?>
    </div>
</div>
<?php endif; ?>

<script>
function cancelTask(taskId, csrfToken) {
    if (!confirm('¿Cancelar tarea #' + taskId + '?')) return;
    fetch('api/v1/task_cancel.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({task_id: taskId, csrf_token: csrfToken})
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            location.reload();
        } else {
            alert('Error: ' + (data.error || 'No se pudo cancelar'));
        }
    })
    .catch(err => alert('Error de red: ' + err));
}
</script>
<?php require __DIR__ . '/templates/footer.php'; ?>
