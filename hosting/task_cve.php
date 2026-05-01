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
        $cveInput = trim($_POST['cve_id'] ?? '');
        $product = validateInput($_POST['product'] ?? '', 100);
        $version = validateInput($_POST['version'] ?? '', 50, '/^[\w\s\.\-+_\/]+$/u') ?: '';
        $year = validateInput($_POST['year'] ?? '', 4, '/^\d{0,4}$/') ?: '';
        $severity = validateInput($_POST['severity'] ?? '', 10, '/^(LOW|MEDIUM|HIGH|CRITICAL)?$/') ?: '';
        $maxResults = filter_input(INPUT_POST, 'max_results', FILTER_VALIDATE_INT) ?: 10;
        $maxResults = max(1, min($maxResults, 20));

        // Parsear múltiples CVE IDs (coma, salto de línea, espacio)
        $cveList = [];
        if ($cveInput) {
            $parts = preg_split('/[\s,]+/', strtoupper($cveInput));
            foreach ($parts as $part) {
                if (preg_match('/^CVE-\d{4}-\d+$/i', $part)) {
                    $cveList[] = $part;
                }
            }
            $cveList = array_unique(array_slice($cveList, 0, 20));
        }

        $cveId = $cveList[0] ?? '';

        if (empty($cveList) && !$product) {
            $error = 'Introduce al menos un CVE ID o un producto/software.';
        } else {
            // Leer ejecutor por defecto desde config
            $execConfig = Database::fetchOne("SELECT value FROM config WHERE key = 'default_task_executor'");
            $assignment = $execConfig['value'] ?? 'worker';

            $assignment = $_POST['executor'] ?? 'worker';
            if ($assignment !== 'worker' && !preg_match('/^provider:\d+:[\w\-.@:\/]+$/', $assignment)) {
                $assignment = 'worker';
            }

            // Leer plantilla seleccionada
            $templateContent = '';
            $templateId = filter_input(INPUT_POST, 'template_id', FILTER_VALIDATE_INT);
            if ($templateId) {
                foreach ($reportTemplates as $tpl) {
                    if ((int)$tpl['id'] === $templateId) {
                        $templateContent = $tpl['content'];
                        break;
                    }
                }
            }
            if (!$templateContent && !empty($reportTemplates)) {
                // Usar la plantilla por defecto
                foreach ($reportTemplates as $tpl) {
                    if ($tpl['is_default']) {
                        $templateContent = $tpl['content'];
                        break;
                    }
                }
            }

            // Si hay múltiples CVEs, crear una tarea por cada uno (cola individual)
            $createdIds = [];
            if (count($cveList) > 1) {
                foreach ($cveList as $cid) {
                    $input = json_encode([
                        'cve_id' => $cid,
                        'cve_list' => [],
                        'product' => '',
                        'version' => $version,
                        'year' => $year,
                        'severity' => $severity,
                        'max_results' => 1,
                        'template' => $templateContent,
                        'language' => $_POST['language'] ?? 'es',
                    ], JSON_UNESCAPED_UNICODE);
                    $tid = Database::insert('tasks', [
                        'task_type' => 'cve_search',
                        'input_data' => $input,
                        'status' => 'pending',
                        'assignment' => $assignment
                    ]);
                    if ($tid) {
                        $createdIds[] = $tid;
                    }
                }
            } else {
                // Modo single o búsqueda por producto
                $input = json_encode([
                    'cve_id' => $cveId,
                    'cve_list' => $cveList,
                    'product' => $product,
                    'version' => $version,
                    'year' => $year,
                    'severity' => $severity,
                    'max_results' => $maxResults,
                    'template' => $templateContent,
                    'language' => $_POST['language'] ?? 'es',
                ], JSON_UNESCAPED_UNICODE);
                $tid = Database::insert('tasks', [
                    'task_type' => 'cve_search',
                    'input_data' => $input,
                    'status' => 'pending',
                    'assignment' => $assignment
                ]);
                if ($tid) {
                    $createdIds[] = $tid;
                }
            }

            // PRG pattern: redirect to avoid duplicate task on refresh
            if (!empty($createdIds)) {
                $_SESSION['last_task_ids'] = $createdIds;
                if (count($createdIds) === 1) {
                    $_SESSION['last_task_id'] = $createdIds[0];
                }
                header('Location: task_cve.php');
                exit;
            }
        }
    }
}

// Restore task ID(s) from PRG redirect
$taskId = null;
$taskIds = [];
if (isset($_SESSION['last_task_ids'])) {
    $taskIds = $_SESSION['last_task_ids'];
    unset($_SESSION['last_task_ids']);
    if (count($taskIds) === 1) {
        $taskId = $taskIds[0];
    }
}
if (isset($_SESSION['last_task_id'])) {
    $taskId = $_SESSION['last_task_id'];
    unset($_SESSION['last_task_id']);
}

// --- Worker status widget data ---
$worker = null;
$workerOnline = false;
try {
    $worker = Database::fetchOne(
        "SELECT *, CASE WHEN created_at > datetime('now', '-3 minutes') THEN 1 ELSE 0 END as is_online
         FROM worker_heartbeats ORDER BY created_at DESC LIMIT 1"
    );
    $workerOnline = $worker && !empty($worker['is_online']);
} catch (Exception $e) {
    $worker = null;
    $workerOnline = false;
}

// Catálogo de modelos para etiquetas legibles
$modelCatalog = [];
try {
    $modelCatalog = Database::fetchAll("SELECT pattern, label, tier FROM model_catalog ORDER BY id");
} catch (Throwable $e) {
    $modelCatalog = [];
}

function resolveModelLabel(string $filename, array $catalog): string {
    foreach ($catalog as $entry) {
        $pattern = str_replace(['*', '?'], ['.*', '.'], $entry['pattern']);
        $pattern = '/^' . str_replace('/', '\/', $pattern) . '$/i';
        if (preg_match($pattern, $filename)) {
            return $entry['label'] . ($entry['tier'] ? ' (' . $entry['tier'] . ')' : '');
        }
    }
    return $filename;
}
$modelDisplayName = $worker ? resolveModelLabel($worker['model_loaded'] ?? '', $modelCatalog) : '—';

// --- CVE search history ---
$cveHistory = [];
try {
    $cveHistory = Database::fetchAll(
        "SELECT id, status, created_at, executed_by, input_data, cvss_base_score, cvss_severity FROM tasks WHERE task_type='cve_search' ORDER BY created_at DESC LIMIT 20"
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

// Virtual Workers disponibles
$virtualWorkers = [];
try {
    $virtualWorkers = Database::fetchAll(
        "SELECT 'provider:' || p.id || ':' || m.model_id as value,
                p.label || ' → ' || m.label as label,
                m.model_id,
                m.tags
         FROM external_models m
         JOIN external_providers p ON p.id = m.provider_id
         WHERE m.is_active = 1 AND p.is_active = 1
         ORDER BY p.label, m.label"
    );
} catch (Throwable $e) {
    $virtualWorkers = [];
}

// Plantillas de informe CVE disponibles
$reportTemplates = [];
try {
    $reportTemplates = Database::fetchAll(
        "SELECT id, name, content, is_default FROM report_templates WHERE task_type = 'cve_search' ORDER BY is_default DESC, name ASC"
    );
} catch (Throwable $e) {
    $reportTemplates = [];
}

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
        <script src="assets/js/polling.js?v=2"></script>
    <?php elseif (!empty($taskIds)): ?>
        <div class="alert alert-success">
            <p><strong><?php echo count($taskIds); ?></strong> tareas individuales creadas (una por CVE):</p>
            <div style="display:flex;flex-wrap:wrap;gap:.5rem;margin-top:.5rem;">
                <?php foreach ($taskIds as $tid): ?>
                    <a href="task_result.php?id=<?php echo (int)$tid; ?>"><button class="secondary small">#<?php echo (int)$tid; ?></button></a>
                <?php endforeach; ?>
            </div>
            <p class="small mt-1">Se procesarán de 1 en 1 en la cola del worker. Refresca el historial para ver el progreso.</p>
        </div>
    <?php else: ?>
        <?php if ($error): ?>
            <p class="alert alert-error"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
        
        <form method="POST" class="form-cve-prominent">
            <?php echo csrfInput(); ?>
            <label for="cve_id">CVE ID(s)</label>
            <textarea id="cve_id" name="cve_id" rows="3" maxlength="600" placeholder="Ej: CVE-2024-3393, CVE-2021-44228"><?php echo htmlspecialchars($prefillCve); ?></textarea>
            <p class="small">Introduce uno o varios CVE IDs (máximo 20), separados por coma, espacio o salto de línea.</p>
            <label for="executor" style="margin-top:1rem;display:block;">🖥️ Ejecutor</label>
            <select id="executor" name="executor" style="min-width:320px;margin-bottom:.5rem;">
                <option value="worker">🏠 Worker local (Orin)</option>
                <?php foreach ($virtualWorkers as $vw):
                    $vwTags = [];
                    if (!empty($vw['tags'])) {
                        $tagsArr = json_decode($vw['tags'], true);
                        if (is_array($tagsArr)) {
                            foreach ($tagsArr as $t) {
                                if ($t === 'cybersecurity') $vwTags[] = '🛡️';
                                if ($t === 'reasoning') $vwTags[] = '🧠';
                                if ($t === 'recommended') $vwTags[] = '⭐';
                            }
                        }
                    }
                    $tagStr = $vwTags ? ' ' . implode(' ', $vwTags) : '';
                ?>
                <option value="<?php echo htmlspecialchars($vw['value']); ?>">
                    ☁️ <?php echo htmlspecialchars($vw['label']) . $tagStr; ?>
                </option>
                <?php endforeach; ?>
            </select>

            <?php if (!empty($reportTemplates)): ?>
            <label for="template_id" style="margin-top:1rem;display:block;">📄 Plantilla de informe</label>
            <select id="template_id" name="template_id" style="min-width:320px;margin-bottom:.5rem;">
                <?php foreach ($reportTemplates as $tpl): ?>
                <option value="<?php echo (int)$tpl['id']; ?>" <?php echo $tpl['is_default'] ? 'selected' : ''; ?>>
                    <?php echo htmlspecialchars($tpl['name']) . ($tpl['is_default'] ? ' (por defecto)' : ''); ?>
                </option>
                <?php endforeach; ?>
            </select>
            <?php endif; ?>

            <label for="language" style="margin-top:1rem;display:block;">🌐 Idioma del informe</label>
            <select id="language" name="language" style="min-width:320px;margin-bottom:.5rem;">
                <option value="es" selected>🇪🇸 Español</option>
                <option value="en">🇬🇧 English</option>
            </select>

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
                    <div><?php echo htmlspecialchars($modelDisplayName); ?></div>
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
        <input type="search" id="cve-history-filter"
               placeholder="🔎 Filtrar por CVE ID, producto, ejecutor..."
               style="width:100%;max-width:480px;margin-bottom:.75rem;">
        <table id="cve-history-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Consulta</th>
                    <th>Estado</th>
                    <th>Score</th>
                    <th>Ejecutor</th>
                    <th>Creado</th>
                    <th>Acción</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($cveHistory as $t):
                $inputData = json_decode($t['input_data'] ?? '{}', true);
                $cveList = $inputData['cve_list'] ?? [];
                $product = $inputData['product'] ?? '';
                if (!empty($cveList)) {
                    $queryLabel = implode(', ', array_slice($cveList, 0, 3));
                    if (count($cveList) > 3) $queryLabel .= ' +' . (count($cveList) - 3);
                } elseif ($product) {
                    $queryLabel = $product;
                } else {
                    $queryLabel = '—';
                }

                $score = $t['cvss_base_score'];
                $sev   = $t['cvss_severity'] ?? '';
                if ($score !== null) {
                    $sevClass = 'sev-' . strtolower($sev ?: 'none');
                    $scoreCell = '<span class="cvss-badge ' . $sevClass . '">'
                               . number_format((float)$score, 1)
                               . ($sev ? ' ' . htmlspecialchars(ucfirst(strtolower($sev))) : '')
                               . '</span>';
                } else {
                    $scoreCell = '<span class="small">—</span>';
                }
            ?>
                <tr>
                    <td>#<?php echo $t['id']; ?></td>
                    <td class="small"><?php echo htmlspecialchars($queryLabel); ?></td>
                    <td class="status-<?php echo $t['status']; ?>"><?php echo ucfirst(htmlspecialchars($t['status'])); ?></td>
                    <td><?php echo $scoreCell; ?></td>
                    <td class="small"><?php echo htmlspecialchars($t['executed_by'] ?? '—'); ?></td>
                    <td class="small"><?php echo htmlspecialchars($t['created_at']); ?></td>
                    <td>
                        <?php if ($t['status'] === 'completed' || $t['status'] === 'error' || $t['status'] === 'cancelled'): ?>
                            <a href="task_result.php?id=<?php echo $t['id']; ?>">Ver</a>
                            <?php if ($t['status'] === 'completed'): ?>
                                · <a href="export_cve.php?id=<?php echo $t['id']; ?>&format=md" title="Descargar Markdown">MD</a>
                                · <a href="export_cve.php?id=<?php echo $t['id']; ?>&format=docx" title="Descargar Word">DOC</a>
                            <?php endif; ?>
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
    const fd = new FormData();
    fd.append('task_id', taskId);
    fd.append('csrf_token', csrfToken);
    fetch('ajax_admin.php?action=cancel_task', {method: 'POST', body: fd})
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

/**
 * Polling de filas pendientes del historial CVE.
 * Refresca estado, ejecutor y botón de acción cuando una tarea termina.
 */
(function() {
    const table = document.getElementById('cve-history-table');
    if (!table) return;

    const POLL_MS = 5000;

    function pendingTaskIds() {
        const ids = [];
        table.querySelectorAll('tbody tr').forEach(tr => {
            const statusCell = tr.querySelector('td:nth-child(3)');
            if (!statusCell) return;
            const cls = statusCell.className || '';
            if (cls.includes('status-pending') || cls.includes('status-processing')) {
                const idCell = tr.querySelector('td:first-child');
                if (idCell) {
                    const m = idCell.textContent.trim().match(/#(\d+)/);
                    if (m) ids.push(parseInt(m[1], 10));
                }
            }
        });
        return ids;
    }

    async function refreshOne(taskId) {
        try {
            const res = await fetch('ajax_check_status.php?task_id=' + taskId, {
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            const data = await res.json();
            if (data.error) return;
            if (data.status === 'pending' || data.status === 'processing') return;
            updateRow(taskId, data.status, data.executed_by);
        } catch (e) { /* silencioso */ }
    }

    function updateRow(taskId, status, executedBy) {
        const rows = table.querySelectorAll('tbody tr');
        for (const r of rows) {
            const idCell = r.querySelector('td:first-child');
            if (idCell && idCell.textContent.trim() === '#' + taskId) {
                const statusCell = r.querySelector('td:nth-child(3)');
                const execCell = r.querySelector('td:nth-child(4)');
                const actionCell = r.querySelector('td:last-child');
                if (statusCell) {
                    statusCell.textContent = status.charAt(0).toUpperCase() + status.slice(1);
                    statusCell.className = 'status-' + status;
                }
                if (execCell && executedBy) execCell.textContent = executedBy;
                if (actionCell) {
                    actionCell.innerHTML = '<a href="task_result.php?id=' + taskId + '"><button class="secondary small">Ver resultado</button></a>';
                }
                break;
            }
        }
    }

    async function tick() {
        const ids = pendingTaskIds();
        if (ids.length === 0) return;
        await Promise.all(ids.map(refreshOne));
    }

    setInterval(tick, POLL_MS);
    setTimeout(tick, 1500);
})();

// Filtro client-side del historial CVE
(function() {
    const input = document.getElementById('cve-history-filter');
    const table = document.getElementById('cve-history-table');
    if (!input || !table) return;

    input.addEventListener('input', () => {
        const q = input.value.trim().toLowerCase();
        table.querySelectorAll('tbody tr').forEach(tr => {
            const text = tr.textContent.toLowerCase();
            tr.style.display = (q === '' || text.includes(q)) ? '' : 'none';
        });
    });
})();
</script>
<?php require __DIR__ . '/templates/footer.php'; ?>
