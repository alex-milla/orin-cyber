<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/updater.php';

requireAdmin();

$tab = $_GET['tab'] ?? 'updates';
$renderError = '';

try {
    $updater = new Updater();
    $currentVersion = $updater->getCurrentVersion();
} catch (Throwable $e) {
    $currentVersion = '0.0.0';
    $renderError = 'Updater error: ' . $e->getMessage();
}

try {
    $users = Database::fetchAll('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at DESC');
} catch (Throwable $e) {
    $users = [];
    $renderError = ($renderError ? $renderError . ' | ' : '') . 'Users DB error: ' . $e->getMessage();
}

try {
    $backups = $updater->listBackups();
} catch (Throwable $e) {
    $backups = [];
}

try {
    $apiKeys = Database::fetchAll("SELECT id, name, api_key, is_active, last_used, created_at FROM api_keys ORDER BY created_at DESC");
} catch (Throwable $e) {
    $apiKeys = [];
}

try {
    $alertSubs = Database::fetchAll("SELECT id, type, value, severity_threshold, active, created_at FROM alert_subscriptions ORDER BY created_at DESC");
} catch (Throwable $e) {
    $alertSubs = [];
}

// Catálogo de modelos para etiquetas legibles — Fase 4
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

try {
    $workers = Database::fetchAll(
        "SELECT h.*, k.name as worker_name, k.api_key,
            CASE WHEN h.created_at > datetime('now', '-2 minutes') THEN 1 ELSE 0 END as is_online
         FROM worker_heartbeats h
         INNER JOIN api_keys k ON k.id = h.api_key_id
         WHERE h.created_at = (
             SELECT MAX(created_at) FROM worker_heartbeats WHERE api_key_id = h.api_key_id
         )
         ORDER BY h.created_at DESC"
    );
} catch (Throwable $e) {
    $workers = [];
}

try {
    $virtualWorkers = Database::fetchAll(
        "SELECT m.id, m.model_id, m.label as model_label, m.context_window,
                p.id as provider_id, p.label as provider_label, p.base_url
         FROM external_models m
         JOIN external_providers p ON p.id = m.provider_id
         WHERE m.is_active = 1 AND p.is_active = 1
         ORDER BY p.label, m.label"
    );
} catch (Throwable $e) {
    $virtualWorkers = [];
}

try {
    $regRow = Database::fetchOne("SELECT value FROM config WHERE key = 'allow_registration'");
    $regEnabled = !$regRow || $regRow['value'] === '1';
} catch (Throwable $e) {
    $regEnabled = false;
}

try {
    $patRow = Database::fetchOne("SELECT value FROM config WHERE key = 'github_pat'");
    $githubPat = $patRow['value'] ?? '';
} catch (Throwable $e) {
    $githubPat = '';
}

try {
    $execRow = Database::fetchOne("SELECT value FROM config WHERE key = 'default_task_executor'");
    $defaultExecutor = $execRow['value'] ?? 'worker';
} catch (Throwable $e) {
    $defaultExecutor = 'worker';
}

try {
    $executorOptions = Database::fetchAll(
        "SELECT 'worker' as value, 'Worker local (Orin)' as label
         UNION ALL
         SELECT 'provider:' || p.id || ':' || m.model_id as value,
                p.label || ' → ' || m.label as label
         FROM external_models m
         JOIN external_providers p ON p.id = m.provider_id
         WHERE m.is_active = 1 AND p.is_active = 1"
    );
} catch (Throwable $e) {
    $executorOptions = [['value' => 'worker', 'label' => 'Worker local (Orin)']];
}

// Plantillas de informe
$reportTemplates = [];
try {
    $reportTemplates = Database::fetchAll(
        "SELECT id, task_type, name, content, is_default, created_at, updated_at FROM report_templates ORDER BY task_type, is_default DESC, name ASC"
    );
} catch (Throwable $e) {
    $reportTemplates = [];
}

$pageTitle = 'Administración — OrinSec';
require __DIR__ . '/templates/header.php';
?>
<div class="card">
    <h2>⚙️ Panel de administración</h2>
    <?php if ($renderError): ?>
        <div class="alert alert-error"><?php echo htmlspecialchars($renderError); ?></div>
    <?php endif; ?>
    <div class="tabs">
        <a href="?tab=updates" class="<?php echo $tab==='updates'?'active':''; ?>">Actualizaciones</a>
        <a href="?tab=workers" class="<?php echo $tab==='workers'?'active':''; ?>">Workers</a>
        <a href="?tab=users" class="<?php echo $tab==='users'?'active':''; ?>">Usuarios</a>
        <a href="?tab=alerts" class="<?php echo $tab==='alerts'?'active':''; ?>">Alertas</a>
        <a href="?tab=providers" class="<?php echo $tab==='providers'?'active':''; ?>">Proveedores</a>
        <a href="?tab=config" class="<?php echo $tab==='config'?'active':''; ?>">Configuración</a>
        <a href="?tab=templates" class="<?php echo $tab==='templates'?'active':''; ?>">Plantillas</a>
    </div>

    <?php if ($tab === 'updates'): ?>
    <div id="update-panel">
        <h3>🔐 GitHub PAT (repo privado)</h3>
        <p class="small">Si este repositorio es privado, introduce aquí un <strong>Personal Access Token</strong> de GitHub con permiso <code>repo</code> para que el updater pueda descargar releases.</p>
        <form method="POST" action="ajax_admin.php?action=save_github_pat" onsubmit="return savePat(this);" class="flex gap-2 items-end mb-3">
            <?php echo csrfInput(); ?>
            <input type="password" name="pat" value="<?php echo htmlspecialchars($githubPat); ?>" placeholder="ghp_xxxxxxxxxxxx" class="w-full font-mono">
            <button type="submit">💾 Guardar</button>
        </form>
        <p id="pat-msg" class="small mb-3"></p>

        <div class="mt-4 divider-top">
            <h3>Estado del sistema</h3>
            <p>Versión instalada: <code id="current-version"><?php echo htmlspecialchars($currentVersion); ?></code></p>
            <p>Versión remota: <code id="remote-version">Consultando...</code></p>
            <p id="remote-message" class="small"></p>
            <div class="flex gap-2 mt-2 mb-2">
                <button id="btn-check" onclick="checkUpdate()">🔄 Buscar actualizaciones</button>
                <button id="btn-update" onclick="doUpdate()" class="hidden">⬇️ Actualizar ahora</button>
            </div>
            <div id="update-log" class="update-log"></div>
        </div>

        <h3 class="mt-4">Backups disponibles</h3>
        <?php if (empty($backups)): ?>
            <p class="small">No hay backups.</p>
        <?php else: ?>
            <table>
                <thead><tr>
                    <th>Archivo</th>
                    <th>Tamaño</th>
                    <th>Fecha</th>
                    <th>Acción</th>
                </tr></thead>
                <tbody>
                <?php foreach ($backups as $b): ?>
                <tr>
                    <td><?php echo htmlspecialchars($b['file']); ?></td>
                    <td><?php echo htmlspecialchars($b['size']); ?></td>
                    <td><?php echo htmlspecialchars($b['date']); ?></td>
                    <td>
                        <div class="flex gap-1 flex-wrap">
                            <a class="btn secondary" href="ajax_update.php?action=download_backup&file=<?php echo urlencode($b['file']); ?>">⬇️ Descargar</a>
                            <button class="secondary" onclick="doRollback('<?php echo htmlspecialchars($b['file'], ENT_QUOTES); ?>')">↩️ Restaurar</button>
                            <button class="secondary danger" onclick="deleteBackup('<?php echo htmlspecialchars($b['file'], ENT_QUOTES); ?>')">🗑️ Eliminar</button>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <?php elseif ($tab === 'workers'): ?>
    <h3>🖥️ Workers conectados</h3>
    <?php if (empty($workers)): ?>
        <p class="small">No hay workers reportando todavía. Asegúrate de que el worker está ejecutándose y tiene conexión al hosting.</p>
    <?php else: ?>
    <table>
        <thead><tr>
            <th>Nombre</th>
            <th>Estado</th>
            <th>CPU</th>
            <th>RAM</th>
            <th>GPU</th>
            <th>Temp</th>
            <th>Disco</th>
            <th>Modelo</th>
            <th>Uptime</th>
            <th>Último heartbeat</th>
            <th>Logs</th>
        </tr></thead>
        <tbody>
        <?php foreach ($workers as $w):
            $isOnline = !empty($w['is_online']);
            $gpuInfo = $w['gpu_info'] ? json_decode($w['gpu_info'], true) : null;
            $gpuText = $gpuInfo ? ($gpuInfo['name'] ?? 'GPU') . ' ' . ($gpuInfo['load_percent'] ?? '?') . '%' : '—';
            $uptime = $w['uptime_seconds'] ? gmdate('H:i:s', $w['uptime_seconds']) : '—';
        ?>
        <tr>
            <td><strong><?php echo htmlspecialchars($w['worker_name']); ?></strong><br><span class="small"><?php echo htmlspecialchars($w['hostname'] ?? '—'); ?></span></td>
            <td><?php echo $isOnline ? '<span class="status-completed">● Online</span>' : '<span class="status-error">● Offline</span>'; ?></td>
            <td><?php echo $w['cpu_percent'] !== null ? round($w['cpu_percent'], 1) . '%' : '—'; ?></td>
            <td><?php echo $w['memory_percent'] !== null ? round($w['memory_percent'], 1) . '%' : '—'; ?><br><span class="small"><?php echo $w['memory_used_mb'] ? round($w['memory_used_mb']/1024, 1) . '/' . round($w['memory_total_mb']/1024, 1) . ' GB' : ''; ?></span></td>
            <td><?php echo htmlspecialchars($gpuText); ?></td>
            <td><?php echo $w['temperature_c'] !== null ? round($w['temperature_c'], 1) . '°C' : '—'; ?></td>
            <td><?php echo $w['disk_percent'] !== null ? round($w['disk_percent'], 1) . '%' : '—'; ?></td>
            <td id="model-cell-<?php echo (int)$w['api_key_id']; ?>"><code><?php echo htmlspecialchars(resolveModelLabel($w['model_loaded'] ?? '', $modelCatalog) ?: '—'); ?></code></td>
            <td><?php echo htmlspecialchars($uptime); ?></td>
            <td class="small"><?php echo htmlspecialchars($w['created_at']); ?></td>
            <td><button type="button" class="btn secondary small" onclick="toggleWorkerLogs(<?php echo (int)$w['api_key_id']; ?>)">📜</button></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>

    <?php foreach ($workers as $w): ?>
    <div id="logs-panel-<?php echo (int)$w['api_key_id']; ?>" class="hidden" style="margin-bottom:1rem;">
        <div style="background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:1rem;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.5rem;">
                <strong>Logs — <?php echo htmlspecialchars($w['worker_name']); ?></strong>
                <span class="small" style="color:var(--text-muted)">Actualiza con cada heartbeat (~30s)</span>
            </div>
            <pre id="logs-pre-<?php echo (int)$w['api_key_id']; ?>" style="max-height:300px;overflow:auto;background:#0d1117;color:#c9d1d9;padding:.75rem;border-radius:6px;font-size:12px;line-height:1.4;margin:0;"></pre>
        </div>
    </div>
    <?php endforeach; ?>
    <?php endif; ?>

    <?php if (!empty($virtualWorkers)): ?>
    <h3 class="mt-4">☁️ Virtual Workers (modelos cloud)</h3>
    <p class="small">Estos modelos se ejecutan vía API externa y pueden ser seleccionados como ejecutores en las herramientas.</p>
    <table>
        <thead><tr>
            <th>Nombre</th>
            <th>Estado</th>
            <th>Proveedor</th>
            <th>Modelo</th>
            <th>Context</th>
            <th>Acciones</th>
        </tr></thead>
        <tbody>
        <?php foreach ($virtualWorkers as $vw): ?>
        <tr>
            <td><strong>☁️ <?php echo htmlspecialchars($vw['provider_label']); ?> → <?php echo htmlspecialchars($vw['model_label']); ?></strong></td>
            <td><span class="status-completed">● Online</span></td>
            <td><?php echo htmlspecialchars($vw['provider_label']); ?></td>
            <td class="small mono"><?php echo htmlspecialchars($vw['model_id']); ?></td>
            <td><?php echo number_format($vw['context_window']); ?></td>
            <td>
                <button class="secondary small" onclick="testProvider(<?php echo (int)$vw['provider_id']; ?>)">🧪 Test</button>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>

    <h3 class="mt-4">📡 Enviar comando a worker</h3>
    <p class="small">Los comandos se ejecutan en el próximo ciclo de polling del worker.</p>
    <form method="POST" action="ajax_admin.php?action=send_worker_command" onsubmit="return sendWorkerCmd(this);" id="worker-cmd-form">
        <?php echo csrfInput(); ?>
        <label>Worker</label>
        <select name="api_key_id" required id="worker-select" onchange="populateModels()">
            <option value="">Selecciona un worker...</option>
            <?php foreach ($apiKeys as $k): ?>
            <option value="<?php echo $k['id']; ?>"><?php echo htmlspecialchars($k['name']); ?></option>
            <?php endforeach; ?>
        </select>
        <label>Comando</label>
        <select name="command" required id="cmd-select" onchange="toggleModelSelect()">
            <option value="change_model">Cambiar modelo</option>
            <option value="restart">Reiniciar worker</option>
        </select>
        <div id="model-select-wrap">
            <label>Modelo</label>
            <select id="model-select" onchange="updatePayload()">
                <option value="">— Selecciona un worker primero —</option>
            </select>
            <p id="model-hint" class="small"></p>
            <p class="small" style="color:var(--warning);">⚠️ Este comando edita el config.ini del worker y reinicia llama-server automáticamente.</p>
        </div>
        <input type="hidden" name="payload" id="cmd-payload" value='{"model":""}'>
        <button type="submit" class="mt-2">📤 Enviar comando</button>
    </form>
    <p id="cmd-msg" class="mt-1"></p>
    <div id="cmd-progress" class="mt-1 hidden">
        <div style="display:flex;align-items:center;gap:.5rem;">
            <div class="spinner" style="width:16px;height:16px;border-width:2px;"></div>
            <span id="cmd-status-text" class="small"></span>
        </div>
    </div>
    <script>
    const WORKERS_MODELS = <?php echo json_encode(array_reduce($workers, function($carry, $w) {
        $carry[$w['api_key_id']] = json_decode($w['available_models'] ?? '[]', true) ?: [];
        return $carry;
    }, []), JSON_UNESCAPED_UNICODE); ?>;
    const MODEL_CATALOG = <?php echo json_encode($modelCatalog, JSON_UNESCAPED_UNICODE); ?>;

    function toggleModelSelect() {
        const cmd = document.getElementById('cmd-select').value;
        const wrap = document.getElementById('model-select-wrap');
        wrap.style.display = cmd === 'change_model' ? 'block' : 'none';
    }
    function updatePayload() {
        const model = document.getElementById('model-select').value;
        document.getElementById('cmd-payload').value = JSON.stringify({model: model});
    }
    // Convierte patrón glob simple (* → .*) a regex
    function globToRegex(pattern) {
        const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
        return new RegExp('^' + escaped.replace(/\*/g, '.*') + '$', 'i');
    }
    function resolveModelLabel(filename) {
        for (const entry of MODEL_CATALOG) {
            if (globToRegex(entry.pattern).test(filename)) {
                return entry.label + (entry.tier ? ' (' + entry.tier + ')' : '');
            }
        }
        return filename;
    }
    function populateModels() {
        const workerId = document.getElementById('worker-select').value;
        const modelSelect = document.getElementById('model-select');
        const hint = document.getElementById('model-hint');
        modelSelect.innerHTML = '';
        if (!workerId) {
            modelSelect.innerHTML = '<option value="">— Selecciona un worker primero —</option>';
            hint.textContent = '';
            updatePayload();
            return;
        }
        const models = WORKERS_MODELS[workerId] || [];
        if (!models.length) {
            modelSelect.innerHTML = '<option value="">— Sin datos del worker —</option>';
            hint.textContent = 'El worker aún no ha reportado modelos disponibles. Espera al primer heartbeat.';
            updatePayload();
            return;
        }
        models.forEach(function(m) {
            const label = resolveModelLabel(m);
            const displayName = m.replace(/\.gguf$/i, '');
            const opt = document.createElement('option');
            opt.value = m;
            opt.textContent = displayName;
            opt.title = label; // tooltip con el nombre amigable
            modelSelect.appendChild(opt);
        });
        hint.textContent = models.length + ' modelo(s) disponible(s) en este worker.';
        updatePayload();
    }
    toggleModelSelect();
    populateModels();
    </script>

    <?php elseif ($tab === 'users'): ?>
    <h3>Usuarios registrados</h3>
    <?php if (empty($users)): ?>
        <p class="small">No hay usuarios registrados.</p>
    <?php else: ?>
    <table>
        <thead><tr>
            <th>ID</th>
            <th>Usuario</th>
            <th>Admin</th>
            <th>Registro</th>
        </tr></thead>
        <tbody>
        <?php foreach ($users as $u): ?>
        <tr>
            <td><?php echo $u['id']; ?></td>
            <td><?php echo htmlspecialchars($u['username']); ?></td>
            <td><?php echo $u['is_admin'] ? 'Sí' : 'No'; ?></td>
            <td><?php echo htmlspecialchars($u['created_at']); ?></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>

    <h3 class="mt-4">Crear usuario</h3>
    <form method="POST" action="ajax_admin.php?action=add_user" onsubmit="return addUser(this);">
        <?php echo csrfInput(); ?>
        <label>Usuario</label>
        <input type="text" name="username" required maxlength="64" pattern="[\w\-.@]+" title="Letras, números, guiones, puntos y @">
        <label>Contraseña</label>
        <input type="password" name="password" required minlength="8" maxlength="128">
        <label><input type="checkbox" name="is_admin" value="1"> Administrador</label>
        <button type="submit" class="mt-2">Crear usuario</button>
        <p id="user-msg" class="mt-1"></p>
    </form>

    <?php elseif ($tab === 'alerts'): ?>
    <h3>🔔 Suscripciones de alertas</h3>
    <p class="small">El worker ejecuta tareas <code>alert_scan</code> que buscan CVEs recientes y generan alertas según estas suscripciones.</p>

    <?php if (empty($alertSubs)): ?>
        <p class="small">No hay suscripciones configuradas.</p>
    <?php else: ?>
    <table>
        <thead><tr>
            <th>Tipo</th>
            <th>Valor</th>
            <th>Umbral</th>
            <th>Activa</th>
            <th>Creada</th>
        </tr></thead>
        <tbody>
        <?php foreach ($alertSubs as $s): ?>
        <tr>
            <td><?php echo htmlspecialchars($s['type']); ?></td>
            <td><code><?php echo htmlspecialchars($s['value']); ?></code></td>
            <td><?php echo htmlspecialchars($s['severity_threshold'] ?? 'LOW'); ?></td>
            <td><?php echo $s['active'] ? 'Sí' : 'No'; ?></td>
            <td class="small"><?php echo htmlspecialchars($s['created_at']); ?></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>

    <h3 class="mt-4">➕ Añadir suscripción</h3>
    <form method="POST" action="ajax_admin.php?action=add_alert_subscription" onsubmit="return addAlertSub(this);">
        <?php echo csrfInput(); ?>
        <label>Tipo</label>
        <select name="type" required>
            <option value="product">Producto / Software</option>
            <option value="vendor">Vendor / Fabricante</option>
            <option value="keyword">Palabra clave</option>
            <option value="severity">Severidad mínima</option>
        </select>
        <label>Valor</label>
        <input type="text" name="value" required maxlength="100" placeholder="Ej: apache, log4j, CRITICAL...">
        <label>Umbral de severidad (para filtro adicional)</label>
        <select name="severity_threshold">
            <option value="LOW">LOW</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="HIGH" selected>HIGH</option>
            <option value="CRITICAL">CRITICAL</option>
        </select>
        <button type="submit" class="mt-2">Añadir suscripción</button>
        <p id="alert-sub-msg" class="small mt-1"></p>
    </form>
    <script>
    async function addAlertSub(form) {
        const fd = new FormData(form);
        const msg = document.getElementById('alert-sub-msg');
        try {
            const resp = await fetch(form.action, {method: 'POST', body: fd});
            const data = await resp.json();
            if (data.success) {
                msg.className = 'alert alert-success mt-1';
                msg.textContent = 'Suscripción añadida.';
                form.reset();
                setTimeout(() => location.reload(), 800);
            } else {
                msg.className = 'alert alert-error mt-1';
                msg.textContent = data.error || 'Error';
            }
        } catch (err) {
            msg.className = 'alert alert-error mt-1';
            msg.textContent = 'Error de red: ' + err.message;
        }
        return false;
    }
    </script>

    <?php elseif ($tab === 'providers'): ?>
    <h3>🌐 Proveedores externos</h3>
    <p class="small">Gestiona API keys de proveedores cloud (OpenRouter, OpenAI, Nvidia NIM). Las keys se cifran en la base de datos.</p>

    <div id="providers-container">
        <p class="small">Cargando...</p>
    </div>

    <h4 class="mt-4">Añadir proveedor</h4>
    <form id="provider-form" onsubmit="return saveProvider(this);" class="flex gap-1 flex-wrap items-end">
        <?php echo csrfInput(); ?>
        <div>
            <label class="small">Nombre interno</label>
            <input type="text" name="name" placeholder="openrouter" required maxlength="64" pattern="[\w\-]+">
        </div>
        <div>
            <label class="small">Label</label>
            <input type="text" name="label" placeholder="OpenRouter" required maxlength="100">
        </div>
        <div style="flex:1;min-width:200px;">
            <label class="small">Base URL</label>
            <input type="url" name="base_url" placeholder="https://openrouter.ai/api/v1" required>
        </div>
        <div>
            <label class="small">API Key</label>
            <input type="password" name="api_key" placeholder="sk-..." required>
        </div>
        <div>
            <label class="small">Timeout (s)</label>
            <input type="number" name="timeout_seconds" value="60" min="10" max="300" style="width:70px;">
        </div>
        <div>
            <label class="small">Activo</label>
            <input type="checkbox" name="is_active" value="1" checked>
        </div>
        <button type="submit">➕ Añadir</button>
    </form>
    <p id="provider-msg" class="small mt-1"></p>

    <h4 class="mt-4">Añadir modelo</h4>
    <form id="model-form" onsubmit="return saveModel(this);" class="flex gap-1 flex-wrap items-end">
        <?php echo csrfInput(); ?>
        <div>
            <label class="small">Proveedor</label>
            <select name="provider_id" id="model-provider-select" required></select>
        </div>
        <div>
            <label class="small">Model ID</label>
            <input type="text" name="model_id" placeholder="anthropic/claude-3.5-sonnet" required maxlength="128">
        </div>
        <div>
            <label class="small">Label</label>
            <input type="text" name="label" placeholder="Claude 3.5 Sonnet" required maxlength="128">
        </div>
        <div>
            <label class="small">Context</label>
            <input type="number" name="context_window" value="8192" min="512" style="width:90px;">
        </div>
        <div>
            <label class="small">$ / 1k in</label>
            <input type="number" step="0.0001" name="cost_per_1k_input" placeholder="0.003" style="width:80px;">
        </div>
        <div>
            <label class="small">$ / 1k out</label>
            <input type="number" step="0.0001" name="cost_per_1k_output" placeholder="0.015" style="width:80px;">
        </div>
        <div>
            <label class="small">Activo</label>
            <input type="checkbox" name="is_active" value="1" checked>
        </div>
        <button type="submit">➕ Añadir</button>
    </form>
    <p id="model-msg" class="small mt-1"></p>

    <h4 class="mt-4">📥 Importar modelos desde JSON</h4>
    <p class="small">Selecciona un archivo .json o pega un array JSON para importar masivamente al proveedor seleccionado. Los que ya existen se saltan.</p>
    <form id="import-form" onsubmit="return importModels(this);" class="flex gap-1 flex-wrap items-end">
        <?php echo csrfInput(); ?>
        <div>
            <label class="small">Proveedor</label>
            <select name="provider_id" id="import-provider-select" required></select>
        </div>
        <div style="flex:1;min-width:300px;">
            <label class="small">Archivo JSON <span class="small" style="color:#888">(opcional — se carga en el campo de abajo)</span></label>
            <input type="file" id="import-file" accept=".json,application/json" onchange="loadJsonFile(this)" style="font-size:12px;">
            <textarea name="json" rows="6" placeholder='[&#10;  {"model_id":"nvidia/nemotron-3-super-120b-a12b:free","label":"Nemotron 3 Super 120B (Free)","context_window":262144},&#10;  {"model_id":"z-ai/glm-4.5-air:free","label":"GLM 4.5 Air (Free)","context_window":131072}&#10;]' required style="font-family:monospace;font-size:12px;width:100%;margin-top:4px;"></textarea>
        </div>
        <button type="submit">📥 Importar</button>
    </form>
    <p id="import-msg" class="small mt-1"></p>

    <h4 class="mt-4">📊 Uso del mes</h4>
    <div id="usage-stats-container">
        <p class="small">Cargando...</p>
    </div>

    <script>
    async function loadProvidersAdmin() {
        const container = document.getElementById('providers-container');
        try {
            const data = await apiFetch('api/v1/admin_providers.php?action=list');
            if (!data.success) {
                container.innerHTML = '<p class="alert alert-error small">Error al cargar proveedores: ' + escapeHtml(data.error || 'Desconocido') + '</p>';
                return;
            }
            renderProviders(data.providers || [], data.models || []);
            populateModelProviderSelect(data.providers || []);
        } catch (e) {
            console.error(e);
            container.innerHTML = '<p class="alert alert-error small">Error al cargar proveedores: ' + escapeHtml(e.message) + '</p>';
        }
    }

    function renderModelTags(tagsJson) {
        if (!tagsJson) return '';
        let tags;
        try { tags = JSON.parse(tagsJson); } catch(e) { return ''; }
        if (!Array.isArray(tags)) return '';
        const colors = {
            cybersecurity: 'background:#fff3e0;color:#f57c00;border:1px solid #f57c00;',
            reasoning: 'background:#e3f2fd;color:#1976d2;border:1px solid #1976d2;',
            recommended: 'background:#e8f5e9;color:#2e7d32;border:1px solid #2e7d32;',
            free: 'background:#f5f5f5;color:#888;border:1px solid #ccc;'
        };
        return tags.map(t => `<span class="badge" style="${colors[t]||colors.free}font-size:0.7rem;padding:0.1rem 0.35rem;margin:0 0.15rem 0 0;">${t}</span>`).join('');
    }

    function renderProviders(providers, models) {
        const container = document.getElementById('providers-container');
        if (!providers.length) {
            container.innerHTML = '<p class="small">No hay proveedores configurados.</p>';
            return;
        }
        let html = '<table><thead><tr><th>ID</th><th>Nombre</th><th>Label</th><th>URL</th><th>Key</th><th>Timeout</th><th>Activo</th><th>Modelos</th><th>Acciones</th></tr></thead><tbody>';
        providers.forEach(p => {
            const pmodels = models.filter(m => m.provider_id == p.id);
            const modelList = pmodels.map(m => `<span class="badge ${m.is_active?'':'badge-inactive'}">${m.label}</span>${renderModelTags(m.tags)}`).join(' ');
            const noModelsHint = pmodels.length ? '' : '<br><span class="small" style="color:var(--warning)">⚠️ Añade modelos abajo para usarlos en el chat</span>';
            html += `<tr>
                <td>${p.id}</td>
                <td>${escapeHtml(p.name)}</td>
                <td>${escapeHtml(p.label)}</td>
                <td class="small mono">${escapeHtml(p.base_url)}</td>
                <td class="small mono">${escapeHtml(p.api_key_hint || '—')}</td>
                <td>${p.timeout_seconds}s</td>
                <td>${p.is_active ? 'Sí' : 'No'}</td>
                <td>${modelList || '<span class="small text-muted">Sin modelos</span>'}${noModelsHint}</td>
                <td>
                    <div class="flex gap-1 flex-wrap">
                        <button class="secondary small" onclick="testProvider(${p.id})">🧪 Test</button>
                        <button class="secondary small danger" onclick="deleteProvider(${p.id})">🗑️</button>
                    </div>
                </td>
            </tr>`;
        });
        html += '</tbody></table>';
        container.innerHTML = html;
    }

    function populateModelProviderSelect(providers) {
        const sel = document.getElementById('model-provider-select');
        sel.innerHTML = '';
        providers.forEach(p => {
            const opt = document.createElement('option');
            opt.value = p.id;
            opt.textContent = p.label;
            sel.appendChild(opt);
        });
        // También poblar el select de importación
        const importSel = document.getElementById('import-provider-select');
        if (importSel) {
            importSel.innerHTML = '';
            providers.forEach(p => {
                const opt = document.createElement('option');
                opt.value = p.id;
                opt.textContent = p.label;
                importSel.appendChild(opt);
            });
        }
    }

    async function loadUsageStats() {
        const container = document.getElementById('usage-stats-container');
        try {
            const data = await apiFetch('api/v1/admin_providers.php?action=usage_stats');
            if (!data.success) {
                container.innerHTML = '<p class="alert alert-error small">Error al cargar estadísticas: ' + escapeHtml(data.error || 'Desconocido') + '</p>';
                return;
            }
            if (!data.stats || !data.stats.length) {
                container.innerHTML = '<p class="small">Sin uso este mes.</p>';
                return;
            }
            let html = '<table><thead><tr><th>Proveedor</th><th>Modelo</th><th>Input tokens</th><th>Output tokens</th><th>Coste ($)</th><th>Llamadas</th></tr></thead><tbody>';
            data.stats.forEach(s => {
                html += `<tr>
                    <td>${escapeHtml(s.provider)}</td>
                    <td>${escapeHtml(s.model || '—')}</td>
                    <td>${s.in_tokens || 0}</td>
                    <td>${s.out_tokens || 0}</td>
                    <td>$${(s.cost_total || 0).toFixed(4)}</td>
                    <td>${s.calls}</td>
                </tr>`;
            });
            html += '</tbody></table>';
            container.innerHTML = html;
        } catch (e) { console.error(e); }
    }

    async function saveProvider(form) {
        event.preventDefault();
        const fd = new FormData(form);
        const payload = {
            name: fd.get('name'),
            label: fd.get('label'),
            base_url: fd.get('base_url'),
            api_key: fd.get('api_key'),
            timeout_seconds: parseInt(fd.get('timeout_seconds')),
            is_active: fd.get('is_active') ? 1 : 0
        };
        const msg = document.getElementById('provider-msg');
        try {
            await apiFetch('api/v1/admin_providers.php?action=create_provider', {
                method: 'POST', body: JSON.stringify(payload)
            });
            msg.style.color = '#2e7d32';
            msg.textContent = 'Proveedor añadido.';
            form.reset();
            loadProvidersAdmin();
            loadUsageStats();
        } catch (err) {
            msg.style.color = '#c62828';
            msg.textContent = err.message;
        }
        return false;
    }

    async function saveModel(form) {
        event.preventDefault();
        const fd = new FormData(form);
        const payload = {
            provider_id: parseInt(fd.get('provider_id')),
            model_id: fd.get('model_id'),
            label: fd.get('label'),
            context_window: parseInt(fd.get('context_window')),
            cost_per_1k_input: fd.get('cost_per_1k_input') || null,
            cost_per_1k_output: fd.get('cost_per_1k_output') || null,
            is_active: fd.get('is_active') ? 1 : 0
        };
        const msg = document.getElementById('model-msg');
        try {
            await apiFetch('api/v1/admin_providers.php?action=create_model', {
                method: 'POST', body: JSON.stringify(payload)
            });
            msg.style.color = '#2e7d32';
            msg.textContent = 'Modelo añadido.';
            form.reset();
            loadProvidersAdmin();
        } catch (err) {
            msg.style.color = '#c62828';
            msg.textContent = err.message;
        }
        return false;
    }

    async function testProvider(id) {
        if (!confirm('¿Probar conexión con este proveedor?')) return;
        try {
            const data = await apiFetch('api/v1/admin_providers.php?action=test_connection', {
                method: 'POST', body: JSON.stringify({id: id})
            });
            alert('✅ Conexión OK. Modelos disponibles: ' + (data.models_available || '?'));
        } catch (err) { alert('❌ ' + err.message); }
    }

    function loadJsonFile(input) {
        const file = input.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = function(e) {
            const textarea = input.parentElement.querySelector('textarea[name=json]');
            if (textarea) textarea.value = e.target.result;
        };
        reader.onerror = function() {
            alert('No se pudo leer el archivo JSON');
        };
        reader.readAsText(file);
    }

    async function importModels(form) {
        event.preventDefault();
        const msg = document.getElementById('import-msg');
        const providerId = parseInt(document.getElementById('import-provider-select').value);
        if (!providerId) {
            msg.style.color = '#c62828';
            msg.textContent = 'Selecciona un proveedor.';
            return false;
        }
        let models;
        try {
            models = JSON.parse(form.querySelector('textarea[name=json]').value);
            if (!Array.isArray(models)) throw new Error('El JSON debe ser un array');
        } catch (e) {
            msg.style.color = '#c62828';
            msg.textContent = 'JSON inválido: ' + e.message;
            return false;
        }
        try {
            const data = await apiFetch('api/v1/admin_providers.php?action=import_models', {
                method: 'POST', body: JSON.stringify({provider_id: providerId, models: models})
            });
            msg.style.color = '#2e7d32';
            let txt = 'Importados: ' + data.imported + ', Saltados (ya existían): ' + data.skipped;
            if (data.errors.length) txt += ', Errores: ' + data.errors.join('; ');
            msg.textContent = txt;
            loadProvidersAdmin();
        } catch (err) {
            msg.style.color = '#c62828';
            msg.textContent = err.message;
        }
        return false;
    }

    async function deleteProvider(id) {
        if (!confirm('¿Eliminar proveedor y todos sus modelos? No se puede deshacer.')) return;
        try {
            await apiFetch('api/v1/admin_providers.php?action=delete_provider', {
                method: 'POST', body: JSON.stringify({id: id})
            });
            loadProvidersAdmin();
        } catch (err) { alert('❌ ' + err.message); }
    }

    function escapeHtml(text) {
        if (!text) return '';
        const d = document.createElement('div');
        d.textContent = text;
        return d.innerHTML;
    }

    document.addEventListener('DOMContentLoaded', () => {
        loadProvidersAdmin();
        loadUsageStats();
    });
    </script>

    <?php elseif ($tab === 'templates'): ?>
    <h3>📝 Plantillas de informe</h3>
    <p class="small">Las plantillas definen la estructura y formato del informe CVE generado por el LLM. Se usan como <strong>base</strong> del system prompt; el sistema añade automáticamente reglas de seguridad.</p>

    <div id="templates-container">
        <?php if (empty($reportTemplates)): ?>
            <p class="small">No hay plantillas configuradas.</p>
        <?php else: ?>
        <table>
            <thead><tr>
                <th>ID</th>
                <th>Nombre</th>
                <th>Tipo</th>
                <th>Por defecto</th>
                <th>Actualizada</th>
                <th>Acciones</th>
            </tr></thead>
            <tbody>
            <?php foreach ($reportTemplates as $tpl): ?>
            <tr>
                <td><?php echo $tpl['id']; ?></td>
                <td><?php echo htmlspecialchars($tpl['name']); ?></td>
                <td><?php echo htmlspecialchars($tpl['task_type']); ?></td>
                <td><?php echo $tpl['is_default'] ? '⭐ Sí' : '—'; ?></td>
                <td class="small"><?php echo htmlspecialchars($tpl['updated_at'] ?? $tpl['created_at']); ?></td>
                <td>
                    <div class="flex gap-1 flex-wrap">
                        <button class="secondary small" onclick="editTemplate(<?php echo (int)$tpl['id']; ?>, <?php echo json_encode($tpl['name'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE); ?>, <?php echo json_encode($tpl['content'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE); ?>, <?php echo (int)$tpl['is_default']; ?>, <?php echo json_encode($tpl['task_type'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE); ?>)">✏️ Editar</button>
                        <button class="secondary small" onclick="previewTemplate(<?php echo json_encode($tpl['content'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE); ?>, <?php echo json_encode($tpl['name'], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE); ?>)">👁️ Ver prompt</button>
                        <button class="secondary small danger" onclick="deleteTemplate(<?php echo (int)$tpl['id']; ?>)">🗑️</button>
                    </div>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>

    <h4 class="mt-4"><?php echo isset($_GET['edit_template']) ? '✏️ Editar plantilla' : '➕ Crear plantilla'; ?></h4>
    <form id="template-form" onsubmit="return saveTemplate(this);" class="flex gap-1 flex-wrap items-end">
        <?php echo csrfInput(); ?>
        <input type="hidden" name="id" id="tpl-id" value="">
        <div style="flex:1;min-width:250px;">
            <label class="small">Nombre</label>
            <input type="text" name="name" id="tpl-name" placeholder="Ej: Informe ejecutivo" required maxlength="100" style="width:100%;">
        </div>
        <div>
            <label class="small">Tipo de tarea</label>
            <select name="task_type" id="tpl-task-type">
                <option value="cve_search">CVE Search</option>
            </select>
        </div>
        <div>
            <label class="small">Por defecto</label>
            <input type="checkbox" name="is_default" id="tpl-is-default" value="1">
        </div>
        <button type="submit">💾 Guardar</button>
        <button type="button" class="secondary" onclick="resetTemplateForm()">↩️ Nuevo</button>
    </form>
    <label class="small mt-2" style="display:block;">Contenido (Markdown / texto plano)</label>
    <textarea name="content" id="tpl-content" rows="12" placeholder="Escribe aquí la plantilla. Usa markdown para estructurar el informe." required style="width:100%;font-family:var(--font-mono);font-size:.9rem;margin-top:.25rem;"></textarea>
    <p class="small mt-1" style="color:var(--text-muted);">💡 Al guardar, el sistema añadirá automáticamente las reglas de seguridad (no inventar datos, concisión, etc.). Usa el botón 👁️ para ver el prompt completo.</p>
    <p id="tpl-msg" class="small mt-1"></p>

    <!-- Modal preview -->
    <div id="tpl-preview-modal" class="hidden" style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.6);z-index:1000;display:flex;align-items:center;justify-content:center;">
        <div style="background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:1.5rem;width:90%;max-width:800px;max-height:80vh;overflow:auto;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
                <h3 id="tpl-preview-title" style="margin:0;">Prompt completo</h3>
                <button type="button" class="secondary small" onclick="closeTplPreview()">✕ Cerrar</button>
            </div>
            <pre id="tpl-preview-body" style="background:var(--surface);padding:1rem;border-radius:6px;font-size:.85rem;line-height:1.5;white-space:pre-wrap;word-break:break-word;"></pre>
        </div>
    </div>

    <script>
    const TPL_SYSTEM_RULES = "\n\n---\nREGLAS DEL SISTEMA (no omitir):\n" +
        "1. No inventes versiones de parche, fechas ni detalles de vendor.\n" +
        "2. No repitas datos que ya aparecen en los metadatos (CVSS, EPSS, CISA KEV).\n" +
        "3. Usa [INFERIDO] solo para consecuencias lógicas obvias.\n" +
        "4. Sé conciso: máximo 300 palabras en total.\n" +
        "5. Responde en español.\n" +
        "6. Los datos estructurados de la vulnerabilidad se proporcionan en el mensaje del usuario.";

    function previewTemplate(content, name) {
        document.getElementById('tpl-preview-title').textContent = 'Prompt completo — ' + name;
        document.getElementById('tpl-preview-body').textContent = content + TPL_SYSTEM_RULES;
        document.getElementById('tpl-preview-modal').style.display = 'flex';
    }
    function closeTplPreview() {
        document.getElementById('tpl-preview-modal').style.display = 'none';
    }
    document.getElementById('tpl-preview-modal').addEventListener('click', function(e) {
        if (e.target === this) closeTplPreview();
    });

    function editTemplate(id, name, content, isDefault, taskType) {
        document.getElementById('tpl-id').value = id;
        document.getElementById('tpl-name').value = name;
        document.getElementById('tpl-content').value = content;
        document.getElementById('tpl-is-default').checked = isDefault ? true : false;
        document.getElementById('tpl-task-type').value = taskType;
        document.getElementById('tpl-msg').textContent = '';
        document.getElementById('tpl-content').focus();
    }
    function resetTemplateForm() {
        document.getElementById('tpl-id').value = '';
        document.getElementById('tpl-name').value = '';
        document.getElementById('tpl-content').value = '';
        document.getElementById('tpl-is-default').checked = false;
        document.getElementById('tpl-task-type').value = 'cve_search';
        document.getElementById('tpl-msg').textContent = '';
    }
    async function saveTemplate(form) {
        event.preventDefault();
        const msg = document.getElementById('tpl-msg');
        const fd = new FormData(form);
        fd.append('content', document.getElementById('tpl-content').value);
        try {
            const data = await apiFetch('ajax_admin.php?action=save_report_template', {
                method: 'POST',
                body: JSON.stringify(Object.fromEntries(fd))
            });
            msg.style.color = '#2e7d32';
            msg.textContent = 'Plantilla guardada.';
            setTimeout(() => location.reload(), 600);
        } catch (err) {
            msg.style.color = '#c62828';
            msg.textContent = err.message;
        }
        return false;
    }
    async function deleteTemplate(id) {
        if (!confirm('¿Eliminar esta plantilla? No se puede deshacer.')) return;
        try {
            await apiFetch('ajax_admin.php?action=delete_report_template', {
                method: 'POST',
                body: JSON.stringify({id: id})
            });
            location.reload();
        } catch (err) {
            alert('❌ ' + err.message);
        }
    }
    </script>

    <?php else: ?>
    <h3>Configuración del sistema</h3>

    <h3>🔑 API Keys — Workers conectados</h3>
    <p class="small">Cada worker o sistema externo debe usar su propia API key. Puedes revocar una key sin afectar a los demás.</p>

    <?php if (empty($apiKeys)): ?>
        <p class="small">No hay API keys.</p>
    <?php else: ?>
    <table>
        <thead><tr>
            <th>Nombre</th>
            <th>Key</th>
            <th>Estado</th>
            <th>Último uso</th>
            <th>Acciones</th>
        </tr></thead>
        <tbody>
        <?php foreach ($apiKeys as $k): ?>
        <tr>
            <td><?php echo htmlspecialchars($k['name']); ?></td>
            <td class="mono">
                <span id="key-<?php echo $k['id']; ?>" class="blur-reveal" title="Clic para revelar" data-full="<?php echo htmlspecialchars($k['api_key'], ENT_QUOTES); ?>" onclick="revealKey(this)"><?php echo htmlspecialchars(substr($k['api_key'], 0, 8) . '...' . substr($k['api_key'], -8)); ?></span>
                <button class="secondary" style="font-size:0.8rem; padding:0.3rem 0.5rem;" onclick="copyKey('key-<?php echo $k['id']; ?>')">📋</button>
            </td>
            <td><?php echo $k['is_active'] ? '<span class="status-completed">Activa</span>' : '<span class="status-error">Revocada</span>'; ?></td>
            <td class="small"><?php echo $k['last_used'] ? htmlspecialchars($k['last_used']) : 'Nunca'; ?></td>
            <td>
                <div class="flex gap-1 flex-wrap">
                <?php if ($k['is_active']): ?>
                    <button class="secondary" onclick="revokeKey(<?php echo $k['id']; ?>)">🚫 Revocar</button>
                <?php else: ?>
                    <button class="secondary" onclick="activateKey(<?php echo $k['id']; ?>)">✅ Activar</button>
                <?php endif; ?>
                    <button class="secondary" onclick="regenKey(<?php echo $k['id']; ?>)">🔄 Regenerar</button>
                    <button class="secondary" onclick="deleteKey(<?php echo $k['id']; ?>)">🗑️ Eliminar</button>
                </div>
            </td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>

    <h4>Añadir nuevo worker</h4>
    <form method="POST" action="ajax_admin.php?action=add_api_key" onsubmit="return addKey(this);" class="flex gap-1 items-end">
        <?php echo csrfInput(); ?>
        <div class="w-full">
            <label class="small">Nombre del worker</label>
            <input type="text" name="name" placeholder="Ej: Orin Nano 2, VPS Frankfurt..." required maxlength="100">
        </div>
        <button type="submit">➕ Añadir key</button>
    </form>
    <div id="key-result" class="mt-2" style="display:none;">
        <div class="alert alert-success">
            <p>Nueva API key generada:</p>
            <code id="key-new-value" style="font-size:1.1rem; padding:.5rem .75rem; display:inline-block; margin:.5rem 0;"></code>
            <button onclick="copyToClipboard('key-new-value')">📋 Copiar</button>
            <p class="small">Guárdala ahora — no se volverá a mostrar.</p>
        </div>
    </div>
    <p id="key-msg" class="small mt-1"></p>
    
    <h3 class="mt-4">🖥️ Ejecutor por defecto para tareas</h3>
    <p class="small">Las tareas CVE (y futuras tareas) se ejecutarán en el worker o modelo seleccionado por defecto.</p>
    <form method="POST" action="ajax_admin.php?action=save_default_executor" onsubmit="return saveExecutor(this);">
        <?php echo csrfInput(); ?>
        <select name="executor" style="min-width: 280px;">
            <?php foreach ($executorOptions as $opt): ?>
            <option value="<?php echo htmlspecialchars($opt['value']); ?>" <?php echo $defaultExecutor === $opt['value'] ? 'selected' : ''; ?>>
                <?php echo htmlspecialchars($opt['label']); ?>
            </option>
            <?php endforeach; ?>
        </select>
        <button type="submit" class="mt-2">💾 Guardar</button>
        <p id="exec-msg" class="small mt-1"></p>
    </form>

    <h3 class="mt-4">Registro de usuarios</h3>
    <p>Estado: <strong><?php echo $regEnabled ? 'Abierto' : 'Cerrado'; ?></strong></p>
    <form method="POST" action="ajax_admin.php?action=toggle_registration" onsubmit="return toggleReg(this);">
        <?php echo csrfInput(); ?>
        <button type="submit"><?php echo $regEnabled ? '🔒 Cerrar registro' : '🔓 Abrir registro'; ?></button>
        <p id="reg-msg" class="mt-1"></p>
    </form>
    <p class="small">Si el registro está cerrado, solo los administradores pueden crear cuentas.</p>
    <?php endif; ?>
</div>

<script>
let remoteInfo = null;
const csrfToken = <?php echo json_encode(csrfToken()); ?>;

async function apiFetch(url, options = {}) {
    const csrf = document.querySelector('input[name="csrf_token"]')?.value || csrfToken;
    const resp = await fetch(url, {
        credentials: 'same-origin',
        ...options,
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'X-CSRF-Token': csrf,
            ...(options.headers || {})
        }
    });
    const ct = resp.headers.get('content-type') || '';
    if (!ct.includes('application/json')) {
        const text = await resp.text();
        throw new Error(`Respuesta no-JSON (${resp.status}): ${text.slice(0, 200)}`);
    }
    const data = await resp.json();
    if (!resp.ok) {
        throw new Error(data.error || `HTTP ${resp.status}`);
    }
    return data;
}

function compareSemver(a, b) {
    const parse = s => s.replace(/^v/, '').split('.').map(Number);
    const av = parse(a);
    const bv = parse(b);
    for (let i = 0; i < Math.max(av.length, bv.length); i++) {
        const avi = av[i] || 0;
        const bvi = bv[i] || 0;
        if (avi > bvi) return 1;
        if (avi < bvi) return -1;
    }
    return 0;
}

function log(msg, type = 'info') {
    const el = document.getElementById('update-log');
    el.classList.add('visible');
    const div = document.createElement('div');
    div.style.margin = '0.25rem 0';
    if (type === 'error') div.style.color = '#c62828';
    if (type === 'success') div.style.color = '#2e7d32';
    div.textContent = msg;
    el.appendChild(div);
}

async function checkUpdate() {
    document.getElementById('btn-check').disabled = true;
    try {
        const resp = await fetch('ajax_update.php?action=check');
        const text = await resp.text();
        let data;
        try {
            data = JSON.parse(text);
        } catch (e) {
            document.getElementById('remote-version').textContent = 'Error';
            document.getElementById('remote-message').textContent = 'Respuesta inválida del servidor. ¿Sesión caducada? Recarga la página.';
            return;
        }

        if (data.error) {
            document.getElementById('remote-version').textContent = 'Error';
            document.getElementById('remote-message').textContent = data.error;
            return;
        }

        remoteInfo = data;
        document.getElementById('remote-version').textContent = data.tag + ' — ' + data.name;
        document.getElementById('remote-message').textContent = 'Publicada: ' + data.published;
        if (data.body) {
            document.getElementById('remote-message').textContent += ' | ' + data.body.substring(0, 200) + (data.body.length > 200 ? '...' : '');
        }

        const current = document.getElementById('current-version').textContent;
        const cmp = compareSemver(current, data.tag);
        if (cmp < 0) {
            // Remota es mayor → mostrar botón
            document.getElementById('btn-update').classList.remove('hidden');
        } else if (cmp > 0) {
            // Instalada es más reciente que la remota → inconsistencia o release antigua
            document.getElementById('remote-message').textContent += ' — ⚠️ La versión instalada (' + current + ') es más reciente que la release remota (' + data.tag + '). No se permite downgrade.';
        } else {
            document.getElementById('remote-message').textContent += ' — ✅ Estás en la última versión.';
        }
    } catch (err) {
        document.getElementById('remote-version').textContent = 'Error';
        document.getElementById('remote-message').textContent = 'No se pudo conectar con el servidor: ' + err.message;
    } finally {
        document.getElementById('btn-check').disabled = false;
    }
}

async function doUpdate() {
    if (!confirm('Se creará un backup antes de actualizar. ¿Continuar?')) return;
    document.getElementById('btn-update').disabled = true;
    document.getElementById('update-log').innerHTML = '';
    document.getElementById('update-log').classList.remove('visible');

    async function ajax(action, params = '') {
        const resp = await fetch('ajax_update.php?action=' + action + (params ? '&' + params : ''));
        const text = await resp.text();
        try { return JSON.parse(text); }
        catch (e) { throw new Error('Respuesta inválida del servidor (¿sesión caducada?). Recarga la página.'); }
    }

    try {
        log('1/4 Creando backup...');
        const d1 = await ajax('backup');
        if (d1.error) { log('❌ Backup fallido: ' + d1.error, 'error'); document.getElementById('btn-update').disabled = false; return; }
        log('✅ Backup creado: ' + d1.file, 'success');

        log('2/4 Descargando actualización...');
        const d2 = await ajax('download');
        if (d2.error) { log('❌ Descarga fallida: ' + d2.error, 'error'); await doRollbackAjax(d1.file); return; }
        log('✅ Descargado', 'success');

        log('3/4 Extrayendo...');
        const d3 = await ajax('extract');
        if (d3.error) { log('❌ Extracción fallida: ' + d3.error, 'error'); await doRollbackAjax(d1.file); return; }
        log('✅ Extraído', 'success');

        log('4/4 Aplicando actualización...');
        const d4 = await ajax('apply', 'backup=' + encodeURIComponent(d1.file));
        if (d4.error) {
            log('❌ Aplicación fallida: ' + d4.error, 'error');
            log('Iniciando rollback automático...');
            await doRollbackAjax(d1.file);
            return;
        }
        log('✅ Actualización completada. Nueva versión: ' + d4.version, 'success');
        log('🔄 Recargando página en 3 segundos...');
        setTimeout(() => location.reload(), 3000);
    } catch (err) {
        log('❌ Error: ' + err.message, 'error');
        document.getElementById('btn-update').disabled = false;
    }
}

async function doRollbackAjax(file) {
    log('↩️ Rollback a ' + file + '...');
    try {
        const resp = await fetch('ajax_update.php?action=rollback&file=' + encodeURIComponent(file));
        const text = await resp.text();
        let d;
        try { d = JSON.parse(text); } catch (e) { throw new Error('Respuesta inválida del servidor'); }
        if (d.error) { log('❌ Rollback fallido: ' + d.error, 'error'); }
        else { log('✅ Rollback completado. Recargando...', 'success'); setTimeout(() => location.reload(), 2000); }
    } catch (err) {
        log('❌ Rollback fallido: ' + err.message, 'error');
    }
}

async function doRollback(file) {
    if (!confirm('¿Restaurar backup ' + file + '?')) return;
    document.getElementById('update-log').innerHTML = '';
    log('Restaurando ' + file + '...');
    try {
        const resp = await fetch('ajax_update.php?action=rollback&file=' + encodeURIComponent(file));
        const text = await resp.text();
        let d;
        try { d = JSON.parse(text); } catch (e) { throw new Error('Respuesta inválida del servidor'); }
        if (d.error) { log('❌ ' + d.error, 'error'); }
        else { log('✅ Restaurado. Recargando...', 'success'); setTimeout(() => location.reload(), 2000); }
    } catch (err) {
        log('❌ Error: ' + err.message, 'error');
    }
}

async function savePat(form) {
    event.preventDefault();
    const fd = new FormData(form);
    const resp = await fetch(form.action, { method: 'POST', body: fd });
    const data = await resp.json();
    const msg = document.getElementById('pat-msg');
    if (data.success) {
        msg.style.color = '#2e7d32';
        msg.textContent = 'PAT guardado.';
    } else {
        msg.style.color = '#c62828';
        msg.textContent = data.error || 'Error';
    }
}

async function addKey(form) {
    event.preventDefault();
    const fd = new FormData(form);
    const resp = await fetch(form.action, { method: 'POST', body: fd });
    const data = await resp.json();
    const msg = document.getElementById('key-msg');
    if (data.success) {
        document.getElementById('key-new-value').textContent = data.api_key;
        document.getElementById('key-result').style.display = 'block';
        msg.textContent = '';
    } else {
        document.getElementById('key-result').style.display = 'none';
        msg.className = 'alert alert-error mt-1';
        msg.textContent = data.error || 'Error';
    }
}

function showToast(msg) {
    const t = document.createElement('div');
    t.textContent = msg;
    t.style.cssText = 'position:fixed;bottom:2rem;right:2rem;background:var(--success);color:#fff;padding:.75rem 1.25rem;border-radius:var(--radius-sm);font-weight:600;z-index:9999;box-shadow:var(--shadow-lg);transition:opacity .3s;';
    document.body.appendChild(t);
    setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }, 2000);
}

function copyToClipboard(elementId) {
    const text = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(text).then(() => showToast('✅ Copiado')).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast('✅ Copiado');
    });
}

function revealKey(el) {
    el.textContent = el.dataset.full;
    el.style.filter = 'none';
    el.style.cursor = 'default';
    el.onclick = null;
}

function copyKey(elementId) {
    const el = document.getElementById(elementId);
    const full = el.dataset.full || el.textContent;
    navigator.clipboard.writeText(full).then(() => showToast('✅ Copiado')).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = full;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast('✅ Copiado');
    });
}

async function revokeKey(id) {
    if (!confirm('¿Revocar esta API key? El worker dejará de funcionar inmediatamente.')) return;
    const resp = await fetch('ajax_admin.php?action=revoke_api_key&id=' + id + '&csrf_token=' + encodeURIComponent(csrfToken), { method: 'POST' });
    const data = await resp.json();
    if (data.success) location.reload();
    else alert(data.error || 'Error');
}

async function activateKey(id) {
    const resp = await fetch('ajax_admin.php?action=activate_api_key&id=' + id + '&csrf_token=' + encodeURIComponent(csrfToken), { method: 'POST' });
    const data = await resp.json();
    if (data.success) location.reload();
    else alert(data.error || 'Error');
}

async function regenKey(id) {
    if (!confirm('¿Regenerar esta API key? El worker dejará de funcionar hasta que actualices su config.ini.')) return;
    const resp = await fetch('ajax_admin.php?action=regenerate_api_key&id=' + id + '&csrf_token=' + encodeURIComponent(csrfToken), { method: 'POST' });
    const data = await resp.json();
    if (data.success) {
        alert('Nueva key: ' + data.api_key + '\nActualiza el worker.');
        location.reload();
    } else {
        alert(data.error || 'Error');
    }
}

async function deleteKey(id) {
    if (!confirm('¿Eliminar permanentemente esta API key? No se puede deshacer.')) return;
    const resp = await fetch('ajax_admin.php?action=delete_api_key&id=' + id + '&csrf_token=' + encodeURIComponent(csrfToken), { method: 'POST' });
    const data = await resp.json();
    if (data.success) location.reload();
    else alert(data.error || 'Error');
}

async function saveExecutor(form) {
    event.preventDefault();
    const fd = new FormData(form);
    const resp = await fetch(form.action, { method: 'POST', body: fd });
    const data = await resp.json();
    const msg = document.getElementById('exec-msg');
    if (data.success) {
        msg.style.color = '#2e7d32';
        msg.textContent = 'Ejecutor por defecto guardado.';
    } else {
        msg.style.color = '#c62828';
        msg.textContent = data.error || 'Error';
    }
}

async function toggleReg(form) {
    event.preventDefault();
    const fd = new FormData(form);
    const resp = await fetch(form.action, { method: 'POST', body: fd });
    const data = await resp.json();
    const msg = document.getElementById('reg-msg');
    if (data.success) {
        msg.style.color = '#2e7d32';
        msg.textContent = data.enabled ? 'Registro abierto.' : 'Registro cerrado.';
        setTimeout(() => location.reload(), 1000);
    } else {
        msg.style.color = '#c62828';
        msg.textContent = data.error || 'Error';
    }
}

async function addUser(form) {
    event.preventDefault();
    const fd = new FormData(form);
    const resp = await fetch(form.action, { method: 'POST', body: fd });
    const data = await resp.json();
    const msg = document.getElementById('user-msg');
    if (data.success) {
        msg.style.color = '#2e7d32';
        msg.textContent = 'Usuario creado.';
        form.reset();
        setTimeout(() => location.reload(), 1000);
    } else {
        msg.style.color = '#c62828';
        msg.textContent = data.error || 'Error al crear usuario';
    }
}

async function sendWorkerCmd(form) {
    event.preventDefault();
    const fd = new FormData(form);
    const resp = await fetch(form.action, { method: 'POST', body: fd });
    const data = await resp.json();
    const msg = document.getElementById('cmd-msg');
    const progress = document.getElementById('cmd-progress');
    const statusText = document.getElementById('cmd-status-text');
    if (data.success) {
        msg.className = 'alert alert-success mt-1';
        msg.textContent = 'Comando enviado. El worker lo ejecutará en su próximo ciclo.';
        if (data.command_id && fd.get('command') === 'change_model') {
            progress.classList.remove('hidden');
            let modelName = '';
            try {
                const p = JSON.parse(fd.get('payload') || '{}');
                modelName = p.model || '';
            } catch(e) {}
            pollCommandStatus(data.command_id, fd.get('api_key_id'), modelName);
        }
    } else {
        msg.className = 'alert alert-error mt-1';
        msg.textContent = data.error || 'Error';
        progress.classList.add('hidden');
    }
}

const _LOG_POLLERS = {};

function toggleWorkerLogs(apiKeyId) {
    const panel = document.getElementById('logs-panel-' + apiKeyId);
    if (!panel) return;
    if (panel.classList.contains('hidden')) {
        panel.classList.remove('hidden');
        pollWorkerLogs(apiKeyId);
    } else {
        panel.classList.add('hidden');
        if (_LOG_POLLERS[apiKeyId]) {
            clearInterval(_LOG_POLLERS[apiKeyId]);
            delete _LOG_POLLERS[apiKeyId];
        }
    }
}

function pollWorkerLogs(apiKeyId) {
    if (_LOG_POLLERS[apiKeyId]) clearInterval(_LOG_POLLERS[apiKeyId]);
    const pre = document.getElementById('logs-pre-' + apiKeyId);
    if (!pre) return;
    const csrf = document.querySelector('input[name="csrf_token"]')?.value || '';
    const fetchLogs = async () => {
        try {
            const resp = await fetch('ajax_admin.php?action=worker_logs&api_key_id=' + apiKeyId + '&csrf_token=' + encodeURIComponent(csrf));
            const data = await resp.json();
            if (data.success && data.recent_logs !== undefined) {
                pre.textContent = data.recent_logs || '(sin logs recientes)';
            }
        } catch (e) {
            // ignorar errores de red en el polling
        }
    };
    fetchLogs();
    _LOG_POLLERS[apiKeyId] = setInterval(fetchLogs, 5000);
}

async function pollCommandStatus(cmdId, apiKeyId, modelName) {
    const progress = document.getElementById('cmd-progress');
    const statusText = document.getElementById('cmd-status-text');
    const msg = document.getElementById('cmd-msg');
    const csrfToken = document.querySelector('input[name="csrf_token"]')?.value || '';
    const maxAttempts = 180; // ~6 min
    for (let i = 0; i < maxAttempts; i++) {
        await new Promise(r => setTimeout(r, 2000));
        try {
            const resp = await fetch('ajax_admin.php?action=command_status&id=' + cmdId + '&csrf_token=' + encodeURIComponent(csrfToken));
            const data = await resp.json();
            if (!data.success) continue;
            const status = data.status;
            if (statusText) statusText.textContent = data.message || status;

            if (status === 'ready' || status === 'error') {
                if (progress) progress.classList.add('hidden');
                if (msg) {
                    msg.className = status === 'ready' ? 'alert alert-success mt-1' : 'alert alert-error mt-1';
                    msg.textContent = data.message || (status === 'ready' ? 'Modelo cargado correctamente' : 'Error al cargar el modelo');
                }
                if (status === 'ready' && modelName) {
                    const modelCell = document.getElementById('model-cell-' + apiKeyId);
                    if (modelCell) {
                        modelCell.innerHTML = '<code>' + modelName + '</code>';
                    }
                }
                return;
            }
        } catch (e) {
            // ignorar errores de red en el polling
        }
    }
    if (progress) progress.classList.add('hidden');
    if (msg) {
        msg.className = 'alert alert-warning mt-1';
        msg.textContent = 'Timeout esperando confirmación del worker. Revisa el estado manualmente.';
    }
}

async function deleteBackup(file) {
    if (!confirm('¿Eliminar permanentemente ' + file + '? No se puede deshacer.')) return;
    try {
        const resp = await fetch('ajax_update.php?action=delete_backup&file=' + encodeURIComponent(file));
        const text = await resp.text();
        let d;
        try { d = JSON.parse(text); } catch (e) { throw new Error('Respuesta inválida del servidor'); }
        if (d.error) { alert('❌ ' + d.error); }
        else { location.reload(); }
    } catch (err) {
        alert('❌ Error: ' + err.message);
    }
}
</script>
<?php require __DIR__ . '/templates/footer.php'; ?>
