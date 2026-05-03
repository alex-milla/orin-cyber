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

// ── Procesar formulario (CSV o manual) ──────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $incidentId = sanitizeString($_POST['incident_id'] ?? '');
    $title = sanitizeString($_POST['incident_title'] ?? '');
    $severity = sanitizeString($_POST['incident_severity'] ?? 'Medium');
    $source = sanitizeString($_POST['incident_source'] ?? 'manual');
    $splitByRow = isset($_POST['split_by_row']) && $_POST['split_by_row'] === '1';

    $hasFile = isset($_FILES['incident_csv']) && $_FILES['incident_csv']['error'] === UPLOAD_ERR_OK;

    // Generar titulo automatico si esta vacio
    if (empty($title)) {
        $title = 'Incidencia Sentinel ' . date('Y-m-d H:i:s');
    }

    // Si no hay ID manual y no se va a dividir por fila, generar uno automatico
    if (empty($incidentId) && !($hasFile && $splitByRow)) {
        $incidentId = 'MANUAL-' . date('YmdHis') . '-' . random_int(1000, 9999);
    }
        try {
            if ($hasFile) {
                $file = $_FILES['incident_csv'];
                $csvData = file_get_contents($file['tmp_name']);
                if ($csvData === false || strlen($csvData) === 0) {
                    $error = 'El archivo está vacío o no se pudo leer.';
                } elseif ($splitByRow) {
                    // ── Modo: un incidente por cada fila del CSV ─────────
                    $lines = explode("\n", $csvData);
                    if (count($lines) < 2) {
                        $error = 'CSV vacío o sin filas de datos.';
                    } else {
                        $headers = str_getcsv($lines[0]);
                        $createdCount = 0;
                        $firstTaskId = null;
                        for ($i = 1; $i < count($lines); $i++) {
                            $line = trim($lines[$i]);
                            if (empty($line)) continue;
                            $row = str_getcsv($line);
                            if (empty(array_filter($row))) continue;

                            // Reconstruir CSV de una sola fila
                            $handle = fopen('php://memory', 'r+');
                            fputcsv($handle, $headers);
                            fputcsv($handle, $row);
                            rewind($handle);
                            $rowCsv = stream_get_contents($handle);
                            fclose($handle);

                            // Generar ID automático basado en UserHash (primera columna) + índice
                            $userHash = trim($row[0] ?? '');
                            $hashPrefix = substr(preg_replace('/[^a-zA-Z0-9]/', '', $userHash), 0, 8);
                            $autoId = 'SENT-' . ($hashPrefix ?: 'row') . '-' . date('YmdHis') . '-' . $createdCount;

                            // Insertar incidente individual
                            $rowTitle = $title . ($createdCount > 0 ? ' #' . ($createdCount + 1) : '');
                            Database::insert('incidents', [
                                'incident_id' => $autoId,
                                'title' => $rowTitle,
                                'severity' => $severity,
                                'source' => $source,
                                'raw_data' => $rowCsv,
                                'status' => 'open',
                                'created_time' => date('Y-m-d H:i:s'),
                            ]);

                            _extractAndStoreEntities($autoId, $rowCsv);

                            $taskInput = json_encode([
                                'incident_id' => $autoId,
                                'title' => $title,
                                'severity' => $severity,
                                'csv_data' => $rowCsv,
                            ]);
                            $taskId = Database::insert('tasks', [
                                'task_type' => 'incident_analysis',
                                'input_data' => $taskInput,
                                'status' => 'pending',
                            ]);
                            Database::update('incidents', ['blue_team_task_id' => $taskId], 'incident_id = ?', [$autoId]);

                            if ($firstTaskId === null) {
                                $firstTaskId = $taskId;
                            }
                            $createdCount++;
                        }
                        if ($createdCount > 0) {
                            header("Location: task_result.php?id=" . $firstTaskId);
                            exit;
                        } else {
                            $error = 'No se pudieron crear incidentes: el CSV no contiene filas válidas.';
                        }
                    }
                } else {
                    // ── Modo normal: un solo incidente ──────────────────
                    $existing = Database::fetchOne("SELECT * FROM incidents WHERE incident_id = ?", [$incidentId]);
                    if ($existing) {
                        if (empty($title)) $title = $existing['title'] ?? 'Incidente sin título';
                        if (empty($severity)) $severity = $existing['severity'] ?? 'Medium';
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

                    _extractAndStoreEntities($incidentId, $csvData);

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
                    Database::update('incidents', ['blue_team_task_id' => $taskId], 'incident_id = ?', [$incidentId]);

                    header("Location: task_result.php?id=" . $taskId);
                    exit;
                }
            } else {
                // Sin archivo: crear o actualizar incidente manualmente
                if (empty($incidentId)) {
                    $error = 'El ID de incidente es obligatorio.';
                } else {
                    $existing = Database::fetchOne("SELECT * FROM incidents WHERE incident_id = ?", [$incidentId]);
                    if ($existing) {
                        Database::update('incidents', [
                            'title' => $title,
                            'severity' => $severity,
                            'source' => $source,
                            'status' => 'open',
                        ], 'incident_id = ?', [$incidentId]);
                    } else {
                        Database::insert('incidents', [
                            'incident_id' => $incidentId,
                            'title' => $title,
                            'severity' => $severity,
                            'source' => $source,
                            'status' => 'open',
                            'created_time' => date('Y-m-d H:i:s'),
                        ]);
                    }
                    $message = 'Incidente guardado correctamente.' . ($existing ? ' (actualizado)' : ' (creado)');
                }
            }
        } catch (Exception $e) {
            $error = 'Error al procesar: ' . $e->getMessage();
        }
    }

/**
 * Detecta si un CSV tiene la estructura del export Sentinel ofuscado.
 * Criterio: tiene cabeceras UserHash, UserDomain, EntityType.
 */
function _isSentinelObfuscatedCsv(array $headers): bool {
    $required = ['UserHash', 'UserDomain', 'EntityType'];
    $headersLower = array_map('strtolower', $headers);
    foreach ($required as $col) {
        if (!in_array(strtolower($col), $headersLower, true)) {
            return false;
        }
    }
    return true;
}

/**
 * Parsea un JSON array en formato string de KQL: ["ES","IT"] o ["1.2.3.4"]
 * Devuelve array de strings limpios.
 */
function _parseJsonArrayString(string $raw): array {
    if (empty($raw)) return [];
    // Intentar JSON decode
    $decoded = json_decode($raw, true);
    if (is_array($decoded)) {
        return array_filter(array_map('trim', $decoded));
    }
    // Fallback: limpiar brackets y dividir por coma
    $raw = trim($raw, '[]"\'');
    return array_filter(array_map('trim', explode(',', $raw)));
}

/**
 * Procesa CSV de Sentinel ofuscado extrayendo entidades por columna,
 * no por regex sobre texto plano.
 */
function _extractSentinelObfuscatedEntities(string $incidentId, array $rows, array $headers): void {
    // Normalizar nombres de cabecera a lowercase para búsqueda insensible
    $headerMap = [];
    foreach ($headers as $i => $h) {
        $headerMap[strtolower(trim($h))] = $i;
    }

    foreach ($rows as $row) {
        // Mapear columnas
        $userHash   = trim($row[($headerMap['userhash']   ?? -1)] ?? '');
        $userDomain = trim($row[($headerMap['userdomain'] ?? -1)] ?? '');
        $ipsRaw     = trim($row[($headerMap['ips']        ?? -1)] ?? '');
        $countries  = trim($row[($headerMap['countries']  ?? -1)] ?? '');
        $cities     = trim($row[($headerMap['cities']     ?? -1)] ?? '');
        $apps       = trim($row[($headerMap['apps']       ?? -1)] ?? '');
        $severity   = trim($row[($headerMap['severity']   ?? -1)] ?? 'high');
        $subject    = trim($row[($headerMap['subject']    ?? -1)] ?? '');

        // 1. Entidad usuario ofuscado (UserHash como identificador)
        if ($userHash) {
            $entityValue = $userDomain
                ? "hash:{$userHash}@{$userDomain}"
                : "hash:{$userHash}";

            try {
                Database::query(
                    "INSERT OR IGNORE INTO entities (entity_type, entity_value) VALUES (?, ?)",
                    ['user_obfuscated', $entityValue]
                );
                Database::query(
                    "INSERT OR IGNORE INTO incident_entities (incident_id, entity_value, role) VALUES (?, ?, ?)",
                    [$incidentId, $entityValue, 'victim']
                );
            } catch (Exception $e) { /* ignorar duplicados */ }
        }

        // 2. IPs — extraer del JSON array string: ["1.2.3.4","5.6.7.8"]
        $ips = _parseJsonArrayString($ipsRaw);
        foreach ($ips as $ip) {
            $ip = trim($ip, '"\'');
            if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;
            try {
                Database::query(
                    "INSERT OR IGNORE INTO entities (entity_type, entity_value) VALUES (?, ?)",
                    ['ip', $ip]
                );
                Database::query(
                    "INSERT OR IGNORE INTO incident_entities (incident_id, entity_value, role) VALUES (?, ?, ?)",
                    [$incidentId, $ip, 'related']
                );
            } catch (Exception $e) { /* ignorar duplicados */ }
        }
    }
}

// ── Extraer entidades del CSV y guardarlas ──────────────────────────
function _extractAndStoreEntities(string $incidentId, string $csvData): void {
    $lines = explode("\n", $csvData);
    if (count($lines) < 2) return;

    $headers = str_getcsv($lines[0]);

    // ── NUEVO: detectar CSV de Sentinel ofuscado ──────────────────
    if (_isSentinelObfuscatedCsv($headers)) {
        $rows = [];
        for ($i = 1; $i < count($lines); $i++) {
            $line = trim($lines[$i]);
            if (empty($line)) continue;
            $rows[] = str_getcsv($line);
        }
        _extractSentinelObfuscatedEntities($incidentId, $rows, $headers);
        return; // no continuar con la lógica de regex
    }
    // ── FIN NUEVO ─────────────────────────────────────────────────

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

$recentIOCs = Database::fetchAll(
    "SELECT * FROM iocs ORDER BY last_seen DESC LIMIT 30"
);

$iocStats = Database::fetchAll(
    "SELECT ioc_type, status, COUNT(*) as count FROM iocs GROUP BY ioc_type, status"
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

<!-- ── Formulario: Crear Manual + Subir CSV ────────────────────────── -->
<div class="card" style="margin-bottom:1.5rem;">
    <h3>📤 Gestión de Incidencias Blue Team</h3>

    <!-- SECCION A: Crear manual -->
    <form method="POST" action="" style="margin-top:1rem;padding:1rem;background:var(--surface);border-radius:var(--radius-sm);border:1px solid var(--border);">
        <h4 style="margin:0 0 .75rem;font-size:1rem;">➕ Crear incidencia manualmente</h4>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;">
            <div>
                <label>ID de Incidente</label>
                <input type="text" name="incident_id" placeholder="INC-25234 (opcional si usas split por filas)" style="width:100%;">
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
            <button type="submit" class="btn btn-primary">💾 Guardar incidencia manual</button>
        </div>
    </form>

    <!-- SECCION B: Subir CSV -->
    <form method="POST" action="" enctype="multipart/form-data" style="margin-top:1rem;padding:1rem;background:var(--surface);border-radius:var(--radius-sm);border:1px solid var(--border);">
        <h4 style="margin:0 0 .75rem;font-size:1rem;">📁 Subir CSV de Sentinel y analizar</h4>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;">
            <div>
                <label>Título base</label>
                <input type="text" name="incident_title" placeholder="Login desde país no habitual" style="width:100%;">
            </div>
            <div>
                <label>Severidad</label>
                <select name="incident_severity" style="width:100%;">
                    <option value="Low">Low</option>
                    <option value="Medium" selected>Medium</option>
                    <option value="High" selected>High</option>
                    <option value="Critical">Critical</option>
                </select>
            </div>
            <div>
                <label>Fuente</label>
                <select name="incident_source" style="width:100%;">
                    <option value="sentinel" selected>Microsoft Sentinel</option>
                    <option value="manual">Manual / CSV</option>
                </select>
            </div>
            <div style="display:flex;align-items:center;gap:.4rem;">
                <input type="checkbox" id="split_by_row" name="split_by_row" value="1" style="width:auto;">
                <label for="split_by_row" style="font-weight:normal;font-size:.85rem;cursor:pointer;">
                    Crear un incidente por cada fila del CSV
                </label>
            </div>
        </div>
        <div style="margin-top:1rem;">
            <label>Archivo CSV exportado de Sentinel *</label>
            <input type="file" name="incident_csv" accept=".csv,.json" required style="width:100%;padding:.5rem;border:2px dashed var(--border);border-radius:var(--radius-sm);background:var(--surface-2);">
            <div style="margin-top:.75rem;padding:.75rem 1rem;background:var(--surface-2);
                        border-radius:var(--radius-sm);font-size:.83rem;border-left:3px solid var(--accent);">
                <strong>📥 ¿Cómo exportar desde Sentinel?</strong>
                <ol style="margin:.5rem 0 0 1.2rem;padding:0;">
                    <li>Ejecuta la KQL de detección en Log Analytics / Sentinel.</li>
                    <li>Haz clic en <strong>Export → CSV (all columns)</strong>.</li>
                    <li>Sube el archivo aquí.</li>
                </ol>
                <details style="margin-top:.5rem;">
                    <summary style="cursor:pointer;color:var(--accent);">Ver KQL de ejemplo (login fuera de ES)</summary>
                    <pre style="background:var(--surface);padding:.75rem;border-radius:var(--radius-sm);
                                font-size:.75rem;overflow-x:auto;margin:.5rem 0;">SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City    = tostring(LocationDetails.city)
| where Country != "ES" and isnotempty(Country)
| summarize
    Countries  = tostring(make_set(Country, 10)),
    Cities     = tostring(make_set(City, 10)),
    IPs        = tostring(make_set(IPAddress, 10)),
    Apps       = tostring(make_set(AppDisplayName, 10)),
    FirstSeen  = min(TimeGenerated),
    LastSeen   = max(TimeGenerated),
    LoginCount = count()
    by UserPrincipalName
| extend
    Subject    = "Login desde país no habitual (fuera de ES)",
    EntityType = "user",
    Severity   = "high",
    UserHash   = tostring(hash_sha256(UserPrincipalName)),
    UserDomain = tostring(split(UserPrincipalName, "@")[1])
| project UserHash, UserDomain, Subject, EntityType, Severity,
          Countries, Cities, IPs, Apps, FirstSeen, LastSeen, LoginCount
| order by LoginCount desc</pre>
                    <p style="margin:.25rem 0 0;color:var(--text-muted);">
                        ⚠️ Los usuarios se exportan <strong>ofuscados</strong> (hash SHA256).
                        Para investigar un usuario concreto, usa la query de desofuscación en Sentinel.
                    </p>
                </details>
            </div>
        </div>
        <div style="margin-top:1rem;">
            <button type="submit" class="btn btn-primary">🔍 Analizar Incidente</button>
        </div>
    </form>
</div>

<!-- ── Azure Sentinel Sync ─────────────────────────────────────────── -->
<div class="card" style="margin-bottom:1.5rem;">
    <h3>🌩️ Azure Sentinel Sync</h3>
    <p style="color:var(--text-muted);font-size:.85rem;margin-bottom:1rem;">
        Sincroniza incidentes directamente desde Microsoft Sentinel usando Azure CLI device code flow.
        Requiere que hayas ejecutado <code>az login --use-device-code</code> en la Orin previamente.
    </p>
    <form id="azure-sync-form" onsubmit="return false;" style="display:flex;gap:.5rem;align-items:flex-end;flex-wrap:wrap;">
        <input type="hidden" id="azure-csrf" value="<?php echo htmlspecialchars(csrfToken(), ENT_QUOTES, 'UTF-8'); ?>">
        <div style="flex:1;min-width:200px;">
            <label style="font-size:.8rem;color:var(--text-muted);">Workspace ID (GUID)</label>
            <input type="text" id="azure-workspace" placeholder="12345678-1234-1234-1234-123456789abc" style="width:100%;">
        </div>
        <div>
            <label style="font-size:.8rem;color:var(--text-muted);">Días atrás</label>
            <input type="number" id="azure-days" value="7" min="1" max="30" style="width:80px;">
        </div>
        <div style="flex:1;min-width:150px;">
            <label style="font-size:.8rem;color:var(--text-muted);">Nº Incidente (opcional)</label>
            <input type="text" id="azure-incident" placeholder="Todos" style="width:100%;">
        </div>
        <button type="button" class="btn btn-primary" onclick="startAzureSync()">🔄 Sincronizar</button>
    </form>
    <div id="azure-sync-status" style="margin-top:1rem;display:none;">
        <p><span class="spinner"></span> Sincronizando con Sentinel...</p>
    </div>
    <div id="azure-sync-result" style="margin-top:1rem;"></div>
</div>

<script>
function startAzureSync() {
    const workspace = document.getElementById('azure-workspace').value.trim();
    const days = parseInt(document.getElementById('azure-days').value);
    const incident = document.getElementById('azure-incident').value.trim();
    const csrf = document.getElementById('azure-csrf').value;

    if (!workspace) { alert('Introduce el Workspace ID'); return; }

    const statusDiv = document.getElementById('azure-sync-status');
    const resultDiv = document.getElementById('azure-sync-result');
    statusDiv.style.display = 'block';
    resultDiv.innerHTML = '';

    fetch('api/v1/azure_sync.php?action=sync', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
        body: JSON.stringify({workspace_id: workspace, days: days, incident_id: incident})
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            resultDiv.innerHTML = '<div class="alert alert-success">Sync iniciada (tarea #' + data.task_id + '). Recarga la página en unos segundos para ver los incidentes.</div>';
            pollAzureStatus(data.task_id);
        } else {
            statusDiv.style.display = 'none';
            resultDiv.innerHTML = '<div class="alert alert-error">Error: ' + (data.error || 'desconocido') + '</div>';
        }
    })
    .catch(e => {
        statusDiv.style.display = 'none';
        resultDiv.innerHTML = '<div class="alert alert-error">Error de red: ' + e + '</div>';
    });
}

function pollAzureStatus(taskId) {
    const statusDiv = document.getElementById('azure-sync-status');
    const resultDiv = document.getElementById('azure-sync-result');

    const interval = setInterval(() => {
        fetch('api/v1/azure_sync.php?action=status&task_id=' + taskId)
        .then(r => r.json())
        .then(data => {
            if (!data.success) { clearInterval(interval); return; }
            const task = data.task;
            if (task.status === 'completed') {
                clearInterval(interval);
                statusDiv.style.display = 'none';
                resultDiv.innerHTML = '<div class="alert alert-success">✅ Sync completada.</div>' + (task.result_html || '');
            } else if (task.status === 'error') {
                clearInterval(interval);
                statusDiv.style.display = 'none';
                resultDiv.innerHTML = '<div class="alert alert-error">Error: ' + (task.error_message || 'desconocido') + '</div>';
            }
        })
        .catch(() => {});
    }, 5000);

    // Timeout después de 5 minutos
    setTimeout(() => { clearInterval(interval); statusDiv.style.display = 'none'; }, 300000);
}
</script>

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
                        $sevClass = match(strtoupper($inc['severity'] ?? '')) {
                            'CRITICAL' => 'severity-critical',
                            'HIGH'     => 'severity-high',
                            'MEDIUM'   => 'severity-medium',
                            'LOW'      => 'severity-low',
                            default    => 'severity-info',
                        };
                        ?>
                        <span class="badge <?php echo $sevClass; ?>"><?php echo htmlspecialchars($inc['severity'] ?? 'N/A'); ?></span>
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
                            $vClass = match($inc['llm_verdict']) {
                                'True Positive'  => 'verdict-true-positive',
                                'False Positive' => 'verdict-false-positive',
                                'Needs Review'   => 'verdict-needs-review',
                                default          => 'severity-info',
                            };
                            ?>
                            <span class="badge <?php echo $vClass; ?>"><?php echo htmlspecialchars($inc['llm_verdict']); ?></span>
                        <?php else: ?>
                            <em style="color:var(--text-muted);">Pendiente</em>
                        <?php endif; ?>
                    </td>
                    <td style="font-size:.85rem;color:var(--text-muted);"><?php echo htmlspecialchars(substr($inc['created_time'] ?? '', 0, 16)); ?></td>
                    <td style="white-space:nowrap;">
                        <?php if ($inc['blue_team_task_id']): ?>
                        <a href="task_result.php?id=<?php echo (int)$inc['blue_team_task_id']; ?>" class="btn btn-sm">Ver</a>
                        <?php else: ?>
                        <form method="POST" action="" enctype="multipart/form-data" style="display:inline-flex;gap:.3rem;align-items:center;">
                            <input type="hidden" name="incident_id" value="<?php echo htmlspecialchars($inc['incident_id'], ENT_QUOTES, 'UTF-8'); ?>">
                            <input type="file" name="incident_csv" accept=".csv" required style="width:90px;font-size:.7rem;padding:.2rem;">
                            <button type="submit" class="btn btn-sm" title="Subir CSV y analizar">📎</button>
                        </form>
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
                        $riskClass = $risk > 0.8 ? 'risk-critical' : ($risk > 0.5 ? 'risk-high' : 'risk-low');
                        $textRiskClass = $risk > 0.8 ? 'text-risk-critical' : ($risk > 0.5 ? 'text-risk-high' : 'text-risk-low');
                        ?>
                        <div style="display:flex;align-items:center;gap:.5rem;">
                            <div style="flex:1;background:var(--bg);border-radius:4px;height:8px;overflow:hidden;">
                                <div class="<?php echo $riskClass; ?>" style="width:<?php echo round($risk * 100); ?>%;height:100%;"></div>
                            </div>
                            <span class="<?php echo $textRiskClass; ?>" style="font-size:.8rem;font-weight:600;"><?php echo round($risk * 100); ?>%</span>
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

<!-- ── IOC Tracker ─────────────────────────────────────────────────── -->
<div class="card">
    <h3>🦠 IOC Tracker</h3>

    <!-- Formulario añadir IOC manual -->
    <form id="ioc-add-form" style="margin-bottom:1rem;display:flex;gap:.5rem;align-items:flex-end;flex-wrap:wrap;">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(csrfToken(), ENT_QUOTES, 'UTF-8'); ?>">
        <div style="flex:1;min-width:200px;">
            <label style="font-size:.8rem;color:var(--text-muted);">Valor IOC</label>
            <input type="text" id="ioc-value" placeholder="185.220.101.44 o evil.com" style="width:100%;">
        </div>
        <div>
            <label style="font-size:.8rem;color:var(--text-muted);">Tipo</label>
            <select id="ioc-type">
                <option value="ip">IP</option>
                <option value="domain">Dominio</option>
                <option value="hash">Hash</option>
                <option value="url">URL</option>
            </select>
        </div>
        <div style="flex:1;min-width:200px;">
            <label style="font-size:.8rem;color:var(--text-muted);">Notas</label>
            <input type="text" id="ioc-notes" placeholder="Contexto o evidencia" style="width:100%;">
        </div>
        <button type="button" class="btn btn-primary" onclick="addIoc()">➕ Añadir</button>
    </form>

    <!-- Mini estadísticas -->
    <div style="display:flex;gap:1rem;margin-bottom:1rem;flex-wrap:wrap;">
        <?php
        $statusLabels = ['sospechosa' => '🟡 Sospechosa', 'confirmada_maliciosa' => '🔴 Maliciosa', 'falsa_alarma' => '🟢 Falsa alarma', 'whitelist' => '⚪ Whitelist'];
        $statusCounts = [];
        foreach ($iocStats as $s) {
            $statusCounts[$s['status']] = ($statusCounts[$s['status']] ?? 0) + (int)$s['count'];
        }
        foreach ($statusLabels as $st => $label):
            $count = $statusCounts[$st] ?? 0;
        ?>
        <div style="background:var(--surface);border-radius:var(--radius-sm);padding:.5rem .75rem;font-size:.85rem;">
            <?php echo $label; ?>: <strong><?php echo $count; ?></strong>
        </div>
        <?php endforeach; ?>
    </div>

    <?php if (empty($recentIOCs)): ?>
        <p style="color:var(--text-muted);">No hay IOCs registrados. Se extraerán automáticamente al analizar incidentes, o puedes añadirlos manualmente arriba.</p>
    <?php else: ?>
    <div style="overflow-x:auto;">
        <table class="data-table">
            <thead>
                <tr>
                    <th>IOC</th>
                    <th>Tipo</th>
                    <th>Estado</th>
                    <th>VT</th>
                    <th>AbuseIPDB</th>
                    <th>Campaña</th>
                    <th>Última vez</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($recentIOCs as $ioc): ?>
                <tr>
                    <td><code><?php echo htmlspecialchars($ioc['ioc_value']); ?></code></td>
                    <td><span class="badge"><?php echo htmlspecialchars($ioc['ioc_type']); ?></span></td>
                    <td>
                        <?php
                        $iocClass = match($ioc['status']) {
                            'sospechosa'           => 'ioc-sospechosa',
                            'confirmada_maliciosa' => 'ioc-confirmada-maliciosa',
                            'falsa_alarma'         => 'ioc-falsa-alarma',
                            'whitelist'            => 'ioc-whitelist',
                            default                => 'severity-info',
                        };
                        ?>
                        <span class="badge <?php echo $iocClass; ?>">
                            <?php echo htmlspecialchars($ioc['status']); ?>
                        </span>
                    </td>
                    <td style="text-align:center;"><?php echo $ioc['osint_vt_score'] !== null ? $ioc['osint_vt_score'] . '/94' : '—'; ?></td>
                    <td style="text-align:center;"><?php echo $ioc['osint_abuse_score'] !== null ? $ioc['osint_abuse_score'] . '/100' : '—'; ?></td>
                    <td><?php echo htmlspecialchars($ioc['campaign_tag'] ?? ''); ?></td>
                    <td style="font-size:.85rem;color:var(--text-muted);"><?php echo htmlspecialchars(substr($ioc['last_seen'] ?? '', 0, 16)); ?></td>
                    <td>
                        <select onchange="updateIocStatus(<?php echo (int)$ioc['ioc_id']; ?>, this.value)" style="font-size:.8rem;">
                            <option value="" disabled selected>Cambiar...</option>
                            <option value="sospechosa">Sospechosa</option>
                            <option value="confirmada_maliciosa">Confirmada maliciosa</option>
                            <option value="falsa_alarma">Falsa alarma</option>
                            <option value="whitelist">Whitelist</option>
                        </select>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>

<script>
function addIoc() {
    const value = document.getElementById('ioc-value').value.trim();
    const type = document.getElementById('ioc-type').value;
    const notes = document.getElementById('ioc-notes').value.trim();
    const csrf = document.querySelector('input[name="csrf_token"]').value;

    if (!value) { alert('Introduce un valor IOC'); return; }

    fetch('api/v1/ioc_tracker.php?action=add', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
        body: JSON.stringify({ioc_value: value, ioc_type: type, notes: notes})
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) { location.reload(); }
        else { alert('Error: ' + (data.error || 'desconocido')); }
    })
    .catch(e => alert('Error de red: ' + e));
}

function updateIocStatus(id, status) {
    if (!status) return;
    const csrf = document.querySelector('input[name="csrf_token"]').value;
    fetch('api/v1/ioc_tracker.php?action=update_status', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
        body: JSON.stringify({ioc_id: id, status: status})
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) { location.reload(); }
        else { alert('Error: ' + (data.error || 'desconocido')); }
    })
    .catch(e => alert('Error de red: ' + e));
}
</script>

<?php require_once __DIR__ . '/templates/footer.php'; ?>
