<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/ioc_converter_utils.php';

requireAuth();
iocCleanOldFiles();

$error = '';
$result = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        $error = 'Token de seguridad inválido. Recarga la página.';
    } else {
        $inputFiles = $_FILES['input_files'] ?? null;
        if (!$inputFiles || $inputFiles['error'][0] === UPLOAD_ERR_NO_FILE) {
            $error = 'Por favor selecciona al menos un archivo.';
        } elseif ($inputFiles['error'][0] !== UPLOAD_ERR_OK) {
            $error = 'Error al subir el archivo.';
        } else {
            $outputFormat = in_array($_POST['output_format'] ?? '', ['split','merged']) ? ($_POST['output_format'] ?? 'split') : 'split';
            $sourceName = validateInput($_POST['source_name'] ?? 'Unknown', 100) ?: 'Unknown';
            $threatActor = validateInput($_POST['threat_actor'] ?? '', 100) ?: '';
            $tags = validateInput($_POST['tags'] ?? '', 200) ?: '';
            $confidence = filter_input(INPUT_POST, 'confidence', FILTER_VALIDATE_INT) ?: 75;
            $confidence = max(1, min(100, $confidence));
            $tlpLevel = in_array($_POST['tlp_level'] ?? '', ['white','green','amber','red']) ? ($_POST['tlp_level'] ?? 'green') : 'green';
            $indicatorType = in_array($_POST['indicator_type'] ?? '', ['malicious-activity','anomalous-activity','attribution','compromised','benign','unknown']) ? ($_POST['indicator_type'] ?? 'malicious-activity') : 'malicious-activity';
            $validDays = filter_input(INPUT_POST, 'valid_days', FILTER_VALIDATE_INT) ?: 365;
            $validDays = max(1, min(3650, $validDays));

            $result = iocProcessFiles($inputFiles, $outputFormat, $sourceName, $threatActor, $tags, $confidence, $tlpLevel, $indicatorType, $validDays);
            if (!$result['success']) {
                $error = $result['error'] ?? 'Error desconocido';
                $result = null;
            }
        }
    }
}

$pageTitle = 'IOC → STIX 2.1 — OrinSec';
require __DIR__ . '/templates/header.php';
?>

<div class="card">
    <h2>🔄 Convertidor IOC → STIX 2.1</h2>
    <p class="small" style="color:var(--text-secondary);">Convierte listas de indicadores de compromiso (IPs, dominios, hashes, URLs, etc.) al formato estándar STIX 2.1 para interoperabilidad con plataformas de ciberseguridad.</p>

    <?php if ($error): ?>
        <p class="alert alert-error"><?php echo htmlspecialchars($error); ?></p>
    <?php endif; ?>

    <?php if ($result): ?>
        <div class="alert alert-success">
            <strong>✅ Conversión completada</strong> — <?php echo (int)$result['processed']; ?> indicadores procesados
            <?php if ($result['duplicates'] > 0): ?> (<?php echo (int)$result['duplicates']; ?> duplicados eliminados)<?php endif; ?>
        </div>

        <div class="dashboard-grid" style="margin-top:1rem;">
            <div class="widget">
                <h3>📊 Resumen por tipo</h3>
                <?php if (empty($result['by_type'])): ?>
                    <p class="empty-state">No se detectaron indicadores.</p>
                <?php else: ?>
                    <div class="mini-bar-chart">
                        <?php
                        $maxCount = max($result['by_type']);
                        $typeColors = [
                            'ipv4-addr' => 'bar-info',
                            'ipv6-addr' => 'bar-info',
                            'domain-name' => 'bar-medium',
                            'url' => 'bar-high',
                            'file' => 'bar-critical',
                            'email-addr' => 'bar-warning',
                            'user-account' => 'bar-low',
                            'windows-registry-key' => 'bar-low',
                        ];
                        foreach ($result['by_type'] as $type => $count):
                            $pct = $maxCount > 0 ? round(($count / $maxCount) * 100) : 0;
                            $color = $typeColors[$type] ?? 'bar-info';
                            $label = iocGetHumanReadableType($type);
                        ?>
                        <div class="mini-bar-row">
                            <div class="mini-bar-label"><?php echo htmlspecialchars($label); ?></div>
                            <div class="mini-bar-track">
                                <div class="mini-bar-fill <?php echo $color; ?>" style="width: <?php echo $pct; ?>%;"></div>
                            </div>
                            <div class="mini-bar-count"><?php echo (int)$count; ?></div>
                        </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>

            <div class="widget">
                <h3>📁 Archivos generados</h3>
                <?php if (empty($result['output_files'])): ?>
                    <p class="empty-state">No se generaron archivos.</p>
                <?php else: ?>
                    <ul style="list-style:none;padding:0;margin:0;">
                        <?php foreach ($result['output_files'] as $fileName):
                            $filePath = $result['download_paths'][$fileName] ?? '';
                            $size = $filePath && file_exists($filePath) ? iocFormatBytes(filesize($filePath)) : '—';
                        ?>
                        <li style="display:flex;justify-content:space-between;align-items:center;padding:.5rem 0;border-bottom:1px solid var(--border);">
                            <span class="small font-mono"><?php echo htmlspecialchars($fileName); ?></span>
                            <span class="small" style="color:var(--text-muted);"><?php echo $size; ?></span>
                            <?php if ($filePath && file_exists($filePath)): ?>
                            <a href="ioc_download.php?f=<?php echo urlencode(basename($fileName)); ?>&t=<?php echo urlencode($_SESSION['csrf_token'] ?? ''); ?>" class="btn small" style="margin-left:auto;">Descargar</a>
                            <?php endif; ?>
                        </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
                <p class="small" style="color:var(--text-muted);margin-top:.5rem;">Generado: <?php echo htmlspecialchars($result['timestamp']); ?></p>
            </div>
        </div>

        <p style="margin-top:1.5rem;">
            <a href="ioc_converter.php"><button class="secondary">← Nueva conversión</button></a>
        </p>
    <?php else: ?>
        <form method="POST" enctype="multipart/form-data">
            <?php echo csrfInput(); ?>

            <div class="dashboard-grid">
                <div class="widget" style="padding:1.25rem;">
                    <h3>📤 Archivos de entrada</h3>
                    <label>Archivos IOC</label>
                    <input type="file" name="input_files[]" multiple accept=".txt,.list,.dat,.ioc,.csv,.json" required style="padding:.5rem 0;">
                    <p class="small" style="color:var(--text-muted);margin-top:.25rem;">Formatos: txt, list, dat, ioc, csv, json. Máx. 10 MB por archivo.</p>

                    <label style="margin-top:1rem;">Formato de salida</label>
                    <select name="output_format">
                        <option value="split" selected>Separado por tipo (recomendado)</option>
                        <option value="merged">Archivo único combinado</option>
                    </select>
                </div>

                <div class="widget" style="padding:1.25rem;">
                    <h3>🏷️ Metadatos STIX</h3>
                    <label>Nombre de la fuente</label>
                    <input type="text" name="source_name" value="Unknown" required>

                    <label>Actor de amenaza</label>
                    <input type="text" name="threat_actor" placeholder="Ej: APT28, Lazarus Group">

                    <label>Tags (separados por coma)</label>
                    <input type="text" name="tags" placeholder="ransomware, c2, banking">
                </div>
            </div>

            <div class="dashboard-grid" style="margin-top:var(--gap);">
                <div class="widget" style="padding:1.25rem;">
                    <h3>⚙️ Configuración de indicadores</h3>
                    <label>Confianza (1-100)</label>
                    <input type="number" name="confidence" min="1" max="100" value="75" required>

                    <label>Nivel TLP</label>
                    <select name="tlp_level">
                        <option value="white">WHITE</option>
                        <option value="green" selected>GREEN</option>
                        <option value="amber">AMBER</option>
                        <option value="red">RED</option>
                    </select>

                    <label>Tipo de indicador</label>
                    <select name="indicator_type">
                        <option value="malicious-activity" selected>Actividad Maliciosa</option>
                        <option value="anomalous-activity">Actividad Anómala</option>
                        <option value="attribution">Atribución</option>
                        <option value="compromised">Sistema Comprometido</option>
                        <option value="benign">Benigno</option>
                        <option value="unknown">Desconocido</option>
                    </select>

                    <label>Validez (días)</label>
                    <input type="number" name="valid_days" min="1" max="3650" value="365" required>
                </div>

                <div class="widget" style="padding:1.25rem;display:flex;flex-direction:column;justify-content:center;align-items:center;text-align:center;">
                    <div style="font-size:3rem;margin-bottom:.5rem;">🔄</div>
                    <p class="small" style="color:var(--text-secondary);margin-bottom:1rem;">Los archivos se procesan localmente en el hosting. No se envían a servicios externos.</p>
                    <button type="submit" class="btn btn-primary" style="font-size:1.05rem;padding:.75rem 2rem;">Convertir a STIX 2.1</button>
                </div>
            </div>
        </form>
    <?php endif; ?>
</div>

<div class="card">
    <h3>📖 Formatos de entrada soportados</h3>
    <div class="quick-actions" style="margin-top:.5rem;">
        <div class="quick-action-btn" style="min-height:auto;padding:.75rem;cursor:default;">
            <span class="qa-label">📄 .txt / .list / .dat</span>
            <span class="qa-desc">Un IOC por línea. Se admiten comentarios (#, //, ;)</span>
        </div>
        <div class="quick-action-btn" style="min-height:auto;padding:.75rem;cursor:default;">
            <span class="qa-label">📊 .csv</span>
            <span class="qa-desc">Primera fila como cabecera. Detecta columna value/indicator/ip/domain/hash/url</span>
        </div>
        <div class="quick-action-btn" style="min-height:auto;padding:.75rem;cursor:default;">
            <span class="qa-label">🗂️ .json</span>
            <span class="qa-desc">Array de objetos o strings. Busca campo value/indicator/ip/domain/hash/url</span>
        </div>
    </div>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
