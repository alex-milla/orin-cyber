<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/updater.php';

requireAdmin();

$tab = $_GET['tab'] ?? 'updates';
$updater = new Updater();
$currentVersion = $updater->getCurrentVersion();
$users = Database::fetchAll('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at DESC');
$backups = $updater->listBackups();

$pageTitle = 'Administración — OrinSec';
require __DIR__ . '/templates/header.php';
?>
<div class="card">
    <h2>⚙️ Panel de administración</h2>
    <div style="display:flex; gap:1rem; margin-bottom:1rem; border-bottom:2px solid #ddd;">
        <a href="?tab=updates" style="padding:.5rem 0; text-decoration:none; font-weight:600; color:<?php echo $tab==='updates'?'var(--primary)':'#666'; ?>; border-bottom:3px solid <?php echo $tab==='updates'?'var(--primary)':'transparent'; ?>;">Actualizaciones</a>
        <a href="?tab=users" style="padding:.5rem 0; text-decoration:none; font-weight:600; color:<?php echo $tab==='users'?'var(--primary)':'#666'; ?>; border-bottom:3px solid <?php echo $tab==='users'?'var(--primary)':'transparent'; ?>;">Usuarios</a>
        <a href="?tab=config" style="padding:.5rem 0; text-decoration:none; font-weight:600; color:<?php echo $tab==='config'?'var(--primary)':'#666'; ?>; border-bottom:3px solid <?php echo $tab==='config'?'var(--primary)':'transparent'; ?>;">Configuración</a>
    </div>

    <?php if ($tab === 'updates'): ?>
    <div id="update-panel">
        <h3>Estado del sistema</h3>
        <p>Versión instalada: <code id="current-version"><?php echo htmlspecialchars($currentVersion); ?></code></p>
        <p>Versión remota: <code id="remote-version">Consultando...</code></p>
        <p id="remote-message" class="small"></p>
        <button id="btn-check" onclick="checkUpdate()">🔄 Buscar actualizaciones</button>
        <button id="btn-update" onclick="doUpdate()" style="display:none;">⬇️ Actualizar ahora</button>
        <div id="update-log" style="margin-top:1rem; font-family:monospace; background:#f5f5f5; padding:1rem; border-radius:4px; min-height:60px; display:none;"></div>

        <h3 style="margin-top:2rem;">Backups disponibles</h3>
        <?php if (empty($backups)): ?>
            <p class="small">No hay backups.</p>
        <?php else: ?>
            <table style="width:100%; border-collapse:collapse;">
                <thead><tr style="border-bottom:2px solid #ddd;">
                    <th style="text-align:left; padding:.5rem;">Archivo</th>
                    <th style="text-align:left; padding:.5rem;">Tamaño</th>
                    <th style="text-align:left; padding:.5rem;">Fecha</th>
                    <th style="text-align:left; padding:.5rem;">Acción</th>
                </tr></thead>
                <tbody>
                <?php foreach ($backups as $b): ?>
                <tr style="border-bottom:1px solid #eee;">
                    <td style="padding:.5rem;"><?php echo htmlspecialchars($b['file']); ?></td>
                    <td style="padding:.5rem;"><?php echo htmlspecialchars($b['size']); ?></td>
                    <td style="padding:.5rem;"><?php echo htmlspecialchars($b['date']); ?></td>
                    <td style="padding:.5rem;"><button class="secondary" onclick="doRollback('<?php echo htmlspecialchars($b['file'], ENT_QUOTES); ?>')">↩️ Restaurar</button></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <?php elseif ($tab === 'users'): ?>
    <h3>Usuarios registrados</h3>
    <table style="width:100%; border-collapse:collapse;">
        <thead><tr style="border-bottom:2px solid #ddd;">
            <th style="text-align:left; padding:.5rem;">ID</th>
            <th style="text-align:left; padding:.5rem;">Usuario</th>
            <th style="text-align:left; padding:.5rem;">Admin</th>
            <th style="text-align:left; padding:.5rem;">Registro</th>
        </tr></thead>
        <tbody>
        <?php foreach ($users as $u): ?>
        <tr style="border-bottom:1px solid #eee;">
            <td style="padding:.5rem;"><?php echo $u['id']; ?></td>
            <td style="padding:.5rem;"><?php echo htmlspecialchars($u['username']); ?></td>
            <td style="padding:.5rem;"><?php echo $u['is_admin'] ? 'Sí' : 'No'; ?></td>
            <td style="padding:.5rem;"><?php echo htmlspecialchars($u['created_at']); ?></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
    </table>

    <h3 style="margin-top:2rem;">Crear usuario</h3>
    <form method="POST" action="ajax_admin.php?action=add_user" onsubmit="return addUser(this);">
        <?php echo csrfInput(); ?>
        <label>Usuario</label>
        <input type="text" name="username" required maxlength="64" pattern="[\w\-.@]+" title="Letras, números, guiones, puntos y @">
        <label>Contraseña</label>
        <input type="password" name="password" required minlength="8" maxlength="128">
        <label><input type="checkbox" name="is_admin" value="1"> Administrador</label>
        <button type="submit" style="margin-top:1rem;">Crear usuario</button>
        <p id="user-msg" style="margin-top:.5rem;"></p>
    </form>

    <?php else: ?>
    <h3>Configuración del sistema</h3>
    <?php
    $apiKeyRow = Database::fetchOne("SELECT value FROM config WHERE key = 'api_key'");
    $apiKey = $apiKeyRow['value'] ?? 'No configurada';
    $regRow = Database::fetchOne("SELECT value FROM config WHERE key = 'allow_registration'");
    $regEnabled = !$regRow || $regRow['value'] === '1';
    ?>
    <p><strong>API Key del worker:</strong></p>
    <code style="display:block; background:#f5f5f5; padding:1rem; word-break:break-all;"><?php echo htmlspecialchars($apiKey); ?></code>
    <p class="small">Esta clave debe configurarse en <code>worker/config.ini</code> del Orin Nano.</p>
    
    <h3 style="margin-top:2rem;">Registro de usuarios</h3>
    <p>Estado: <strong><?php echo $regEnabled ? 'Abierto' : 'Cerrado'; ?></strong></p>
    <form method="POST" action="ajax_admin.php?action=toggle_registration" onsubmit="return toggleReg(this);">
        <?php echo csrfInput(); ?>
        <button type="submit"><?php echo $regEnabled ? '🔒 Cerrar registro' : '🔓 Abrir registro'; ?></button>
        <p id="reg-msg" style="margin-top:.5rem;"></p>
    </form>
    <p class="small">Si el registro está cerrado, solo los administradores pueden crear cuentas.</p>
    <?php endif; ?>
</div>

<script>
let remoteInfo = null;
const csrfToken = <?php echo json_encode(csrfToken()); ?>;

function log(msg) {
    const el = document.getElementById('update-log');
    el.style.display = 'block';
    el.textContent += msg + '\n';
}

async function checkUpdate() {
    document.getElementById('btn-check').disabled = true;
    const resp = await fetch('ajax_update.php?action=check');
    const data = await resp.json();
    document.getElementById('btn-check').disabled = false;

    if (data.error) {
        document.getElementById('remote-version').textContent = 'Error';
        document.getElementById('remote-message').textContent = data.error;
        return;
    }

    remoteInfo = data;
    document.getElementById('remote-version').textContent = data.sha + ' (' + data.date + ')';
    document.getElementById('remote-message').textContent = data.message;

    const current = document.getElementById('current-version').textContent;
    if (current !== data.sha && current !== 'main-' + data.sha) {
        document.getElementById('btn-update').style.display = 'inline-block';
    } else {
        document.getElementById('remote-message').textContent += ' — ✅ Estás en la última versión.';
    }
}

async function doUpdate() {
    if (!confirm('Se creará un backup antes de actualizar. ¿Continuar?')) return;
    document.getElementById('btn-update').disabled = true;
    document.getElementById('update-log').textContent = '';

    log('1/4 Creando backup...');
    let r1 = await fetch('ajax_update.php?action=backup');
    let d1 = await r1.json();
    if (d1.error) { log('❌ Backup fallido: ' + d1.error); document.getElementById('btn-update').disabled = false; return; }
    log('✅ Backup creado: ' + d1.file);

    log('2/4 Descargando actualización...');
    let r2 = await fetch('ajax_update.php?action=download');
    let d2 = await r2.json();
    if (d2.error) { log('❌ Descarga fallida: ' + d2.error); rollback(d1.file); return; }
    log('✅ Descargado');

    log('3/4 Extrayendo...');
    let r3 = await fetch('ajax_update.php?action=extract');
    let d3 = await r3.json();
    if (d3.error) { log('❌ Extracción fallida: ' + d3.error); rollback(d1.file); return; }
    log('✅ Extraído');

    log('4/4 Aplicando actualización...');
    let r4 = await fetch('ajax_update.php?action=apply&backup=' + encodeURIComponent(d1.file) + '&csrf=' + encodeURIComponent(csrfToken));
    let d4 = await r4.json();
    if (d4.error) {
        log('❌ Aplicación fallida: ' + d4.error);
        log('Iniciando rollback automático...');
        rollback(d1.file);
        return;
    }
    log('✅ Actualización completada. Nueva versión: ' + d4.version);
    log('🔄 Recargando página en 3 segundos...');
    setTimeout(() => location.reload(), 3000);
}

async function rollback(file) {
    log('↩️ Rollback a ' + file + '...');
    let r = await fetch('ajax_update.php?action=rollback&file=' + encodeURIComponent(file) + '&csrf=' + encodeURIComponent(csrfToken));
    let d = await r.json();
    if (d.error) { log('❌ Rollback fallido: ' + d.error); }
    else { log('✅ Rollback completado. Recargando...'); setTimeout(() => location.reload(), 2000); }
}

async function doRollback(file) {
    if (!confirm('¿Restaurar backup ' + file + '?')) return;
    document.getElementById('update-log').textContent = '';
    log('Restaurando ' + file + '...');
    let r = await fetch('ajax_update.php?action=rollback&file=' + encodeURIComponent(file) + '&csrf=' + encodeURIComponent(csrfToken));
    let d = await r.json();
    if (d.error) { log('❌ ' + d.error); }
    else { log('✅ Restaurado. Recargando...'); setTimeout(() => location.reload(), 2000); }
}

async function addUser(form) {
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
    return false;
}

async function toggleReg(form) {
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
    return false;
}
</script>
<?php require __DIR__ . '/templates/footer.php'; ?>
