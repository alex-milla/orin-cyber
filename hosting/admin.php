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
        <a href="?tab=users" class="<?php echo $tab==='users'?'active':''; ?>">Usuarios</a>
        <a href="?tab=config" class="<?php echo $tab==='config'?'active':''; ?>">Configuración</a>
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
                    <td><button class="secondary" onclick="doRollback('<?php echo htmlspecialchars($b['file'], ENT_QUOTES); ?>')">↩️ Restaurar</button></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

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
                <span id="key-<?php echo $k['id']; ?>" class="blur-reveal" title="Clic para revelar"><?php echo htmlspecialchars(substr($k['api_key'], 0, 8) . '...' . substr($k['api_key'], -8)); ?></span>
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
    <p id="key-msg" class="small mt-1"></p>
    
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
        if (current !== data.tag) {
            document.getElementById('btn-update').classList.remove('hidden');
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
        msg.style.color = '#2e7d32';
        msg.textContent = 'Nueva API key creada: ' + data.api_key;
        setTimeout(() => location.reload(), 2000);
    } else {
        msg.style.color = '#c62828';
        msg.textContent = data.error || 'Error';
    }
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
</script>
<?php require __DIR__ . '/templates/footer.php'; ?>
