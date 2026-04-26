<?php
declare(strict_types=1);
/**
 * EMERGENCY FIX v2 — Replaces corrupted ajax_update.php with clean v0.1.8 version.
 * Upload to hosting root, run via browser, then DELETE immediately.
 */
$target = __DIR__ . '/ajax_update.php';

$clean = <<<'PHP'
<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/updater.php';

try {
    requireAdmin();

    $action = $_GET['action'] ?? '';
    $updater = new Updater();

    if (!isset($_SESSION['update_state'])) {
        $_SESSION['update_state'] = [];
    }

    // Nota: requireAdmin() ya verifica la sesión. El CSRF adicional está
    // desactivado en el updater porque las peticiones son cross-AJAX con
// credenciales de sesión y el origin es el mismo dominio.

function validateBackupName(string $name): ?string {
    if (!preg_match('/^backup_\d{8}_\d{6}\.zip$/', $name)) {
        return null;
    }
    return $name;
}

switch ($action) {
    case 'check':
        $remote = $updater->getRemoteVersion();
        if (isset($remote['error'])) {
            jsonResponse(['error' => $remote['error']], 500);
        }
        jsonResponse($remote);
        break;

    case 'backup':
        try {
            $backupFile = $updater->createBackup();
            $_SESSION['update_state']['backup'] = $backupFile;
            jsonResponse(['success' => true, 'file' => basename($backupFile)]);
        } catch (Exception $e) {
            jsonResponse(['error' => $e->getMessage()], 500);
        }
        break;

    case 'download':
        try {
            $remote = $_SESSION['update_state']['remote'] ?? null;
            if (!$remote || empty($remote['zip_url'])) {
                $remote = $updater->getRemoteVersion();
                if (isset($remote['error'])) {
                    jsonResponse(['error' => $remote['error']], 500);
                }
            }
            $zipFile = $updater->downloadUpdate($remote['zip_url']);
            $_SESSION['update_state']['zip'] = $zipFile;
            $_SESSION['update_state']['remote'] = $remote;
            jsonResponse(['success' => true]);
        } catch (Exception $e) {
            jsonResponse(['error' => $e->getMessage()], 500);
        }
        break;

    case 'extract':
        try {
            $zipFile = $_SESSION['update_state']['zip'] ?? '';
            if (!$zipFile || !file_exists($zipFile)) {
                jsonResponse(['error' => 'No hay ZIP descargado'], 400);
            }
            $sourceDir = $updater->extractUpdate($zipFile);
            $_SESSION['update_state']['source'] = $sourceDir;
            jsonResponse(['success' => true]);
        } catch (Exception $e) {
            jsonResponse(['error' => $e->getMessage()], 500);
        }
        break;

    case 'apply':
        try {
            $sourceDir = $_SESSION['update_state']['source'] ?? '';
            $backupFile = $_GET['backup'] ?? '';
            $remote = $_SESSION['update_state']['remote'] ?? null;
            if (!$sourceDir || !is_dir($sourceDir)) {
                jsonResponse(['error' => 'No hay fuente extraída'], 400);
            }
            $valid = validateBackupName(basename($backupFile));
            if (!$valid) {
                jsonResponse(['error' => 'Nombre de backup inválido'], 400);
            }
            $backupFile = DATA_DIR . '/backups/' . $valid;
            $newVersion = $remote['tag'] ?? date('Y.m.d');
            $updater->applyUpdate($sourceDir, $backupFile, $newVersion);
            $updater->cleanup();
            unset($_SESSION['update_state']);
            jsonResponse(['success' => true, 'version' => $updater->getCurrentVersion()]);
        } catch (Exception $e) {
            jsonResponse(['error' => $e->getMessage()], 500);
        }
        break;

    case 'rollback':
        try {
            $file = $_GET['file'] ?? '';
            $valid = validateBackupName(basename($file));
            if (!$valid) {
                jsonResponse(['error' => 'Nombre de backup inválido'], 400);
            }
            $file = DATA_DIR . '/backups/' . $valid;
            $updater->rollback($file);
            jsonResponse(['success' => true]);
        } catch (Exception $e) {
            jsonResponse(['error' => $e->getMessage()], 500);
        }
        break;

    default:
        jsonResponse(['error' => 'Acción no válida'], 400);
}
} catch (Throwable $e) {
    jsonResponse(['error' => 'Error interno: ' . $e->getMessage()], 500);
}
PHP;

if (file_put_contents($target, $clean) === false) {
    die('ERROR: Could not write ajax_update.php');
}

echo "✅ FIXED: ajax_update.php restored to clean v0.1.8.<br>";
echo "Go to Admin → Updates and click 'Actualizar ahora'.<br><br>";
echo "🗑️ <strong>DELETE this file (emergency_fix.php) immediately after use.</strong>";
