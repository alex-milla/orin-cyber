<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/updater.php';

requireAdmin();

$action = $_GET['action'] ?? '';
$updater = new Updater();

if (!isset($_SESSION['update_state'])) {
    $_SESSION['update_state'] = [];
}

// Verificar CSRF para acciones destructivas
$destructive = ['apply', 'rollback'];
if (in_array($action, $destructive, true)) {
    $token = $_GET['csrf_token'] ?? ($_GET['csrf'] ?? '');
    if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        jsonResponse(['error' => 'Token CSRF inválido'], 403);
    }
}

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
                // Fetch fresh if not cached
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
