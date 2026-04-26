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

// Guardar estado entre pasos en sesión
if (!isset($_SESSION['update_state'])) {
    $_SESSION['update_state'] = [];
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
            $zipFile = $updater->downloadUpdate();
            $_SESSION['update_state']['zip'] = $zipFile;
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
            if (!$sourceDir || !is_dir($sourceDir)) {
                jsonResponse(['error' => 'No hay fuente extraída'], 400);
            }
            // Convertir basename a path absoluto
            if (basename($backupFile) === $backupFile) {
                $backupFile = DATA_DIR . '/backups/' . $backupFile;
            }
            $updater->applyUpdate($sourceDir, $backupFile);
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
            if (basename($file) === $file) {
                $file = DATA_DIR . '/backups/' . $file;
            }
            $updater->rollback($file);
            jsonResponse(['success' => true]);
        } catch (Exception $e) {
            jsonResponse(['error' => $e->getMessage()], 500);
        }
        break;

    default:
        jsonResponse(['error' => 'Acción no válida'], 400);
}
