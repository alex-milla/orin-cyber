<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';

/**
 * Sistema de actualización desde GitHub con backup y rollback.
 */
class Updater {
    private string $repoUrl = 'https://github.com/alex-milla/orin-cyber';
    private string $zipUrl;
    private string $tempDir;
    private string $backupDir;
    private array $exclude = [
        'data',
        'install.php',
        '.htaccess',
    ];

    public function __construct() {
        $this->zipUrl = $this->repoUrl . '/archive/refs/heads/main.zip';
        $this->tempDir = sys_get_temp_dir() . '/orinsec_update_' . uniqid();
        $this->backupDir = DATA_DIR . '/backups';
    }

    /**
     * Obtiene la versión actual instalada
     */
    public function getCurrentVersion(): string {
        $row = Database::fetchOne("SELECT value FROM config WHERE key = 'version'");
        return $row['value'] ?? '0.0.0';
    }

    /**
     * Obtiene información del último commit en GitHub (versión remota)
     */
    public function getRemoteVersion(): array {
        $apiUrl = 'https://api.github.com/repos/alex-milla/orin-cyber/commits/main';
        $ctx = stream_context_create([
            'http' => [
                'header' => 'User-Agent: OrinSec-Updater',
                'timeout' => 10,
            ]
        ]);
        $raw = @file_get_contents($apiUrl, false, $ctx);
        if (!$raw) {
            return ['error' => 'No se pudo contactar con GitHub'];
        }
        $data = json_decode($raw, true);
        return [
            'sha' => substr($data['sha'] ?? 'unknown', 0, 7),
            'date' => $data['commit']['committer']['date'] ?? 'unknown',
            'message' => $data['commit']['message'] ?? 'Sin mensaje',
        ];
    }

    /**
     * Crea un backup ZIP del código actual antes de actualizar
     */
    public function createBackup(): string {
        if (!is_dir($this->backupDir)) {
            mkdir($this->backupDir, 0755, true);
        }
        $backupFile = $this->backupDir . '/backup_' . date('Ymd_His') . '.zip';
        $zip = new ZipArchive();
        if ($zip->open($backupFile, ZipArchive::CREATE) !== true) {
            throw new RuntimeException('No se pudo crear el archivo de backup');
        }

        $base = BASE_DIR;
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($base, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            $relative = str_replace($base . '/', '', $file->getPathname());
            $relative = str_replace('\\', '/', $relative);

            // Excluir data/ y backups anteriores
            if (str_starts_with($relative, 'data/') || str_starts_with($relative, 'data\\')) {
                continue;
            }
            if ($file->isDir()) {
                $zip->addEmptyDir($relative);
            } else {
                $zip->addFile($file->getPathname(), $relative);
            }
        }

        $zip->close();
        return $backupFile;
    }

    /**
     * Descarga el ZIP del repo desde GitHub
     */
    public function downloadUpdate(): string {
        if (!is_dir($this->tempDir)) {
            mkdir($this->tempDir, 0755, true);
        }
        $zipFile = $this->tempDir . '/update.zip';
        $ctx = stream_context_create([
            'http' => [
                'header' => 'User-Agent: OrinSec-Updater',
                'timeout' => 30,
            ]
        ]);
        $data = @file_get_contents($this->zipUrl, false, $ctx);
        if ($data === false) {
            throw new RuntimeException('No se pudo descargar la actualización desde GitHub');
        }
        file_put_contents($zipFile, $data);
        return $zipFile;
    }

    /**
     * Extrae el ZIP descargado
     */
    public function extractUpdate(string $zipFile): string {
        $zip = new ZipArchive();
        if ($zip->open($zipFile) !== true) {
            throw new RuntimeException('No se pudo abrir el ZIP descargado');
        }
        $zip->extractTo($this->tempDir);
        $zip->close();

        // GitHub extrae como orin-cyber-main/
        $extracted = $this->tempDir . '/orin-cyber-main';
        if (!is_dir($extracted)) {
            // Intentar detectar carpeta
            $dirs = glob($this->tempDir . '/*', GLOB_ONLYDIR);
            foreach ($dirs as $d) {
                if (is_dir($d . '/hosting')) {
                    $extracted = $d;
                    break;
                }
            }
        }
        if (!is_dir($extracted . '/hosting')) {
            throw new RuntimeException('Estructura del ZIP inesperada (no se encontró hosting/)');
        }
        return $extracted . '/hosting';
    }

    /**
     * Aplica la actualización reemplazando archivos
     */
    public function applyUpdate(string $sourceDir, string $backupFile): void {
        $targetDir = BASE_DIR;

        // Lista de archivos a copiar (excluyendo protegidos)
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($sourceDir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            $relative = str_replace($sourceDir . '/', '', $file->getPathname());
            $relative = str_replace('\\', '/', $relative);

            // Saltar archivos/carpetas protegidos
            $skip = false;
            foreach ($this->exclude as $ex) {
                if ($relative === $ex || str_starts_with($relative, $ex . '/') || str_starts_with($relative, $ex . '\\')) {
                    $skip = true;
                    break;
                }
            }
            if ($skip) continue;

            $dest = $targetDir . '/' . $relative;
            if ($file->isDir()) {
                if (!is_dir($dest)) {
                    mkdir($dest, 0755, true);
                }
            } else {
                if (!copy($file->getPathname(), $dest)) {
                    throw new RuntimeException("No se pudo copiar: {$relative}");
                }
            }
        }

        // Actualizar versión en DB
        $remote = $this->getRemoteVersion();
        $newVersion = isset($remote['sha']) ? 'main-' . $remote['sha'] : date('Y.m.d');
        Database::query("INSERT OR REPLACE INTO config (key, value) VALUES ('version', ?)", [$newVersion]);
    }

    /**
     * Rollback: restaura desde backup ZIP
     */
    public function rollback(string $backupFile): void {
        if (!file_exists($backupFile)) {
            throw new RuntimeException('Archivo de backup no encontrado');
        }
        $zip = new ZipArchive();
        if ($zip->open($backupFile) !== true) {
            throw new RuntimeException('No se pudo abrir el backup');
        }
        $zip->extractTo(BASE_DIR);
        $zip->close();
    }

    /**
     * Limpia archivos temporales
     */
    public function cleanup(): void {
        if (is_dir($this->tempDir)) {
            $this->rmrf($this->tempDir);
        }
    }

    /**
     * Elimina directorio recursivamente
     */
    private function rmrf(string $dir): void {
        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            is_dir($path) ? $this->rmrf($path) : unlink($path);
        }
        rmdir($dir);
    }

    /**
     * Lista backups disponibles
     */
    public function listBackups(): array {
        if (!is_dir($this->backupDir)) return [];
        $files = glob($this->backupDir . '/*.zip');
        rsort($files);
        return array_map(fn($f) => [
            'file' => basename($f),
            'path' => $f,
            'size' => $this->humanSize(filesize($f)),
            'date' => date('Y-m-d H:i:s', filemtime($f)),
        ], $files);
    }

    private function humanSize(int $bytes): string {
        $units = ['B','KB','MB','GB'];
        $u = 0;
        while ($bytes >= 1024 && $u < count($units) - 1) {
            $bytes /= 1024;
            $u++;
        }
        return round($bytes, 2) . ' ' . $units[$u];
    }
}
