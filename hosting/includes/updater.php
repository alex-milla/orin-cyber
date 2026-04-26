<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';

/**
 * Sistema de actualización desde GitHub Releases con backup y rollback.
 */
class Updater {
    private string $repoOwner = 'alex-milla';
    private string $repoName = 'orin-cyber';
    private string $apiUrl;
    private string $tempDir;
    private string $backupDir;
    private array $exclude = [
        'data',
        'install.php',
        '.htaccess',
    ];

    private ?string $githubPat = null;

    public function __construct() {
        $this->apiUrl = "https://api.github.com/repos/{$this->repoOwner}/{$this->repoName}/releases/latest";
        $this->tempDir = sys_get_temp_dir() . '/orinsec_update_' . uniqid();
        $this->backupDir = DATA_DIR . '/backups';
        
        $patRow = Database::fetchOne("SELECT value FROM config WHERE key = 'github_pat'");
        $this->githubPat = $patRow['value'] ?? null;
    }

    private function httpContext(array $extra = []): array {
        $headers = 'User-Agent: OrinSec-Updater';
        if ($this->githubPat) {
            $headers .= "\r\nAuthorization: Bearer {$this->githubPat}";
        }
        $ctx = [
            'http' => array_merge([
                'header' => $headers,
                'timeout' => 30,
                'follow_location' => true,
            ], $extra)
        ];
        return $ctx;
    }

    /**
     * Obtiene la versión actual instalada
     */
    public function getCurrentVersion(): string {
        $row = Database::fetchOne("SELECT value FROM config WHERE key = 'version'");
        return $row['value'] ?? '0.0.0';
    }

    /**
     * Obtiene información de la última release en GitHub
     */
    private function fetchUrl(string $url): ?string {
        // Intentar con curl primero (más compatible con hosting compartido)
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 15);
            curl_setopt($ch, CURLOPT_USERAGENT, 'OrinSec-Updater');
            if ($this->githubPat) {
                curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $this->githubPat]);
            }
            $raw = curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($raw !== false && $code >= 200 && $code < 300) {
                return $raw;
            }
        }
        // Fallback a file_get_contents
        $ctx = stream_context_create($this->httpContext(['timeout' => 10]));
        $raw = @file_get_contents($url, false, $ctx);
        return $raw ?: null;
    }

    public function getRemoteVersion(): array {
        $raw = $this->fetchUrl($this->apiUrl);
        if (!$raw) {
            return ['error' => 'No se pudo contactar con GitHub o no hay releases disponibles'];
        }
        $data = json_decode($raw, true);
        if (empty($data['tag_name'])) {
            return ['error' => 'Respuesta inesperada de GitHub'];
        }
        return [
            'tag' => $data['tag_name'],
            'name' => $data['name'] ?? $data['tag_name'],
            'published' => $data['published_at'] ?? 'unknown',
            'body' => $data['body'] ?? 'Sin notas de release',
            'zip_url' => $data['zipball_url'] ?? null,
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
     * Descarga el ZIP de la última release desde GitHub
     */
    public function downloadUpdate(string $zipUrl): string {
        if (!is_dir($this->tempDir)) {
            mkdir($this->tempDir, 0755, true);
        }
        $zipFile = $this->tempDir . '/update.zip';

        if (function_exists('curl_init')) {
            $fp = fopen($zipFile, 'w+');
            $ch = curl_init($zipUrl);
            curl_setopt($ch, CURLOPT_FILE, $fp);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 60);
            curl_setopt($ch, CURLOPT_USERAGENT, 'OrinSec-Updater');
            if ($this->githubPat) {
                curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $this->githubPat]);
            }
            curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            fclose($fp);
            if ($code < 200 || $code >= 300) {
                throw new RuntimeException('No se pudo descargar la release desde GitHub (HTTP ' . $code . ')');
            }
            return $zipFile;
        }

        $ctx = stream_context_create($this->httpContext(['timeout' => 60]));
        $data = @file_get_contents($zipUrl, false, $ctx);
        if ($data === false) {
            throw new RuntimeException('No se pudo descargar la release desde GitHub');
        }
        file_put_contents($zipFile, $data);
        return $zipFile;
    }

    /**
     * Extrae el ZIP descargado. GitHub releases usan nombres tipo: repo-tag/
     */
    public function extractUpdate(string $zipFile): string {
        $zip = new ZipArchive();
        if ($zip->open($zipFile) !== true) {
            throw new RuntimeException('No se pudo abrir el ZIP descargado');
        }
        $zip->extractTo($this->tempDir);
        $zip->close();

        // Detectar carpeta extraída (GitHub releases: orin-cyber-0.1.0/)
        $extracted = null;
        $dirs = glob($this->tempDir . '/*', GLOB_ONLYDIR);
        foreach ($dirs as $d) {
            if (is_dir($d . '/hosting')) {
                $extracted = $d;
                break;
            }
        }
        if (!$extracted) {
            throw new RuntimeException('Estructura del ZIP inesperada (no se encontró hosting/)');
        }
        return $extracted . '/hosting';
    }

    /**
     * Aplica la actualización reemplazando archivos
     */
    public function applyUpdate(string $sourceDir, string $backupFile, string $newVersion): void {
        $targetDir = BASE_DIR;

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($sourceDir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            $relative = str_replace($sourceDir . '/', '', $file->getPathname());
            $relative = str_replace('\\', '/', $relative);

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

    private function rmrf(string $dir): void {
        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            is_dir($path) ? $this->rmrf($path) : unlink($path);
        }
        rmdir($dir);
    }

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
