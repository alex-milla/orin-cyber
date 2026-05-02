<?php
declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '1');

require_once __DIR__ . '/includes/config.php';

header('Content-Type: text/plain; charset=utf-8');

echo "=== OrinSec — Instalador sqlite-vec ===\n\n";

$os = PHP_OS_FAMILY;
$arch = php_uname('m');
echo "PHP version: " . PHP_VERSION . "\n";
echo "Sistema operativo: $os\n";
echo "Arquitectura: $arch\n\n";

$platform = null;
if ($os === 'Linux' && (strpos($arch, 'x86_64') !== false || strpos($arch, 'amd64') !== false)) {
    $platform = 'x86_64-linux';
} elseif ($os === 'Linux' && strpos($arch, 'aarch64') !== false) {
    $platform = 'aarch64-linux';
} elseif ($os === 'Darwin' && strpos($arch, 'x86_64') !== false) {
    $platform = 'x86_64-darwin';
} elseif ($os === 'Darwin' && strpos($arch, 'arm64') !== false) {
    $platform = 'aarch64-darwin';
}

if (!$platform) {
    echo "❌ Plataforma no soportada: $os / $arch\n";
    echo "   La búsqueda full-text (Fase 1) seguirá funcionando.\n";
    exit;
}

$vecVersion = '0.1.6';
$vecUrl = "https://github.com/alex-milla/orin-cyber/releases/download/v0.13.0/vec0.so";
$tmpDir = sys_get_temp_dir() . '/sqlite-vec-install';
$tarPath = $tmpDir . '/sqlite-vec.tar.gz';
$soFile = null;

@mkdir($tmpDir, 0755, true);

// Buscar archivo ya subido manualmente primero
$manualPaths = [
    __DIR__ . '/data/sqlite-vec.so',
    __DIR__ . '/sqlite-vec.so',
    dirname(__DIR__) . '/sqlite-vec.so',
];

foreach ($manualPaths as $mp) {
    if (file_exists($mp)) {
        echo "✓ Encontrado sqlite-vec.so subido manualmente: {$mp}\n";
        $soFile = $mp;
        break;
    }
}

// Si no está manualmente, intentar descargar
if (!$soFile) {
    echo "→ Plataforma: $platform\n";
    echo "→ Intentando descargar sqlite-vec v{$vecVersion}...\n";
    echo "   URL: $vecUrl\n\n";

    $soData = false;
    $soPath = $tmpDir . '/vec0.so';

    // Método 1: file_get_contents
    if (ini_get('allow_url_fopen')) {
        echo "→ Método 1: file_get_contents...\n";
        $ctx = stream_context_create(['http' => ['timeout' => 60, 'follow_location' => 1]]);
        $soData = @file_get_contents($vecUrl, false, $ctx);
        if ($soData !== false) {
            echo "✓ Descargado vía file_get_contents (" . strlen($soData) . " bytes)\n";
            file_put_contents($soPath, $soData);
            $soFile = $soPath;
        }
    } else {
        echo "⚠ allow_url_fopen está deshabilitado\n";
    }

    // Método 2: exec curl
    if (!$soFile && function_exists('exec')) {
        echo "→ Método 2: curl vía exec...\n";
        $out = [];
        $ret = -1;
        @exec("curl -sL --max-time 60 '" . escapeshellarg($vecUrl) . "' -o " . escapeshellarg($soPath) . " 2>&1", $out, $ret);
        if ($ret === 0 && file_exists($soPath) && filesize($soPath) > 1000) {
            echo "✓ Descargado vía curl exec (" . filesize($soPath) . " bytes)\n";
            $soFile = $soPath;
        }
    }

    // Método 3: shell_exec curl
    if (!$soFile && function_exists('shell_exec')) {
        echo "→ Método 3: curl vía shell_exec...\n";
        @shell_exec("curl -sL --max-time 60 '" . escapeshellarg($vecUrl) . "' -o " . escapeshellarg($soPath) . " 2>/dev/null");
        if (file_exists($soPath) && filesize($soPath) > 1000) {
            echo "✓ Descargado vía shell_exec (" . filesize($soPath) . " bytes)\n";
            $soFile = $soPath;
        }
    }

    if (!$soFile) {
        echo "\n❌ No se pudo descargar sqlite-vec automáticamente.\n\n";
        echo "=== INSTRUCCIONES MANUALES ===\n";
        echo "1. Descarga este archivo directamente:\n";
        echo "   {$vecUrl}\n\n";
        echo "2. Renómbralo a 'vec0.so' y súbelo por FTP\n";
        echo "   a la carpeta 'hosting/data/' de tu sitio\n";
        echo "3. Vuelve a abrir esta página\n\n";
        echo "✅ La búsqueda full-text (Fase 1) seguirá funcionando perfectamente.\n";
        exit;
    }
}

if (!$soFile || !file_exists($soFile)) {
    echo "❌ No se encontro sqlite-vec.so\n";
    exit;
}

echo "→ Archivo: $soFile\n";
echo "→ Intentando cargar extension...\n";

try {
    $db = new SQLite3(DB_PATH);
    $db->loadExtension($soFile);
    $db->exec("CREATE VIRTUAL TABLE IF NOT EXISTS incident_embeddings_vec USING vec0(id INTEGER PRIMARY KEY, embedding FLOAT[384])");
    echo "\n✅ sqlite-vec CARGADO correctamente.\n";
    echo "✅ Tabla virtual incident_embeddings_vec creada.\n\n";

    $configFile = __DIR__ . '/includes/config.php';
    if (file_exists($configFile)) {
        $configContent = file_get_contents($configFile);
        if (strpos($configContent, "LOCAL_EMBED_URL', 'http://127.0.0.1:8081'") !== false) {
            echo "→ Actualizando LOCAL_EMBED_URL...\n";
            $newContent = str_replace(
                "define('LOCAL_EMBED_URL', 'http://127.0.0.1:8081');",
                "define('LOCAL_EMBED_URL', 'https://embed-orin.cyberintelligence.dev');",
                $configContent
            );
            file_put_contents($configFile, $newContent);
            echo "✅ config.php actualizado.\n\n";
        }
    }

    echo "=== INSTALACION COMPLETADA ===\n";
    echo "El RAG ahora usara busqueda vectorial (sqlite-vec).\n";
} catch (Exception $e) {
    echo "\n❌ Error cargando sqlite-vec: " . $e->getMessage() . "\n\n";
    echo "Esto es normal en hosting compartido.\n";
    echo "✅ La busqueda full-text (Fase 1) seguira funcionando perfectamente.\n";
}

echo "\n⚠️  BORRA ESTE ARCHIVO DESPUES DE EJECUTARLO.\n";
