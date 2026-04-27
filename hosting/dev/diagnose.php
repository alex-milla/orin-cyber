<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/auth.php';
requireAdmin();

header('Content-Type: text/html; charset=utf-8');
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

$errors = [];
$warnings = [];
$ok = [];

// 1. Versión PHP
$phpVersion = PHP_VERSION;
if (version_compare($phpVersion, '8.0.0', '>=')) {
    $ok[] = "PHP version: {$phpVersion} ✅";
} else {
    $errors[] = "PHP version: {$phpVersion} ❌ (se requiere 8.0+)";
}

// 2. Extensiones necesarias
$required = ['pdo', 'pdo_sqlite', 'json', 'session', 'zip'];
foreach ($required as $ext) {
    if (extension_loaded($ext)) {
        $ok[] = "Extensión {$ext}: cargada ✅";
    } else {
        $errors[] = "Extensión {$ext}: NO cargada ❌";
    }
}

// 3. Verificar archivos críticos existen
$files = [
    'includes/config.php',
    'includes/db.php',
    'includes/functions.php',
    'includes/auth.php',
    'templates/header.php',
    'templates/footer.php',
    'login.php',
    'index.php',
    'install.php',
];
foreach ($files as $f) {
    if (file_exists(__DIR__ . '/' . $f)) {
        $ok[] = "Archivo {$f}: existe ✅";
    } else {
        $errors[] = "Archivo {$f}: NO existe ❌";
    }
}

// 4. Verificar directorio data
$dataDir = __DIR__ . '/data';
if (!is_dir($dataDir)) {
    $warnings[] = "Directorio data/: no existe. Se creará automáticamente.";
} else {
    if (is_writable($dataDir)) {
        $ok[] = "Directorio data/: existe y escribible ✅";
    } else {
        $errors[] = "Directorio data/: existe pero NO escribible ❌";
    }
}

// 5. Verificar .htaccess
$htaccess = __DIR__ . '/.htaccess';
if (file_exists($htaccess)) {
    $content = file_get_contents($htaccess);
    if (str_contains($content, 'php_flag')) {
        $errors[] = ".htaccess contiene 'php_flag' — esto causa 500 en muchos hostings ❌";
    } else {
        $ok[] = ".htaccess: existe, sin php_flag ✅";
    }
} else {
    $warnings[] = ".htaccess: no existe";
}

// 6. Intentar cargar config.php y db.php
try {
    require_once __DIR__ . '/includes/config.php';
    $ok[] = "includes/config.php: carga OK ✅";
} catch (Throwable $e) {
    $errors[] = "includes/config.php: FALLA ❌ → " . $e->getMessage();
}

try {
    require_once __DIR__ . '/includes/db.php';
    $ok[] = "includes/db.php: carga OK ✅";
} catch (Throwable $e) {
    $errors[] = "includes/db.php: FALLA ❌ → " . $e->getMessage();
}

try {
    require_once __DIR__ . '/includes/functions.php';
    $ok[] = "includes/functions.php: carga OK ✅";
} catch (Throwable $e) {
    $errors[] = "includes/functions.php: FALLA ❌ → " . $e->getMessage();
}

// 7. Intentar conectar a la base de datos
try {
    if (class_exists('Database')) {
        $db = Database::getInstance();
        $ok[] = "SQLite: conexión OK ✅";
        
        // Verificar tablas
        $tables = $db->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(PDO::FETCH_COLUMN);
        if (in_array('users', $tables)) {
            $ok[] = "Tabla 'users': existe ✅";
        } else {
            $warnings[] = "Tabla 'users': NO existe → ejecuta install.php";
        }
        if (in_array('api_keys', $tables)) {
            $ok[] = "Tabla 'api_keys': existe ✅";
        } else {
            $warnings[] = "Tabla 'api_keys': NO existe → ejecuta install.php";
        }
        if (in_array('tasks', $tables)) {
            $ok[] = "Tabla 'tasks': existe ✅";
        } else {
            $warnings[] = "Tabla 'tasks': NO existe → ejecuta install.php";
        }
    } else {
        $errors[] = "Clase Database: no existe ❌";
    }
} catch (Throwable $e) {
    $errors[] = "SQLite: FALLA ❌ → " . $e->getMessage();
}

// 8. Verificar sesiones
try {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    $ok[] = "Sesiones: funcionan ✅";
} catch (Throwable $e) {
    $errors[] = "Sesiones: FALLA ❌ → " . $e->getMessage();
}

// 9. Intentar cargar auth.php (esto prueba session + funciones)
try {
    require_once __DIR__ . '/includes/auth.php';
    $ok[] = "includes/auth.php: carga OK ✅";
} catch (Throwable $e) {
    $errors[] = "includes/auth.php: FALLA ❌ → " . $e->getMessage();
}

// REPORTE
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Diagnóstico OrinSec</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; }
        h1 { color: #1a237e; }
        .box { border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
        .error { background: #ffebee; color: #c62828; }
        .warn { background: #fff3e0; color: #e65100; }
        .ok { background: #e8f5e9; color: #2e7d32; }
        code { background: #f5f5f5; padding: .2rem .4rem; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>🔧 Diagnóstico OrinSec</h1>
    
    <?php if (!empty($errors)): ?>
    <div class="box error">
        <h2>Errores (<?php echo count($errors); ?>)</h2>
        <?php foreach ($errors as $e): ?><p>❌ <?php echo htmlspecialchars($e); ?></p><?php endforeach; ?>
    </div>
    <?php endif; ?>
    
    <?php if (!empty($warnings)): ?>
    <div class="box warn">
        <h2>Advertencias (<?php echo count($warnings); ?>)</h2>
        <?php foreach ($warnings as $w): ?><p>⚠️ <?php echo htmlspecialchars($w); ?></p><?php endforeach; ?>
    </div>
    <?php endif; ?>
    
    <?php if (!empty($ok)): ?>
    <div class="box ok">
        <h2>OK (<?php echo count($ok); ?>)</h2>
        <?php foreach ($ok as $o): ?><p>✅ <?php echo htmlspecialchars($o); ?></p><?php endforeach; ?>
    </div>
    <?php endif; ?>
    
    <div class="box">
        <h2>Siguiente paso</h2>
        <?php if (!empty($errors)): ?>
            <p><strong>Corrige los errores marcados en rojo arriba.</strong></p>
            <p>Si el error es del .htaccess, renómbralo temporalmente a <code>.htaccess.bak</code> y recarga esta página.</p>
        <?php elseif (!empty($warnings)): ?>
            <p>Todo está bien. Ejecuta <a href="install.php"><code>install.php</code></a> para crear las tablas.</p>
        <?php else: ?>
            <p>Todo parece correcto. Prueba a entrar en <a href="login.php">login.php</a>.</p>
        <?php endif; ?>
    </div>
</body>
</html>
