<?php
error_reporting(E_ALL);
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');

header('Content-Type: text/plain; charset=utf-8');

echo "=== DIAGNOSTICO EXPORT_CVE ===\n\n";
echo "PHP version: " . PHP_VERSION . "\n";
echo "SAPI: " . PHP_SAPI . "\n";
echo "Document root: " . ($_SERVER['DOCUMENT_ROOT'] ?? 'N/A') . "\n";
echo "Script: " . __FILE__ . "\n\n";

// Verificar escritura en data/
echo "--- Escritura en data/ ---\n";
$dataDir = __DIR__ . '/data';
$testFile = $dataDir . '/diagnose_test_' . time() . '.txt';
$writeTest = @file_put_contents($testFile, 'test');
if ($writeTest !== false) {
    echo "OK: data/ es escribible\n";
    @unlink($testFile);
} else {
    echo "ERROR: No se puede escribir en data/\n";
}
echo "\n";

// Verificar includes uno por uno
$files = [
    'includes/config.php',
    'includes/db.php',
    'includes/functions.php',
    'includes/auth.php',
];

echo "--- Includes ---\n";
foreach ($files as $f) {
    $path = __DIR__ . '/' . $f;
    if (!file_exists($path)) {
        echo "MISSING: {$f}\n";
        continue;
    }
    
    $lastError = null;
    set_error_handler(function($errno, $errstr, $errfile, $errline) use (&$lastError) {
        $lastError = "[$errno] $errstr en $errfile:$errline";
        return true;
    });
    
    $result = @include $path;
    
    restore_error_handler();
    
    if ($lastError) {
        echo "ERROR en {$f}: {$lastError}\n";
    } else {
        echo "OK: {$f}\n";
    }
}
echo "\n";

// Verificar sintaxis de export_cve.php
echo "--- Sintaxis export_cve.php ---\n";
$exportFile = __DIR__ . '/export_cve.php';
if (!file_exists($exportFile)) {
    echo "MISSING: export_cve.php no existe\n";
} else {
    $content = file_get_contents($exportFile);
    echo "Tamaño: " . strlen($content) . " bytes\n";
    echo "Primeros 50 bytes (hex): " . bin2hex(substr($content, 0, 50)) . "\n";
    echo "Primeros 100 chars: " . substr($content, 0, 100) . "\n";
    
    // Intentar tokenizar
    $tokens = @token_get_all($content);
    if ($tokens === false) {
        echo "ERROR: token_get_all fallo\n";
    } else {
        $lastError = null;
        foreach ($tokens as $token) {
            if (is_array($token) && $token[0] === T_ERROR) {
                $lastError = "Error de sintaxis en linea {$token[2]}: {$token[1]}";
                break;
            }
        }
        if ($lastError) {
            echo "ERROR: {$lastError}\n";
        } else {
            echo "OK: No se detectaron errores de sintaxis via token_get_all\n";
        }
    }
    
    // Intentar include
    echo "\nIntentando include de export_cve.php...\n";
    $lastError = null;
    set_error_handler(function($errno, $errstr, $errfile, $errline) use (&$lastError) {
        $lastError = "[$errno] $errstr en $errfile:$errline";
        return true;
    });
    
    ob_start();
    $result = @include $exportFile;
    $output = ob_get_clean();
    
    restore_error_handler();
    
    if ($lastError) {
        echo "ERROR durante include: {$lastError}\n";
    } else {
        echo "OK: include exitoso\n";
    }
    if ($output) {
        echo "Output capturado: " . substr($output, 0, 500) . "\n";
    }
}
echo "\n";

// Verificar funciones criticas
echo "--- Funciones disponibles ---\n";
$funcs = ['json_decode', 'preg_replace', 'preg_split', 'explode', 'htmlspecialchars', 'file_get_contents', 'tempnam', 'class_exists'];
foreach ($funcs as $f) {
    echo ($f . ': ' . (function_exists($f) ? 'OK' : 'NO')) . "\n";
}
echo "ZipArchive: " . (class_exists('ZipArchive') ? 'OK' : 'NO') . "\n";

echo "\n=== FIN DIAGNOSTICO ===\n";
