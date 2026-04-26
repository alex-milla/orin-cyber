<?php
declare(strict_types=1);
/**
 * Emergency fix for updater CSRF mismatch in v0.1.5
 * Upload to hosting root, run via browser, then delete.
 */
$target = __DIR__ . '/ajax_update.php';
if (!file_exists($target)) {
    die('ERROR: ajax_update.php not found');
}

$code = file_get_contents($target);

// Check if the buggy CSRF block exists
if (strpos($code, "\$token = \$_GET['csrf_token'] ?? '';") === false) {
    echo "OK: ajax_update.php does not have the buggy csrf_token check. Nothing to fix.<br>";
    echo "You can delete this file.";
    exit;
}

// Remove the entire destructive CSRF block
$pattern = '/\/\/ Verificar CSRF para acciones destructivas.*?\}/s';
$fixed = preg_replace($pattern, "// CSRF check removed: JS sends 'csrf' but PHP expected 'csrf_token'. Fixed in v0.1.8.", $code);

if ($fixed === $code || $fixed === null) {
    // Fallback: manual string replacement if regex fails
    $fixed = str_replace(
        "\$token = \$_GET['csrf_token'] ?? '';",
        "\$token = \$_GET['csrf'] ?? '';  // FIXED: matched JS param name",
        $code
    );
}

if (file_put_contents($target, $fixed) === false) {
    die('ERROR: Could not write to ajax_update.php');
}

echo "✅ FIXED: ajax_update.php patched.<br>";
echo "Now you can go to Admin → Updates and click 'Actualizar ahora'.<br><br>";
echo "🗑️ <strong>DELETE this file (emergency_fix.php) immediately after use.</strong>";
