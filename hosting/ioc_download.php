<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

$token = $_GET['t'] ?? '';
if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
    http_response_code(403);
    echo 'Token inválido.';
    exit;
}

$file = $_GET['f'] ?? '';
if (!$file || preg_match('/\.\./', $file) || !preg_match('/^stix_[\w\-]+\.json$/', $file)) {
    http_response_code(400);
    echo 'Archivo no válido.';
    exit;
}

$filePath = DATA_DIR . '/ioc_output/' . basename($file);
if (!file_exists($filePath)) {
    http_response_code(404);
    echo 'Archivo no encontrado.';
    exit;
}

header('Content-Type: application/json');
header('Content-Disposition: attachment; filename="' . basename($file) . '"');
header('Content-Length: ' . filesize($filePath));
header('Cache-Control: no-cache, must-revalidate');
readfile($filePath);
exit;
