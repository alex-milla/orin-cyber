<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';

/**
 * Valida la API key del worker
 */
function requireApiKey(): void {
    $headers = getallheaders();
    $apiKey = $headers[API_KEY_HEADER] ?? ($_SERVER['HTTP_X_API_KEY'] ?? '');
    
    if (empty($apiKey)) {
        http_response_code(401);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'API key requerida']);
        exit;
    }
    
    $stored = Database::fetchOne(
        'SELECT value FROM config WHERE key = ?',
        ['api_key']
    );
    
    if (!$stored || !hash_equals($stored['value'], $apiKey)) {
        http_response_code(403);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'API key inválida']);
        exit;
    }
}
