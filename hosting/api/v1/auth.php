<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';

/**
 * Valida la API key del worker contra la tabla api_keys.
 * Devuelve la fila de la key si es válida y activa, o termina la ejecución.
 */
function requireApiKey(): array {
    $headers = getallheaders();
    $apiKey = $headers[API_KEY_HEADER] ?? ($_SERVER['HTTP_X_API_KEY'] ?? '');
    
    if (empty($apiKey)) {
        http_response_code(401);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'API key requerida']);
        exit;
    }
    
    $row = Database::fetchOne(
        'SELECT id, name, api_key, is_active, last_used FROM api_keys WHERE api_key = ? AND is_active = 1',
        [$apiKey]
    );
    
    if (!$row) {
        http_response_code(403);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'API key inválida o revocada']);
        exit;
    }
    
    return $row;
}
