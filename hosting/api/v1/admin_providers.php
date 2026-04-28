<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/../../includes/crypto.php';
require_once __DIR__ . '/../../includes/external_client.php';

header('Content-Type: application/json');

set_exception_handler(function ($e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    exit;
});

requireAdmin();

$action = $_GET['action'] ?? '';

switch ($action) {

    case 'list':
        $providers = Database::fetchAll(
            "SELECT id, name, label, base_url, api_key_hint, is_active, timeout_seconds
             FROM external_providers ORDER BY label"
        );
        $models = Database::fetchAll(
            "SELECT m.id, m.provider_id, m.model_id, m.label, m.context_window,
                    m.cost_per_1k_input, m.cost_per_1k_output, m.is_active
             FROM external_models m ORDER BY m.label"
        );
        jsonResponse(['success' => true, 'providers' => $providers, 'models' => $models]);
        break;

    case 'create_provider':
        $data = getJsonInput();
        $name = validateInput((string)($data['name'] ?? ''), 64, '/^[\w\-]+$/u');
        $label = validateInput((string)($data['label'] ?? ''), 100);
        $baseUrl = filter_var(trim((string)($data['base_url'] ?? '')), FILTER_VALIDATE_URL);
        $apiKey = (string)($data['api_key'] ?? '');
        $timeout = (int)($data['timeout_seconds'] ?? 60);
        if (!$name || !$label || !$baseUrl || $apiKey === '') {
            jsonResponse(['success' => false, 'error' => 'Campos requeridos inválidos'], 400);
        }
        $id = Database::insert('external_providers', [
            'name' => $name,
            'label' => $label,
            'base_url' => $baseUrl,
            'api_key_encrypted' => encryptApiKey($apiKey),
            'api_key_hint' => apiKeyHint($apiKey),
            'is_active' => !empty($data['is_active']) ? 1 : 0,
            'timeout_seconds' => max(10, min(300, $timeout)),
        ]);
        jsonResponse(['success' => true, 'id' => $id]);
        break;

    case 'update_provider':
        $data = getJsonInput();
        $id = (int)($data['id'] ?? 0);
        if ($id <= 0) jsonResponse(['success' => false, 'error' => 'ID requerido'], 400);
        $update = [];
        if (isset($data['label'])) {
            $label = validateInput((string)$data['label'], 100);
            if ($label) $update['label'] = $label;
        }
        if (isset($data['base_url'])) {
            $url = filter_var(trim((string)$data['base_url']), FILTER_VALIDATE_URL);
            if ($url) $update['base_url'] = $url;
        }
        if (isset($data['api_key']) && $data['api_key'] !== '') {
            $update['api_key_encrypted'] = encryptApiKey((string)$data['api_key']);
            $update['api_key_hint'] = apiKeyHint((string)$data['api_key']);
        }
        if (isset($data['is_active'])) {
            $update['is_active'] = !empty($data['is_active']) ? 1 : 0;
        }
        if (isset($data['timeout_seconds'])) {
            $update['timeout_seconds'] = max(10, min(300, (int)$data['timeout_seconds']));
        }
        if (empty($update)) jsonResponse(['success' => false, 'error' => 'Nada que actualizar'], 400);
        Database::update('external_providers', $update, 'id = ?', [$id]);
        jsonResponse(['success' => true]);
        break;

    case 'delete_provider':
        $data = getJsonInput();
        $id = (int)($data['id'] ?? 0);
        if ($id <= 0) jsonResponse(['success' => false, 'error' => 'ID requerido'], 400);
        Database::query("DELETE FROM external_providers WHERE id = ?", [$id]);
        jsonResponse(['success' => true]);
        break;

    case 'test_connection':
        $data = getJsonInput();
        $id = (int)($data['id'] ?? 0);
        if ($id <= 0) jsonResponse(['success' => false, 'error' => 'ID requerido'], 400);
        $provider = Database::fetchOne(
            "SELECT base_url, api_key_encrypted, timeout_seconds FROM external_providers WHERE id = ?",
            [$id]
        );
        if (!$provider) jsonResponse(['success' => false, 'error' => 'Proveedor no encontrado'], 404);
        $apiKey = decryptApiKey($provider['api_key_encrypted']);
        $url = rtrim($provider['base_url'], '/') . '/models';
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => (int)$provider['timeout_seconds'],
            CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $apiKey],
        ]);
        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($resp === false) {
            jsonResponse(['success' => false, 'error' => 'cURL: ' . $err]);
        }
        if ($code >= 400) {
            jsonResponse(['success' => false, 'error' => 'HTTP ' . $code]);
        }
        $data = json_decode($resp, true);
        $modelCount = is_array($data['data'] ?? null) ? count($data['data']) : (is_array($data) ? count($data) : 0);
        jsonResponse(['success' => true, 'models_available' => $modelCount]);
        break;

    case 'create_model':
        $data = getJsonInput();
        $providerId = (int)($data['provider_id'] ?? 0);
        $modelId = validateInput((string)($data['model_id'] ?? ''), 128);
        $label = validateInput((string)($data['label'] ?? ''), 128);
        if ($providerId <= 0 || !$modelId || !$label) {
            jsonResponse(['success' => false, 'error' => 'Campos requeridos inválidos'], 400);
        }
        $id = Database::insert('external_models', [
            'provider_id' => $providerId,
            'model_id' => $modelId,
            'label' => $label,
            'context_window' => (int)($data['context_window'] ?? 8192),
            'cost_per_1k_input' => is_numeric($data['cost_per_1k_input'] ?? null) ? (float)$data['cost_per_1k_input'] : null,
            'cost_per_1k_output' => is_numeric($data['cost_per_1k_output'] ?? null) ? (float)$data['cost_per_1k_output'] : null,
            'is_active' => !empty($data['is_active']) ? 1 : 0,
        ]);
        jsonResponse(['success' => true, 'id' => $id]);
        break;

    case 'update_model':
        $data = getJsonInput();
        $id = (int)($data['id'] ?? 0);
        if ($id <= 0) jsonResponse(['success' => false, 'error' => 'ID requerido'], 400);
        $update = [];
        if (isset($data['label'])) {
            $l = validateInput((string)$data['label'], 128);
            if ($l) $update['label'] = $l;
        }
        if (isset($data['context_window'])) $update['context_window'] = (int)$data['context_window'];
        if (isset($data['cost_per_1k_input'])) $update['cost_per_1k_input'] = is_numeric($data['cost_per_1k_input']) ? (float)$data['cost_per_1k_input'] : null;
        if (isset($data['cost_per_1k_output'])) $update['cost_per_1k_output'] = is_numeric($data['cost_per_1k_output']) ? (float)$data['cost_per_1k_output'] : null;
        if (isset($data['is_active'])) $update['is_active'] = !empty($data['is_active']) ? 1 : 0;
        if (empty($update)) jsonResponse(['success' => false, 'error' => 'Nada que actualizar'], 400);
        Database::update('external_models', $update, 'id = ?', [$id]);
        jsonResponse(['success' => true]);
        break;

    case 'delete_model':
        $data = getJsonInput();
        $id = (int)($data['id'] ?? 0);
        if ($id <= 0) jsonResponse(['success' => false, 'error' => 'ID requerido'], 400);
        Database::query("DELETE FROM external_models WHERE id = ?", [$id]);
        jsonResponse(['success' => true]);
        break;

    case 'usage_stats':
        $stats = Database::fetchAll(
            "SELECT p.label AS provider, m.label AS model,
                    SUM(u.tokens_input) AS in_tokens,
                    SUM(u.tokens_output) AS out_tokens,
                    SUM(u.cost_usd) AS cost_total,
                    COUNT(*) AS calls
             FROM external_usage u
             JOIN external_providers p ON p.id = u.provider_id
             LEFT JOIN external_models m ON m.provider_id = u.provider_id AND m.model_id = u.model_id
             WHERE u.created_at >= date('now', 'start of month')
             GROUP BY u.provider_id, u.model_id
             ORDER BY cost_total DESC"
        );
        jsonResponse(['success' => true, 'stats' => $stats]);
        break;

    default:
        jsonResponse(['success' => false, 'error' => 'Acción no válida'], 400);
}
