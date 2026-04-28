<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/external_client.php';
require_once __DIR__ . '/../../includes/functions.php';

header('Content-Type: application/json');

set_exception_handler(function ($e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    exit;
});

requireAuth();

$method = $_SERVER['REQUEST_METHOD'];

// Rate limit por IP para chat externo (proteger contra costes)
checkRateLimit(2);

if ($method === 'POST') {
    $data = getJsonInput();
    $providerId = (int)($data['provider_id'] ?? 0);
    $modelId = (string)($data['model_id'] ?? '');
    $message = trim((string)($data['message'] ?? ''));
    $convId = (int)($data['conversation_id'] ?? 0);
    $systemPrompt = (string)($data['system_prompt'] ?? '');

    if ($providerId <= 0 || $modelId === '' || $message === '') {
        jsonResponse(['success' => false, 'error' => 'Faltan campos requeridos'], 400);
    }

    // Validar que el modelo está activo y pertenece al proveedor
    $modelRow = Database::fetchOne(
        "SELECT m.id, m.model_id, m.context_window, m.cost_per_1k_input, m.cost_per_1k_output,
                p.name AS provider_name
         FROM external_models m
         JOIN external_providers p ON p.id = m.provider_id
         WHERE m.provider_id = ? AND m.model_id = ? AND m.is_active = 1 AND p.is_active = 1",
        [$providerId, $modelId]
    );
    if (!$modelRow) {
        jsonResponse(['success' => false, 'error' => 'Modelo no disponible'], 404);
    }

    // Presupuesto mensual por usuario
    $userRow = Database::fetchOne(
        "SELECT monthly_external_budget_usd FROM users WHERE id = ?",
        [$_SESSION['user_id']]
    );
    $budget = (float)($userRow['monthly_external_budget_usd'] ?? 5.0);

    $spent = Database::fetchOne(
        "SELECT COALESCE(SUM(cost_usd), 0) AS total
         FROM external_usage
         WHERE user_id = ? AND created_at >= date('now','start of month')",
        [$_SESSION['user_id']]
    );
    $spentTotal = (float)($spent['total'] ?? 0.0);
    if ($spentTotal >= $budget) {
        jsonResponse(['success' => false, 'error' => 'Presupuesto mensual agotado'], 402);
    }

    // Conversación
    if ($convId <= 0) {
        $convId = Database::insert('chat_conversations', [
            'user_id' => $_SESSION['user_id'],
            'title' => mb_substr($message, 0, 60),
            'system_prompt' => $systemPrompt ?: null,
        ]);
    } else {
        $own = Database::fetchOne(
            "SELECT id FROM chat_conversations WHERE id = ? AND user_id = ?",
            [$convId, $_SESSION['user_id']]
        );
        if (!$own) jsonResponse(['success' => false, 'error' => 'Conversación no encontrada'], 404);
    }

    // Guardar mensaje del usuario
    Database::insert('chat_messages', [
        'conversation_id' => $convId,
        'role' => 'user',
        'content' => $message,
    ]);

    // Recuperar historial (últimos 20)
    $history = Database::fetchAll(
        "SELECT role, content FROM chat_messages
         WHERE conversation_id = ?
         ORDER BY created_at DESC LIMIT 20",
        [$convId]
    );
    $history = array_reverse($history);

    // Construir messages OpenAI-style
    $messages = [];
    if ($systemPrompt) {
        $messages[] = ['role' => 'system', 'content' => $systemPrompt];
    } else {
        $messages[] = ['role' => 'system',
            'content' => 'Eres un asistente útil y conciso. Responde en el idioma del usuario.'];
    }
    foreach ($history as $h) {
        $messages[] = ['role' => $h['role'], 'content' => $h['content']];
    }

    // Llamada síncrona al proveedor
    $result = ExternalClient::chat($providerId, $modelId, $messages, [
        'temperature' => 0.3,
        'max_tokens' => 2048,
    ]);

    // Persistir respuesta
    Database::insert('chat_messages', [
        'conversation_id' => $convId,
        'role' => 'assistant',
        'content' => $result['content'],
    ]);

    // Persistir uso
    $usage = $result['usage'];
    $tokensIn = (int)($usage['prompt_tokens'] ?? 0);
    $tokensOut = (int)($usage['completion_tokens'] ?? 0);
    $cost = null;
    if ($modelRow['cost_per_1k_input'] && $modelRow['cost_per_1k_output']) {
        $cost = ($tokensIn / 1000) * (float)$modelRow['cost_per_1k_input']
              + ($tokensOut / 1000) * (float)$modelRow['cost_per_1k_output'];
    }
    Database::insert('external_usage', [
        'user_id' => $_SESSION['user_id'],
        'provider_id' => $providerId,
        'model_id' => $modelId,
        'tokens_input' => $tokensIn,
        'tokens_output' => $tokensOut,
        'cost_usd' => $cost,
        'duration_ms' => $result['duration_ms'],
    ]);

    Database::update('chat_conversations',
        ['updated_at' => date('Y-m-d H:i:s')],
        'id = ?', [$convId]);

    jsonResponse([
        'success' => true,
        'response' => $result['content'],
        'conversation_id' => $convId,
        'usage' => $usage,
        'duration_ms' => $result['duration_ms'],
    ]);
}

// GET: listar proveedores y modelos disponibles para el dropdown
if ($method === 'GET') {
    $providers = Database::fetchAll(
        "SELECT id, name, label FROM external_providers WHERE is_active = 1 ORDER BY label"
    );
    $models = Database::fetchAll(
        "SELECT m.id, m.provider_id, m.model_id, m.label, m.context_window
         FROM external_models m
         JOIN external_providers p ON p.id = m.provider_id
         WHERE m.is_active = 1 AND p.is_active = 1
         ORDER BY p.label, m.label"
    );
    jsonResponse([
        'success' => true,
        'providers' => $providers,
        'models' => $models,
    ]);
}

jsonResponse(['success' => false, 'error' => 'Método no permitido'], 405);
