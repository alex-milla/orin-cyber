<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/external_client.php';
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/../../includes/url_fetcher.php';

header('Content-Type: application/json');

/**
 * Llama al llama-server (OpenAI-compatible).
 * Lee la URL desde config('local_llm_url'). Si no existe, fallback a localhost:8080.
 * Soporta Cloudflare Access via config('local_llm_cf_client_id' + 'local_llm_cf_client_secret').
 */
function chatLocal(array $messages, string $modelId): array {
    $url = rtrim(getLocalLlmUrl(), '/') . '/v1/chat/completions';

    $payload = [
        'model' => $modelId,
        'messages' => $messages,
        'temperature' => 0.3,
        'max_tokens' => 2048,
    ];

    $headers = ['Content-Type: application/json'];

    // Cloudflare Access (Zero Trust) service tokens
    $cfId = Database::fetchOne("SELECT value FROM config WHERE key = 'local_llm_cf_client_id'");
    $cfSecret = Database::fetchOne("SELECT value FROM config WHERE key = 'local_llm_cf_client_secret'");
    if (!empty($cfId['value'])) {
        $headers[] = 'CF-Access-Client-Id: ' . $cfId['value'];
    }
    if (!empty($cfSecret['value'])) {
        $headers[] = 'CF-Access-Client-Secret: ' . $cfSecret['value'];
    }

    $start = microtime(true);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 300,
        CURLOPT_POSTFIELDS => json_encode($payload),
        CURLOPT_HTTPHEADER => $headers,
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    $durationMs = (int)((microtime(true) - $start) * 1000);

    if ($response === false) {
        throw new RuntimeException("cURL error: {$curlError}");
    }
    if ($httpCode >= 400) {
        $errData = json_decode($response, true);
        $msg = $errData['error']['message'] ?? "HTTP {$httpCode}";
        throw new RuntimeException("llama-server devolvió error: {$msg}");
    }

    $data = json_decode($response, true);
    if (!is_array($data)) {
        throw new RuntimeException('Respuesta no es JSON válido');
    }

    $content = $data['choices'][0]['message']['content'] ?? '';
    $usage = $data['usage'] ?? ['prompt_tokens' => 0, 'completion_tokens' => 0];

    return [
        'content' => $content,
        'usage' => $usage,
        'duration_ms' => $durationMs,
        'provider_name' => 'Orin Local',
    ];
}

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

    // ── Enriquecer con URLs si las hay ────────────────────────────────────
    $urls = UrlFetcher::extractUrls($message);
    $urlContext = '';
    if (!empty($urls)) {
        $blocks = [];
        foreach ($urls as $u) {
            $fetched = UrlFetcher::fetch($u);
            if ($fetched) {
                $blocks[] = sprintf(
                    "[CONTENIDO DE %s — %s]\n%s",
                    $fetched['url'],
                    $fetched['title'] ?: '(sin título)',
                    $fetched['text']
                );
            } else {
                $blocks[] = sprintf("[%s — no se pudo acceder]", $u);
            }
        }
        $urlContext = "\n\n--- CONTEXTO DE URLS PROPORCIONADAS ---\n"
                      . implode("\n\n", $blocks)
                      . "\n--- FIN CONTEXTO ---\n";
    }
    $messageWithContext = $message . $urlContext;

    if ($providerId < 0 || $modelId === '' || $message === '') {
        jsonResponse(['success' => false, 'error' => 'Faltan campos requeridos'], 400);
    }

    // ── Proveedor local (Orin) — id=0, no está en BD ────────────────────
    $isLocalProvider = ($providerId === 0);
    if ($isLocalProvider) {
        $modelRow = [
            'id' => 0,
            'model_id' => $modelId,
            'provider_name' => 'Orin Local',
            'cost_per_1k_input' => null,
            'cost_per_1k_output' => null,
        ];
    } else {
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
    }

    // Presupuesto mensual por usuario (solo para proveedores externos)
    $budget = PHP_FLOAT_MAX;
    if (!$isLocalProvider) {
        $userRow = Database::fetchOne(
            "SELECT monthly_external_budget_usd FROM users WHERE id = ?",
            [$_SESSION['user_id']]
        );
        $budget = (float)($userRow['monthly_external_budget_usd'] ?? 5.0);
    }

    $spent = Database::fetchOne(
        "SELECT COALESCE(SUM(cost_usd), 0) AS total
         FROM external_usage
         WHERE user_id = ? AND created_at >= date('now','start of month')",
        [$_SESSION['user_id']]
    );
    $spentTotal = (float)($spent['total'] ?? 0.0);
    if (!$isLocalProvider && $spentTotal >= $budget) {
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
        $content = $h['content'];
        // El último mensaje del usuario es el actual: inyectar contexto de URLs
        if ($h['role'] === 'user') {
            $content = $messageWithContext;
        }
        $messages[] = ['role' => $h['role'], 'content' => $content];
    }

    // Llamada síncrona al proveedor (local o externo)
    if ($isLocalProvider) {
        $result = chatLocal($messages, $modelId);
    } else {
        $result = ExternalClient::chat($providerId, $modelId, $messages, [
            'temperature' => 0.3,
            'max_tokens' => 2048,
        ]);
    }

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
    // Añadir proveedor local (Orin) hardcodeado
    $localModel = Database::fetchOne(
        "SELECT model_loaded FROM worker_heartbeats ORDER BY created_at DESC LIMIT 1"
    );
    $localModelId = ($localModel['model_loaded'] ?? null) ?: 'local-model';
    array_unshift($providers, [
        'id' => 0,
        'name' => 'orin-local',
        'label' => '🏠 Orin Local',
    ]);
    array_unshift($models, [
        'id' => 0,
        'provider_id' => 0,
        'model_id' => $localModelId,
        'label' => $localModelId,
        'context_window' => 4096,
    ]);
    jsonResponse([
        'success' => true,
        'providers' => $providers,
        'models' => $models,
    ]);
}

jsonResponse(['success' => false, 'error' => 'Método no permitido'], 405);
