<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/crypto.php';

class ExternalClient {

    /**
     * Llama a un proveedor compatible con OpenAI Chat Completions (síncrono).
     */
    public static function chat(int $providerId, string $modelId, array $messages, array $opts = []): array {
        $provider = Database::fetchOne(
            "SELECT id, name, base_url, api_key_encrypted, timeout_seconds, is_active
             FROM external_providers WHERE id = ?",
            [$providerId]
        );
        if (!$provider) throw new RuntimeException('Proveedor no encontrado');
        if (!$provider['is_active']) throw new RuntimeException('Proveedor desactivado');

        $apiKey = decryptApiKey($provider['api_key_encrypted']);
        $url = rtrim($provider['base_url'], '/') . '/chat/completions';

        $payload = [
            'model' => $modelId,
            'messages' => $messages,
            'temperature' => $opts['temperature'] ?? 0.3,
            'max_tokens' => $opts['max_tokens'] ?? 2048,
        ];

        $start = microtime(true);
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => (int)$provider['timeout_seconds'],
            CURLOPT_POSTFIELDS => json_encode($payload),
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $apiKey,
                'HTTP-Referer: https://orin.cyberintelligence.dev',
                'X-Title: OrinSec',
            ],
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
            throw new RuntimeException("Proveedor devolvió error: {$msg}");
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
            'provider_name' => $provider['name'],
        ];
    }
}
