<?php
declare(strict_types=1);

if (!function_exists('str_contains')) {
    function str_contains(string $haystack, string $needle): bool {
        return $needle === '' || strpos($haystack, $needle) !== false;
    }
}
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool {
        return strpos($haystack, $needle) === 0;
    }
}
if (!function_exists('str_ends_with')) {
    function str_ends_with(string $haystack, string $needle): bool {
        return $needle === '' || substr($haystack, -strlen($needle)) === $needle;
    }
}

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/external_client.php';

/**
 * Adaptador que simula la interfaz del LlmClient del worker Python,
 * pero ejecutando la inferencia contra un proveedor externo.
 *
 * Pensado para ser inyectado en clases de tarea PHP que vivan en el hosting.
 */
class VirtualWorker {
    private int $providerId;
    private string $modelId;
    private array $modelMeta;
    private ?int $userId;

    public function __construct(int $providerId, string $modelId, ?int $userId = null) {
        $this->providerId = $providerId;
        $this->modelId    = $modelId;
        $this->userId     = $userId;

        $row = Database::fetchOne(
            "SELECT m.context_window, m.cost_per_1k_input, m.cost_per_1k_output,
                    m.label, p.label AS provider_label, p.is_active AS provider_active, m.is_active AS model_active
             FROM external_models m
             JOIN external_providers p ON p.id = m.provider_id
             WHERE m.provider_id = ? AND m.model_id = ?",
            [$providerId, $modelId]
        );
        if (!$row) {
            throw new RuntimeException("Modelo {$modelId} no existe en proveedor {$providerId}");
        }
        if (!$row['provider_active'] || !$row['model_active']) {
            throw new RuntimeException("Modelo o proveedor desactivado");
        }
        $this->modelMeta = $row;
    }

    /**
     * Equivalente a LlmClient.chat() del worker Python.
     */
    public function chat(string $systemPrompt, string $userPrompt, array $opts = []): string {
        $messages = [
            ['role' => 'system', 'content' => $systemPrompt],
            ['role' => 'user',   'content' => $userPrompt],
        ];

        $result = ExternalClient::chat($this->providerId, $this->modelId, $messages, [
            'temperature' => $opts['temperature'] ?? 0.3,
            'max_tokens'  => $opts['max_tokens']  ?? 2048,
        ]);

        $this->logUsage($result);
        return $result['content'];
    }

    /**
     * Equivalente a LlmClient.chat_json() del worker Python.
     * Devuelve null si la respuesta no es JSON válido.
     */
    public function chatJson(string $systemPrompt, string $userPrompt, array $opts = []): ?array {
        $raw = $this->chat($systemPrompt, $userPrompt, $opts);

        $content = $raw;
        if (str_contains($content, '```json')) {
            $parts = explode('```json', $content, 2);
            $content = explode('```', $parts[1], 2)[0];
        } elseif (str_contains($content, '```')) {
            $parts = explode('```', $content, 2);
            $content = explode('```', $parts[1] ?? '', 2)[0];
        }

        $content = trim($content);
        $parsed = json_decode($content, true);
        return is_array($parsed) ? $parsed : null;
    }

    /**
     * Persiste el uso (tokens, coste, duración) en external_usage.
     */
    private function logUsage(array $result): void {
        $usage    = $result['usage'] ?? [];
        $tokensIn  = (int)($usage['prompt_tokens']     ?? 0);
        $tokensOut = (int)($usage['completion_tokens'] ?? 0);

        $cost = null;
        if ($this->modelMeta['cost_per_1k_input'] !== null
            && $this->modelMeta['cost_per_1k_output'] !== null) {
            $cost = ($tokensIn  / 1000) * (float)$this->modelMeta['cost_per_1k_input']
                  + ($tokensOut / 1000) * (float)$this->modelMeta['cost_per_1k_output'];
        }

        Database::insert('external_usage', [
            'user_id'       => $this->userId ?? 0,
            'provider_id'   => $this->providerId,
            'model_id'      => $this->modelId,
            'tokens_input'  => $tokensIn,
            'tokens_output' => $tokensOut,
            'cost_usd'      => $cost,
            'duration_ms'   => $result['duration_ms'] ?? 0,
        ]);
    }

    public function getModelLabel(): string { return $this->modelMeta['label']; }
    public function getModelId(): string { return $this->modelId; }
    public function getProviderLabel(): string { return $this->modelMeta['provider_label'] ?? 'Desconocido'; }
    public function getContextWindow(): int { return (int)$this->modelMeta['context_window']; }
}
