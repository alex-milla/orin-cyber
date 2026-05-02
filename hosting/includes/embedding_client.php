<?php
/**
 * Cliente PHP para el servicio de embeddings local.
 * Solo se usa desde endpoints que necesitan generar embeddings (feedback, enrich sync).
 */

class EmbeddingClient {
    private string $baseUrl;
    private int $timeout;

    public function __construct(?string $baseUrl = null, int $timeout = 10) {
        $this->baseUrl = $baseUrl ?? (defined('LOCAL_EMBED_URL') ? LOCAL_EMBED_URL : 'http://127.0.0.1:8081');
        $this->timeout = $timeout;
    }

    /**
     * @param array $texts
     * @return array<array<float>>
     */
    public function embed(array $texts): array {
        if (empty($texts)) return [];

        $ch = curl_init($this->baseUrl . '/v1/embeddings');
        $headers = [
            'Content-Type: application/json',
        ];

        // Cloudflare Access headers si están configuradas
        $cfId = function_exists('config') ? (config('cf_access_client_id') ?? '') : '';
        $cfSecret = function_exists('config') ? (config('cf_access_client_secret') ?? '') : '';
        if ($cfId) $headers[] = 'CF-Access-Client-Id: ' . $cfId;
        if ($cfSecret) $headers[] = 'CF-Access-Client-Secret: ' . $cfSecret;

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_POSTFIELDS => json_encode([
                'input' => $texts,
                'model' => 'local',
            ]),
        ]);

        $resp = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);

        if ($resp === false || $httpCode !== 200) {
            throw new RuntimeException("Embedding service failed (HTTP $httpCode): $err");
        }

        $data = json_decode($resp, true);
        if (!isset($data['data'])) {
            throw new RuntimeException("Invalid embedding response");
        }

        return array_map(fn($item) => $item['embedding'], $data['data']);
    }

    public function embedOne(string $text): array {
        $result = $this->embed([$text]);
        return $result[0] ?? [];
    }
}
