<?php
declare(strict_types=1);

class UrlFetcher {
    private const MAX_BYTES = 200_000;       // 200KB max por URL
    private const TIMEOUT = 10;              // 10s
    private const MAX_URLS_PER_MSG = 3;      // No saturar contexto
    private const ALLOWED_SCHEMES = ['http', 'https'];

    /** Extrae URLs de un texto. */
    public static function extractUrls(string $text): array {
        preg_match_all('#https?://[^\s<>"\']+#i', $text, $m);
        return array_slice(array_unique($m[0]), 0, self::MAX_URLS_PER_MSG);
    }

    /** Fetch + texto plano. Devuelve array o null si falla. */
    public static function fetch(string $url): ?array {
        $parts = parse_url($url);
        if (!$parts || !in_array($parts['scheme'] ?? '', self::ALLOWED_SCHEMES, true)) {
            return null;
        }
        // Evitar SSRF: bloquear IPs privadas básicas
        $host = $parts['host'] ?? '';
        if (self::isPrivateHost($host)) return null;

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_TIMEOUT => self::TIMEOUT,
            CURLOPT_USERAGENT => 'OrinSec-Fetch/1.0',
            CURLOPT_RANGE => '0-' . self::MAX_BYTES,
        ]);
        $body = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        curl_close($ch);

        if ($body === false || $code >= 400) return null;

        // Solo HTML/text/JSON/XML
        if (!preg_match('#text/|application/json|application/xml#i', (string)$type)) {
            return null;
        }

        $text = self::htmlToText((string)$body);
        return [
            'url' => $url,
            'title' => self::extractTitle((string)$body),
            'text' => mb_substr($text, 0, 8000),  // ~2000 tokens max por URL
        ];
    }

    private static function isPrivateHost(string $host): bool {
        if ($host === 'localhost' || $host === '127.0.0.1' || $host === '::1') return true;
        $ip = filter_var($host, FILTER_VALIDATE_IP) ? $host : gethostbyname($host);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
        return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    private static function extractTitle(string $html): string {
        if (preg_match('#<title[^>]*>(.*?)</title>#is', $html, $m)) {
            return trim(html_entity_decode(strip_tags($m[1]), ENT_QUOTES, 'UTF-8'));
        }
        return '';
    }

    private static function htmlToText(string $html): string {
        // Quitar script, style, nav, footer, aside
        $html = preg_replace('#<(script|style|nav|footer|aside)[^>]*>.*?</\1>#is', ' ', $html);
        // Quitar tags
        $text = strip_tags((string)$html);
        // Decodificar entidades
        $text = html_entity_decode($text, ENT_QUOTES, 'UTF-8');
        // Colapsar espacios
        $text = preg_replace('/\s+/u', ' ', $text);
        return trim((string)$text);
    }
}
