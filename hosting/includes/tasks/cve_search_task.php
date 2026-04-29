<?php
declare(strict_types=1);

require_once __DIR__ . '/../virtual_worker.php';

/**
 * Versión PHP de la tarea CVE Search para ejecución vía VirtualWorker (API externa).
 */
class CveSearchTaskPhp {
    public function __construct(private VirtualWorker $worker) {}

    public function run(array $input): array {
        $cveId = trim((string)($input['cve_id'] ?? ''));
        if (!$cveId || !preg_match('/^CVE-\d{4}-\d+$/i', $cveId)) {
            throw new RuntimeException('CVE ID inválido');
        }
        $cveId = strtoupper($cveId);

        // 1. Enriquecer datos
        $enriched = $this->enrichCve($cveId);

        // 2. Generar informe con LLM
        $systemPrompt = $this->buildSystemPrompt();
        $userPrompt = json_encode($enriched, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

        $report = $this->worker->chat($systemPrompt, $userPrompt, [
            'temperature' => 0.2,
            'max_tokens'  => 4096,
        ]);

        // 3. Renderizar HTML
        $html = $this->renderHtml($enriched, $report);

        return [
            'result_html'     => $html,
            'result_text'     => $report,
            'cvss_base_score' => $enriched['cvss_score'],
            'cvss_severity'   => $enriched['severity'],
        ];
    }

    private function enrichCve(string $cveId): array {
        // NVD API
        $nvd = $this->fetchJson("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={$cveId}", 15);
        $item = $nvd['vulnerabilities'][0]['cve'] ?? null;

        $description = '';
        $cvssScore = null;
        $severity = null;
        $vector = null;
        $published = null;
        $modified = null;
        $references = [];

        if ($item) {
            foreach ($item['descriptions'] ?? [] as $d) {
                if (($d['lang'] ?? '') === 'en') {
                    $description = $d['value'];
                    break;
                }
            }
            $metrics = $item['metrics'] ?? [];
            $cvss = $metrics['cvssMetricV31'][0]['cvssData'] ?? ($metrics['cvssMetricV30'][0]['cvssData'] ?? null);
            if ($cvss) {
                $cvssScore = $cvss['baseScore'] ?? null;
                $severity  = $cvss['baseSeverity'] ?? null;
                $vector    = $cvss['vectorString'] ?? null;
            }
            $published = $item['published'] ?? null;
            $modified  = $item['lastModified'] ?? null;
            foreach ($item['references'] ?? [] as $r) {
                $references[] = $r['url'];
            }
        }

        // EPSS API
        $epssScore = null;
        $epssPercentile = null;
        try {
            $epss = $this->fetchJson("https://api.first.org/data/v1/epss?cve={$cveId}", 10);
            $epssData = $epss['data'][0] ?? null;
            if ($epssData) {
                $epssScore = (float)($epssData['epss'] ?? 0);
                $epssPercentile = (float)($epssData['percentile'] ?? 0);
            }
        } catch (Throwable $e) {
            // EPSS es opcional
        }

        return [
            'cve_id' => $cveId,
            'description' => $description,
            'cvss_score' => $cvssScore,
            'severity' => $severity,
            'vector' => $vector,
            'published' => $published,
            'modified' => $modified,
            'epss_score' => $epssScore,
            'epss_percentile' => $epssPercentile,
            'references' => array_slice($references, 0, 10),
        ];
    }

    private function fetchJson(string $url, int $timeout = 15): array {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_USERAGENT => 'OrinSec-VirtualWorker/1.0',
        ]);
        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($resp === false || $code >= 400) {
            throw new RuntimeException("HTTP {$code} en {$url}");
        }
        $data = json_decode($resp, true);
        if (!is_array($data)) {
            throw new RuntimeException('Respuesta no-JSON de ' . $url);
        }
        return $data;
    }

    private function buildSystemPrompt(): string {
        return "Eres un analista de ciberseguridad experto. Genera un informe en español sobre la vulnerabilidad proporcionada.\n\n" .
               "Estructura obligatoria (usa exactamente estos títulos en markdown):\n" .
               "## CONTEXTO\n" .
               "## IMPACTO\n" .
               "## RECOMENDACIONES\n" .
               "## NOTAS\n\n" .
               "Sé conciso (máximo 300 palabras). Usa markdown básico.";
    }

    private function mdToHtml(string $md): string {
        // Escapar HTML primero para seguridad
        $html = htmlspecialchars($md, ENT_NOQUOTES, 'UTF-8');

        // Convertir headers: ## Título → <h2>Título</h2>
        $html = preg_replace('/^#{2}\s+(.+)$/m', '<h2>$1</h2>', $html);
        $html = preg_replace('/^#{3}\s+(.+)$/m', '<h3>$1</h3>', $html);

        // Convertir negrita: **texto** → <strong>texto</strong>
        $html = preg_replace('/\*\*(.+?)\*\*/', '<strong>$1</strong>', $html);

        // Convertir cursiva: *texto* → <em>texto</em> (evitando los de listas)
        $html = preg_replace('/(?<!\s)\*(.+?)\*(?!\s)/', '<em>$1</em>', $html);

        // Convertir listas: - item o * item → <li>item</li>
        $html = preg_replace('/^[\-\*]\s+(.+)$/m', '<li>$1</li>', $html);

        // Doble salto de línea → nuevo párrafo
        $html = str_replace("\n\n", '</p><p>', $html);
        // Salto simple → <br>
        $html = str_replace("\n", '<br>', $html);

        // Envolver en párrafo si no empieza con tag de bloque
        if (!str_starts_with(trim($html), '<')) {
            $html = '<p>' . $html . '</p>';
        } else {
            $html = '<p>' . $html . '</p>';
        }

        // Corregir párrafos vacíos
        $html = str_replace('<p></p>', '', $html);
        $html = preg_replace('/<p>(<h[23]>)/', '$1', $html);
        $html = preg_replace('/(<\/h[23]>)<\/p>/', '$1', $html);
        $html = preg_replace('/<p>(<li>)/', '<ul>$1', $html);
        $html = preg_replace('/(<\/li>)<\/p>/', '$1</ul>', $html);

        return $html;
    }

    private function renderHtml(array $enriched, string $report): string {
        $cveId = htmlspecialchars($enriched['cve_id']);
        $severity = htmlspecialchars($enriched['severity'] ?? 'N/A');
        $cvss = $enriched['cvss_score'] !== null ? round((float)$enriched['cvss_score'], 1) : 'N/A';
        $epss = $enriched['epss_score'] !== null ? round((float)$enriched['epss_score'] * 100, 2) . '%' : 'N/A';
        $published = htmlspecialchars($enriched['published'] ?? 'N/A');

        $refs = '';
        foreach ($enriched['references'] as $r) {
            $refs .= '<li><a href="' . htmlspecialchars($r) . '" target="_blank">' . htmlspecialchars($r) . '</a></li>';
        }

        $bodyHtml = $this->mdToHtml($report);

        $html = <<<HTML
<div class="cve-report">
  <h3>{$cveId}</h3>
  <div class="cve-meta">
    <span class="badge">Severidad: {$severity}</span>
    <span class="badge">CVSS: {$cvss}</span>
    <span class="badge">EPSS: {$epss}</span>
    <span class="badge">Publicado: {$published}</span>
  </div>
  <div class="cve-body">
    {$bodyHtml}
  </div>
  <div class="cve-refs">
    <h4>Referencias</h4>
    <ul>{$refs}</ul>
  </div>
</div>
HTML;
        return $html;
    }
}
