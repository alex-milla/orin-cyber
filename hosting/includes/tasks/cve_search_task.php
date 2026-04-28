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
            'result_html' => $html,
            'result_text' => $report,
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
        {$report}
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
