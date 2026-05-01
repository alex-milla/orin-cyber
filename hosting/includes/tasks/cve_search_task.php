<?php
declare(strict_types=1);

require_once __DIR__ . '/../virtual_worker.php';

/**
 * Versión PHP de la tarea CVE Search para ejecución vía VirtualWorker (API externa).
 * Paridad con worker Python: el CÓDIGO genera la estructura box-drawing determinística.
 * El LLM solo aporta el análisis de riesgo.
 */
class CveSearchTaskPhp {
    public function __construct(private VirtualWorker $worker) {}

    public function run(array $input): array {
        $cveId = trim((string)($input['cve_id'] ?? ''));
        if (!$cveId || !preg_match('/^CVE-\d{4}-\d+$/i', $cveId)) {
            throw new RuntimeException('CVE ID inválido');
        }
        $cveId = strtoupper($cveId);
        $language = strtolower(trim((string)($input['language'] ?? 'es')));
        if (!in_array($language, ['es', 'en'], true)) {
            $language = 'es';
        }

        // 1. Enriquecer datos
        $enriched = $this->enrichCve($cveId, $language);

        // 2. Pedir al LLM SOLO el análisis de riesgo
        $customTemplate = trim((string)($input['template'] ?? ''));
        $llmAnalysis = $this->getLlmAnalysis($enriched, $language, $customTemplate);

        // 3. Construir reporte box-drawing determinístico
        $reportText = $this->buildBoxDrawingReport($enriched, $language, $llmAnalysis);

        // 4. Renderizar HTML
        $html = $this->renderHtml($reportText, $enriched);

        return [
            'result_html'     => $html,
            'result_text'     => $reportText,
            'cvss_base_score' => $enriched['cvss_score'],
            'cvss_severity'   => $enriched['severity'],
        ];
    }

    // ─────────────────────────────────────────────────────────────────────
    // Enrichment
    // ─────────────────────────────────────────────────────────────────────

    private function enrichCve(string $cveId, string $language): array {
        // CVE.org (canónico)
        $cveOrg = $this->fetchCveOrg($cveId);

        // Fallback a NVD
        $nvdData = null;
        if (!$cveOrg) {
            $nvdData = $this->fetchNvd($cveId);
            if ($nvdData) {
                $cveOrg = [
                    'cve_id' => $nvdData['cve_id'],
                    'state' => 'PUBLISHED',
                    'published' => substr($nvdData['published'] ?? '', 0, 10),
                    'updated' => '',
                    'assigner' => '',
                    'descriptions' => ['en' => $nvdData['description'] ?? ''],
                    'description_en' => $nvdData['description'] ?? '',
                    'description_es' => '',
                    'affected' => [],
                    'references' => $nvdData['references'] ?? [],
                    'metrics_cna' => null,
                    'cwes' => [],
                ];
            }
        }

        if (!$cveOrg) {
            throw new RuntimeException("CVE {$cveId} no encontrado en fuentes oficiales");
        }

        // NVD enrichment
        $nvdEnrich = $this->fetchNvdEnrichment($cveId);

        // Fusionar referencias
        $refs = array_merge($cveOrg['references'] ?? [], $nvdEnrich['references'] ?? []);
        $refs = array_values(array_unique($refs));

        // Descripción según idioma
        if ($language === 'es') {
            $description = $cveOrg['description_es'] ?: ($cveOrg['description_en'] ?: 'Sin descripción');
        } else {
            $description = $cveOrg['description_en'] ?: ($cveOrg['description_es'] ?: 'No description');
        }

        // CVSS
        $score = $severity = $vector = $cvssVersion = null;
        if (!empty($cveOrg['metrics_cna'])) {
            $score = $cveOrg['metrics_cna']['base_score'] ?? null;
            $severity = $cveOrg['metrics_cna']['base_severity'] ?? null;
            $vector = $cveOrg['metrics_cna']['vector_string'] ?? null;
            $cvssVersion = $cveOrg['metrics_cna']['version'] ?? null;
        } elseif ($nvdEnrich) {
            $score = $nvdEnrich['cvss_score'] ?? null;
            $severity = $nvdEnrich['severity'] ?? null;
            $vector = $nvdEnrich['vector'] ?? null;
            $cvssVersion = $nvdEnrich['cvss_version'] ?? null;
        }

        // EPSS, KEV, GitHub
        $epss = $this->fetchEpss($cveId);
        $kev = $this->fetchKev($cveId);
        $github = $this->fetchGithubExploits($cveId);

        $priority = $this->calcPriority($score, $epss['score'] ?? null, $kev !== null);

        return [
            'cve_id' => $cveId,
            'state' => $cveOrg['state'] ?? 'UNKNOWN',
            'published' => $cveOrg['published'] ?? '',
            'updated' => $cveOrg['updated'] ?? '',
            'assigner' => $cveOrg['assigner'] ?? '',
            'description' => $description,
            'description_en' => $cveOrg['description_en'] ?? '',
            'description_es' => $cveOrg['description_es'] ?? '',
            'affected' => $cveOrg['affected'] ?? [],
            'references' => array_slice($refs, 0, 10),
            'cwes' => $cveOrg['cwes'] ?? ($nvdEnrich['cwes'] ?? []),
            'cpes' => $nvdEnrich['cpes'] ?? [],
            'cvss_score' => $score,
            'severity' => $severity ?: 'N/A',
            'vector' => $vector ?: 'N/A',
            'cvss_version' => $cvssVersion ?: '',
            'epss' => $epss,
            'kev' => $kev,
            'github' => $github,
            'priority' => $priority,
        ];
    }

    private function getLlmAnalysis(array $enriched, string $language, string $customTemplate = ''): string {
        $cve = $enriched;
        $epss = $enriched['epss'];
        $kev = $enriched['kev'];
        $github = $enriched['github'];

        $cveId = $cve['cve_id'];
        $desc = $cve['description'];
        $vector = $cve['vector'];
        $epssStr = $epss ? "{$epss['score_percent']}%" : 'N/A';
        $kevStr = $kev ? 'YES' : 'NO';
        $exploitCount = $github ? count($github) : 0;

        if ($customTemplate) {
            $systemPrompt = $customTemplate;
        } elseif ($language === 'es') {
            $systemPrompt = "Eres un analista senior de ciberseguridad. Responde de forma concisa y técnica.";
        } else {
            $systemPrompt = "You are a senior cybersecurity analyst. Respond concisely and technically.";
        }

        if ($language === 'es') {
            $userPrompt = (
                "Genera un análisis de riesgo técnico conciso para la vulnerabilidad {$cveId}.\n\n"
                . "DATOS DE REFERENCIA (NO repitas estos valores en tu análisis):\n"
                . "- Descripción: " . substr($desc, 0, 400) . "\n"
                . "- Vector: {$vector}\n"
                . "- EPSS: {$epssStr}\n"
                . "- CISA KEV: {$kevStr}\n"
                . "- Exploits públicos: {$exploitCount}\n\n"
                . "REGLAS:\n"
                . "1. Máximo 150 palabras.\n"
                . "2. NO repitas el score CVSS, la severidad, el EPSS ni el estado KEV.\n"
                . "3. NO inventes versiones de parche ni fechas.\n"
                . "4. Enfócate en: vector de explotación real, condiciones necesarias, impacto para la organización.\n"
                . "5. Usa [INFERIDO] solo para consecuencias lógicas obvias.\n"
                . "6. Responde en español.\n\n"
                . "Escribe SOLO el párrafo de análisis, sin títulos ni formato adicional."
            );
        } else {
            $userPrompt = (
                "Generate a concise technical risk analysis for vulnerability {$cveId}.\n\n"
                . "REFERENCE DATA (DO NOT repeat these values in your analysis):\n"
                . "- Description: " . substr($desc, 0, 400) . "\n"
                . "- Vector: {$vector}\n"
                . "- EPSS: {$epssStr}\n"
                . "- CISA KEV: {$kevStr}\n"
                . "- Public exploits: {$exploitCount}\n\n"
                . "RULES:\n"
                . "1. Maximum 150 words.\n"
                . "2. DO NOT repeat CVSS score, severity, EPSS or KEV status.\n"
                . "3. DO NOT invent patch versions or dates.\n"
                . "4. Focus on: real exploitation vector, required conditions, organizational impact.\n"
                . "5. Use [INFERRED] only for obvious logical consequences.\n"
                . "6. Respond in English.\n\n"
                . "Write ONLY the analysis paragraph, no titles or additional formatting."
            );
        }

        try {
            $analysis = $this->worker->chat($systemPrompt, $userPrompt, [
                'temperature' => 0.2,
                'max_tokens'  => 2048,
            ]);
            return trim($analysis);
        } catch (Throwable $e) {
            return '';
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Scrapers
    // ─────────────────────────────────────────────────────────────────────

    private function fetchCveOrg(string $cveId): ?array {
        $url = "https://cveawg.mitre.org/api/cve/{$cveId}";
        $data = $this->fetchJson($url, 20);
        if (!$data) return null;

        $meta = $data['cveMetadata'] ?? [];
        $containers = $data['containers'] ?? [];
        $cna = $containers['cna'] ?? [];

        $descriptions = [];
        foreach ($cna['descriptions'] ?? [] as $d) {
            $lang = $d['lang'] ?? 'en';
            $val = trim($d['value'] ?? '');
            if ($val) $descriptions[$lang] = $val;
        }
        if (empty($descriptions)) {
            foreach ($containers['adp'] ?? [] as $adp) {
                foreach ($adp['descriptions'] ?? [] as $d) {
                    $lang = $d['lang'] ?? 'en';
                    $val = trim($d['value'] ?? '');
                    if ($val) $descriptions[$lang] = $val;
                }
            }
        }

        $affected = [];
        foreach ($cna['affected'] ?? [] as $entry) {
            $versions = [];
            foreach ($entry['versions'] ?? [] as $v) {
                $status = $v['status'] ?? '';
                $version = $v['version'] ?? '';
                $lessThan = $v['lessThan'] ?? '';
                $versions[] = $lessThan ? "{$version} < {$lessThan} ({$status})" : "{$version} ({$status})";
            }
            $affected[] = [
                'vendor' => $entry['vendor'] ?? 'Unknown',
                'product' => $entry['product'] ?? 'Unknown',
                'versions' => $versions,
                'cpes' => array_slice($entry['cpes'] ?? [], 0, 5),
                'default_status' => $entry['defaultStatus'] ?? '',
            ];
        }

        $metricsCna = null;
        foreach ($cna['metrics'] ?? [] as $m) {
            foreach (['cvssV3_1', 'cvssV3_0', 'cvssV4_0'] as $key) {
                if (!empty($m[$key]['baseScore'])) {
                    $metricsCna = [
                        'version' => $m[$key]['version'] ?? str_replace(['cvssV','_'], ['','.'], $key),
                        'base_score' => $m[$key]['baseScore'],
                        'base_severity' => $m[$key]['baseSeverity'] ?? '',
                        'vector_string' => $m[$key]['vectorString'] ?? '',
                    ];
                    break 2;
                }
            }
        }

        $cwes = [];
        foreach ($cna['problemTypes'] ?? [] as $pt) {
            foreach ($pt['descriptions'] ?? [] as $d) {
                $cwe = trim($d['cweId'] ?? '');
                if ($cwe && !in_array($cwe, $cwes, true)) $cwes[] = $cwe;
            }
        }

        $refs = [];
        foreach ($cna['references'] ?? [] as $r) {
            $url = trim($r['url'] ?? '');
            if ($url && !in_array($url, $refs, true)) $refs[] = $url;
        }

        return [
            'cve_id' => $meta['cveId'] ?? $cveId,
            'state' => $meta['state'] ?? 'UNKNOWN',
            'published' => substr($meta['datePublished'] ?? '', 0, 10),
            'updated' => substr($meta['dateUpdated'] ?? '', 0, 10),
            'assigner' => $meta['assignerShortName'] ?? '',
            'descriptions' => $descriptions,
            'description_en' => $descriptions['en'] ?? '',
            'description_es' => $descriptions['es'] ?? '',
            'affected' => $affected,
            'references' => $refs,
            'metrics_cna' => $metricsCna,
            'cwes' => $cwes,
        ];
    }

    private function fetchNvd(string $cveId): ?array {
        $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={$cveId}";
        $data = $this->fetchJson($url, 15);
        if (!$data || empty($data['vulnerabilities'][0]['cve'])) return null;
        $item = $data['vulnerabilities'][0]['cve'];

        $description = '';
        foreach ($item['descriptions'] ?? [] as $d) {
            if (($d['lang'] ?? '') === 'en') { $description = $d['value']; break; }
        }

        $metrics = $item['metrics'] ?? [];
        $cvss = $metrics['cvssMetricV31'][0]['cvssData'] ?? ($metrics['cvssMetricV30'][0]['cvssData'] ?? null);

        $refs = [];
        foreach ($item['references'] ?? [] as $r) {
            $url = $r['url'] ?? '';
            if ($url) $refs[] = $url;
        }

        return [
            'cve_id' => $item['id'] ?? $cveId,
            'description' => $description,
            'published' => $item['published'] ?? '',
            'score' => $cvss['baseScore'] ?? null,
            'severity' => $cvss['baseSeverity'] ?? null,
            'vector' => $cvss['vectorString'] ?? null,
            'cvss_version' => $cvss['version'] ?? null,
            'references' => $refs,
        ];
    }

    private function fetchNvdEnrichment(string $cveId): ?array {
        $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={$cveId}";
        $data = $this->fetchJson($url, 15);
        if (!$data || empty($data['vulnerabilities'][0]['cve'])) return null;
        $item = $data['vulnerabilities'][0]['cve'];

        $metrics = $item['metrics'] ?? [];
        $cvss = $metrics['cvssMetricV31'][0]['cvssData'] ?? ($metrics['cvssMetricV30'][0]['cvssData'] ?? null);

        $refs = [];
        foreach ($item['references'] ?? [] as $r) {
            $url = $r['url'] ?? '';
            if ($url) $refs[] = $url;
        }

        $cpes = [];
        foreach ($item['configurations'] ?? [] as $conf) {
            foreach ($conf['nodes'] ?? [] as $node) {
                foreach ($node['cpeMatch'] ?? [] as $match) {
                    $criteria = $match['criteria'] ?? '';
                    if ($criteria && !in_array($criteria, $cpes, true)) $cpes[] = $criteria;
                }
            }
        }

        $cwes = [];
        foreach ($item['weaknesses'] ?? [] as $w) {
            foreach ($w['description'] ?? [] as $d) {
                $val = $d['value'] ?? '';
                if (str_starts_with($val, 'CWE-') && !in_array($val, $cwes, true)) $cwes[] = $val;
            }
        }

        return [
            'cvss_score' => $cvss['baseScore'] ?? null,
            'severity' => $cvss['baseSeverity'] ?? null,
            'vector' => $cvss['vectorString'] ?? null,
            'cvss_version' => $cvss['version'] ?? null,
            'references' => $refs,
            'cpes' => array_slice($cpes, 0, 10),
            'cwes' => $cwes,
        ];
    }

    private function fetchEpss(string $cveId): ?array {
        try {
            $data = $this->fetchJson("https://api.first.org/data/v1/epss?cve={$cveId}", 10);
            $entry = $data['data'][0] ?? null;
            if (!$entry) return null;
            $score = (float)($entry['epss'] ?? 0);
            $percentile = (float)($entry['percentile'] ?? 0);
            return [
                'score' => $score,
                'percentile' => $percentile,
                'score_percent' => round($score * 100, 2),
                'percentile_percent' => round($percentile * 100, 2),
            ];
        } catch (Throwable $e) { return null; }
    }

    private function fetchKev(string $cveId): ?array {
        try {
            $data = $this->fetchJson('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 20);
            $cveUpper = strtoupper($cveId);
            foreach ($data['vulnerabilities'] ?? [] as $vuln) {
                if (strtoupper($vuln['cveID'] ?? '') === $cveUpper) {
                    return [
                        'listed' => true,
                        'vendor' => $vuln['vendorProject'] ?? 'Unknown',
                        'product' => $vuln['product'] ?? 'Unknown',
                        'vulnerability' => $vuln['vulnerabilityName'] ?? 'Unknown',
                        'date_added' => $vuln['dateAdded'] ?? 'Unknown',
                        'due_date' => $vuln['dueDate'] ?? 'Unknown',
                        'required_action' => $vuln['requiredAction'] ?? 'Unknown',
                        'ransomware' => $vuln['knownRansomwareCampaignUse'] ?? 'Unknown',
                    ];
                }
            }
        } catch (Throwable $e) {}
        return null;
    }

    private function fetchGithubExploits(string $cveId): ?array {
        try {
            $data = $this->fetchJson("https://api.github.com/search/repositories?q={$cveId}&sort=updated&order=desc&per_page=5", 15);
            $results = [];
            foreach ($data['items'] ?? [] as $item) {
                $results[] = [
                    'name' => $item['full_name'] ?? 'Unknown',
                    'url' => $item['html_url'] ?? '',
                    'description' => $item['description'] ?? '',
                    'stars' => $item['stargazers_count'] ?? 0,
                    'updated_at' => $item['updated_at'] ?? '',
                    'language' => $item['language'] ?? '',
                ];
            }
            return $results ?: null;
        } catch (Throwable $e) { return null; }
    }

    private function calcPriority(?float $score, ?float $epssScore, bool $kevListed): string {
        if ($kevListed) return 'A+';
        if ($score !== null && $epssScore !== null) {
            if ($score >= 9.0 && $epssScore >= 0.5) return 'A+';
            if ($score >= 7.0 && $epssScore >= 0.3) return 'A';
            if ($score >= 7.0 || $epssScore >= 0.3) return 'B';
        }
        if ($score !== null) {
            if ($score >= 9.0) return 'A';
            if ($score >= 7.0) return 'B';
            if ($score >= 4.0) return 'C';
        }
        return 'D';
    }

    // ─────────────────────────────────────────────────────────────────────
    // Report builder (determinístico)
    // ─────────────────────────────────────────────────────────────────────

    private function buildBoxDrawingReport(array $e, string $lang, string $llmAnalysis): string {
        $cveId = $e['cve_id'];
        $published = $e['published'] ?: 'N/A';
        $score = $e['cvss_score'];
        $severity = $e['severity'];
        $vector = $e['vector'];
        $description = $e['description'];
        $refs = $e['references'];
        $epss = $e['epss'];
        $kev = $e['kev'];
        $github = $e['github'];
        $priority = $e['priority'];

        $scoreStr = $score !== null ? (string)$score : 'N/A';

        // Exploits
        if ($github && is_array($github) && count($github) > 0) {
            $exploitBlock = implode("\n", array_map(fn($r) => "  • " . ($r['name'] ?? 'Unknown'), array_slice($github, 0, 5)));
        } else {
            $exploitBlock = '  No exploits found';
        }

        // EPSS
        $epssStr = $epss ? "  EPSS Score:  {$epss['score_percent']}% Probability of exploitation." : '  EPSS Score:  N/A';

        // CISA KEV
        if ($kev) {
            $kevStr = "  ✅ LISTED in CISA KEV Catalog\n  Vendor: {$kev['vendor']}\n  Product: {$kev['product']}\n  Added: {$kev['date_added']}\n  Ransomware: {$kev['ransomware']}";
        } else {
            $kevStr = '  ❌ No data found';
        }

        // Referencias
        if ($refs) {
            $refLines = [];
            $slice = array_slice($refs, 0, 10);
            $lastIdx = count($slice) - 1;
            foreach ($slice as $i => $url) {
                $prefix = ($i < $lastIdx) ? '├' : '└';
                $refLines[] = "{$prefix} {$url}";
            }
            $refBlock = implode("\n", $refLines);
        } else {
            $refBlock = '└ N/A';
        }

        // Análisis del LLM
        if (!$llmAnalysis) {
            $llmAnalysis = '  [No AI analysis available]';
        } else {
            $lines = explode("\n", trim($llmAnalysis));
            $llmAnalysis = implode("\n", array_map(fn($l) => "│  {$l}", $lines));
        }

        return "╔═══════════════════════╗\n"
            . "║ CVE ID: {$cveId:<17} ║\n"
            . "╚═══════════════════════╝\n\n"
            . "┌───[ 🔍 Vulnerability information ]\n"
            . "│\n"
            . "├ Published:   {$published}\n"
            . "├ Base Score:  {$scoreStr} ({$severity})\n"
            . "├ Vector:      {$vector}\n"
            . "└ Description: {$description}\n\n"
            . "┌───[ 💣 Public Exploits (Total: " . ($github ? count($github) : 0) . ") ]\n"
            . "│\n"
            . "└{$exploitBlock}\n\n"
            . "┌───[ ♾️ Exploit Prediction Score (EPSS) ]\n"
            . "│\n"
            . "└{$epssStr}\n\n"
            . "┌───[ 🛡️ CISA KEV Catalog ]\n"
            . "│\n"
            . "└{$kevStr}\n\n"
            . "┌───[ 🤖 AI-Powered Risk Assessment ]\n"
            . "│\n"
            . "{$llmAnalysis}\n"
            . "│\n"
            . "└────────────────────────────────────────\n\n"
            . "┌───[ ⚠️ Patching Priority Rating ]\n"
            . "│\n"
            . "└ Priority:     {$priority}\n\n"
            . "┌───[ 📚 Further References ]\n"
            . "│\n"
            . "{$refBlock}\n\n"
            . "Model: OrinSec Worker";
    }

    // ─────────────────────────────────────────────────────────────────────
    // HTML renderer
    // ─────────────────────────────────────────────────────────────────────

    private function renderHtml(string $reportText, array $enriched): string {
        $severity = htmlspecialchars($enriched['severity'] ?? '');

        $html = htmlspecialchars($reportText, ENT_NOQUOTES, 'UTF-8');

        $html = preg_replace(
            '#(https?://[^\s\)\]\>\"\'\`]+)#',
            '<a href="$1" target="_blank" rel="noopener" style="color:var(--primary);text-decoration:underline;">$1</a>',
            $html
        );

        $badgeHtml = '';
        if ($severity && $severity !== 'N/A') {
            $color = match (strtoupper($severity)) {
                'CRITICAL' => '#c62828',
                'HIGH' => '#f57c00',
                'MEDIUM' => '#f9a825',
                'LOW' => '#2e7d32',
                default => '#78909c',
            };
            $badgeHtml = "<div style='margin-bottom:.5rem;'><span style='display:inline-block;background:{$color};color:#fff;padding:.2rem .6rem;border-radius:4px;font-size:.85rem;font-weight:600;'>{$severity}</span></div>";
        }

        return "<div class='cve-report' style='font-family:var(--font-base);color:var(--text);max-width:900px;margin:0 auto;'>"
            . "<div style='text-align:center;margin-bottom:1rem;'>{$badgeHtml}</div>"
            . "<pre style='white-space:pre-wrap;word-wrap:break-word;font-family:\"Consolas\",\"Monaco\",\"Courier New\",monospace;font-size:.95rem;line-height:1.5;background:var(--bg);padding:1.25rem;border-radius:var(--radius);border:1px solid var(--border);overflow-x:auto;'>{$html}</pre>"
            . "</div>";
    }

    private function fetchJson(string $url, int $timeout = 15): ?array {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_USERAGENT => 'OrinSec-VirtualWorker/1.0',
            CURLOPT_SSL_VERIFYPEER => true,
        ]);
        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($resp === false || $code >= 400) return null;
        $data = json_decode($resp, true);
        return is_array($data) ? $data : null;
    }
}
