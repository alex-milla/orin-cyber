<?php
declare(strict_types=1);

require_once __DIR__ . '/../virtual_worker.php';

/**
 * Versión PHP de la tarea CVE Search para ejecución vía VirtualWorker (API externa).
 * Paridad con worker Python: CVE.org (canónico) + NVD (enriquecimiento) + CISA KEV + EPSS + GitHub.
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

        // 2. Construir reporte pre-rellenado
        $reportBody = $this->buildBoxDrawingReport($enriched, $language);

        // 3. Generar informe con LLM
        $customTemplate = trim((string)($input['template'] ?? ''));
        if ($customTemplate) {
            $systemPrompt = $customTemplate;
            $userPrompt = ($language === 'es'
                ? "A continuación tienes un informe técnico pre-rellenado con datos oficiales.\nREESCRIBE ÚNICAMENTE la sección '🤖 AI-Powered Risk Assessment'.\nMantén TODO el resto exactamente igual, incluyendo los caracteres de dibujo de cajas.\n\n"
                : "Below is a pre-filled technical report with official data.\nREWRITE ONLY the '🤖 AI-Powered Risk Assessment' section.\nKeep EVERYTHING else exactly as is, including the box-drawing characters.\n\n"
            ) . $reportBody;
        } else {
            $systemPrompt = $this->buildSystemPrompt($language);
            $userPrompt = $reportBody;
        }

        $report = $this->worker->chat($systemPrompt, $userPrompt, [
            'temperature' => 0.2,
            'max_tokens'  => 4096,
        ]);

        // Si el LLM devolvió algo vacío o sin el CVE ID, usar el pre-rellenado
        if (!$report || !str_contains($report, 'CVE ID:')) {
            $report = $reportBody;
        }

        // 4. Renderizar HTML
        $html = $this->renderHtml($report, $enriched);

        return [
            'result_html'     => $html,
            'result_text'     => $report,
            'cvss_base_score' => $enriched['cvss_score'],
            'cvss_severity'   => $enriched['severity'],
        ];
    }

    private function enrichCve(string $cveId, string $language): array {
        // ── CVE.org (canónico) ────────────────────────────────────────────
        $cveOrg = $this->fetchCveOrg($cveId);

        // ── Fallback a NVD ────────────────────────────────────────────────
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

        // ── Enriquecimiento NVD ───────────────────────────────────────────
        $nvdEnrich = $this->fetchNvdEnrichment($cveId);

        // Fusionar referencias
        $refs = array_merge(
            $cveOrg['references'] ?? [],
            $nvdEnrich['references'] ?? []
        );
        $refs = array_values(array_unique($refs));

        // Descripción según idioma
        if ($language === 'es') {
            $description = $cveOrg['description_es'] ?: ($cveOrg['description_en'] ?: 'Sin descripción');
        } else {
            $description = $cveOrg['description_en'] ?: ($cveOrg['description_es'] ?: 'No description');
        }

        // CVSS: preferir CNA, luego NVD
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

        // ── EPSS ──────────────────────────────────────────────────────────
        $epss = $this->fetchEpss($cveId);

        // ── CISA KEV ──────────────────────────────────────────────────────
        $kev = $this->fetchKev($cveId);

        // ── GitHub Exploits ───────────────────────────────────────────────
        $github = $this->fetchGithubExploits($cveId);

        // Calcular prioridad
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

    // ─────────────────────────────────────────────────────────────────────
    // Scrapers
    // ─────────────────────────────────────────────────────────────────────

    private function fetchCveOrg(string $cveId): ?array {
        $url = "https://cveawg.mitre.org/api/cve/{$cveId}";
        $data = $this->fetchJson($url, 20);
        if (!$data) {
            return null;
        }

        $meta = $data['cveMetadata'] ?? [];
        $containers = $data['containers'] ?? [];
        $cna = $containers['cna'] ?? [];

        // Descripciones
        $descriptions = [];
        foreach ($cna['descriptions'] ?? [] as $d) {
            $lang = $d['lang'] ?? 'en';
            $val = trim($d['value'] ?? '');
            if ($val) {
                $descriptions[$lang] = $val;
            }
        }
        // Fallback a ADP
        if (empty($descriptions)) {
            foreach ($containers['adp'] ?? [] as $adp) {
                foreach ($adp['descriptions'] ?? [] as $d) {
                    $lang = $d['lang'] ?? 'en';
                    $val = trim($d['value'] ?? '');
                    if ($val) {
                        $descriptions[$lang] = $val;
                    }
                }
            }
        }

        // Affected
        $affected = [];
        foreach ($cna['affected'] ?? [] as $entry) {
            $versions = [];
            foreach ($entry['versions'] ?? [] as $v) {
                $status = $v['status'] ?? '';
                $version = $v['version'] ?? '';
                $lessThan = $v['lessThan'] ?? '';
                if ($lessThan) {
                    $versions[] = "{$version} < {$lessThan} ({$status})";
                } else {
                    $versions[] = "{$version} ({$status})";
                }
            }
            $affected[] = [
                'vendor' => $entry['vendor'] ?? 'Unknown',
                'product' => $entry['product'] ?? 'Unknown',
                'versions' => $versions,
                'cpes' => array_slice($entry['cpes'] ?? [], 0, 5),
                'default_status' => $entry['defaultStatus'] ?? '',
            ];
        }

        // Métricas CNA
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

        // CWEs
        $cwes = [];
        foreach ($cna['problemTypes'] ?? [] as $pt) {
            foreach ($pt['descriptions'] ?? [] as $d) {
                $cwe = trim($d['cweId'] ?? '');
                if ($cwe && !in_array($cwe, $cwes, true)) {
                    $cwes[] = $cwe;
                }
            }
        }

        // Referencias
        $refs = [];
        foreach ($cna['references'] ?? [] as $r) {
            $url = trim($r['url'] ?? '');
            if ($url && !in_array($url, $refs, true)) {
                $refs[] = $url;
            }
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
        if (!$data || empty($data['vulnerabilities'][0]['cve'])) {
            return null;
        }
        $item = $data['vulnerabilities'][0]['cve'];

        $description = '';
        foreach ($item['descriptions'] ?? [] as $d) {
            if (($d['lang'] ?? '') === 'en') {
                $description = $d['value'];
                break;
            }
        }

        $metrics = $item['metrics'] ?? [];
        $cvss = $metrics['cvssMetricV31'][0]['cvssData'] ?? ($metrics['cvssMetricV30'][0]['cvssData'] ?? null);

        $refs = [];
        foreach ($item['references'] ?? [] as $r) {
            $url = $r['url'] ?? '';
            if ($url) {
                $refs[] = $url;
            }
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
        if (!$data || empty($data['vulnerabilities'][0]['cve'])) {
            return null;
        }
        $item = $data['vulnerabilities'][0]['cve'];

        $metrics = $item['metrics'] ?? [];
        $cvss = $metrics['cvssMetricV31'][0]['cvssData'] ?? ($metrics['cvssMetricV30'][0]['cvssData'] ?? null);

        $refs = [];
        foreach ($item['references'] ?? [] as $r) {
            $url = $r['url'] ?? '';
            if ($url) {
                $refs[] = $url;
            }
        }

        $cpes = [];
        foreach ($item['configurations'] ?? [] as $conf) {
            foreach ($conf['nodes'] ?? [] as $node) {
                foreach ($node['cpeMatch'] ?? [] as $match) {
                    $criteria = $match['criteria'] ?? '';
                    if ($criteria && !in_array($criteria, $cpes, true)) {
                        $cpes[] = $criteria;
                    }
                }
            }
        }

        $cwes = [];
        foreach ($item['weaknesses'] ?? [] as $w) {
            foreach ($w['description'] ?? [] as $d) {
                $val = $d['value'] ?? '';
                if (str_starts_with($val, 'CWE-') && !in_array($val, $cwes, true)) {
                    $cwes[] = $val;
                }
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
            if (!$entry) {
                return null;
            }
            $score = (float)($entry['epss'] ?? 0);
            $percentile = (float)($entry['percentile'] ?? 0);
            return [
                'score' => $score,
                'percentile' => $percentile,
                'score_percent' => round($score * 100, 2),
                'percentile_percent' => round($percentile * 100, 2),
            ];
        } catch (Throwable $e) {
            return null;
        }
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
        } catch (Throwable $e) {
            // KEV es opcional
        }
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
        } catch (Throwable $e) {
            return null;
        }
    }

    private function calcPriority(?float $score, ?float $epssScore, bool $kevListed): string {
        if ($kevListed) {
            return 'A+';
        }
        if ($score !== null && $epssScore !== null) {
            if ($score >= 9.0 && $epssScore >= 0.5) {
                return 'A+';
            }
            if ($score >= 7.0 && $epssScore >= 0.3) {
                return 'A';
            }
            if ($score >= 7.0 || $epssScore >= 0.3) {
                return 'B';
            }
        }
        if ($score !== null) {
            if ($score >= 9.0) {
                return 'A';
            }
            if ($score >= 7.0) {
                return 'B';
            }
            if ($score >= 4.0) {
                return 'C';
            }
        }
        return 'D';
    }

    // ─────────────────────────────────────────────────────────────────────
    // Report builder
    // ─────────────────────────────────────────────────────────────────────

    private function buildBoxDrawingReport(array $enriched, string $language): string {
        $cveId = $enriched['cve_id'];
        $published = $enriched['published'] ?: 'N/A';
        $score = $enriched['cvss_score'];
        $severity = $enriched['severity'];
        $vector = $enriched['vector'];
        $description = $enriched['description'];
        $refs = $enriched['references'];
        $epss = $enriched['epss'];
        $kev = $enriched['kev'];
        $github = $enriched['github'];
        $priority = $enriched['priority'];

        $scoreStr = $score !== null ? (string)$score : 'N/A';

        // Exploits
        if ($github && is_array($github) && count($github) > 0) {
            $exploitLines = [];
            foreach (array_slice($github, 0, 5) as $repo) {
                $name = is_array($repo) ? ($repo['name'] ?? 'Unknown') : (string)$repo;
                $exploitLines[] = "  • {$name}";
            }
            $exploitBlock = implode("\n", $exploitLines);
        } else {
            $exploitBlock = '  No exploits found';
        }

        // EPSS
        if ($epss) {
            $epssStr = "  EPSS Score:  {$epss['score_percent']}% Probability of exploitation.";
        } else {
            $epssStr = '  EPSS Score:  N/A';
        }

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

        $riskPlaceholder = '  <AI analysis will be inserted here>';

        return "╔═══════════════════════╗\n"
            . "║ CVE ID: {$cveId}      ║\n"
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
            . "│{$riskPlaceholder}\n"
            . "│\n"
            . "└────────────────────────────────────────\n\n"
            . "┌───[ ⚠️ Patching Priority Rating ]\n"
            . "│\n"
            . "└ Priority:     {$priority}\n\n"
            . "┌───[ 📚 Further References ]\n"
            . "│\n"
            . "{$refBlock}";
    }

    private function buildSystemPrompt(string $language): string {
        if ($language === 'es') {
            return "Eres un analista senior de ciberseguridad. Tu única tarea es revisar el informe técnico pre-rellenado que aparece a continuación y REESCRIBIR ÚNICAMENTE la sección '🤖 AI-Powered Risk Assessment'.\n\nREGLAS ESTRICTAS:\n1. NO modifiques NINGUNA sección excepto '🤖 AI-Powered Risk Assessment'.\n2. NO repitas el score numérico, la severidad, la fecha de publicación, ni porcentajes EPSS/KEV en tu análisis.\n3. NO inventes versiones de parche, fechas ni detalles de vendor.\n4. El análisis debe ser conciso: máximo 150 palabras.\n5. Usa solo datos contrastados; si algo es inferencia lógica, indícalo con [INFERIDO].\n6. Responde en español.\n\nINSTRUCCIÓN:\n- Mantén el formato box-drawing Unicode exacto.\n- La sección '🤖 AI-Powered Risk Assessment' debe contener tu propio análisis técnico del impacto y riesgo.\n- Todo lo demás debe quedar EXACTAMENTE igual al texto proporcionado.";
        }
        return "You are a senior cybersecurity analyst. Your only task is to review the pre-filled technical report below and REWRITE ONLY the '🤖 AI-Powered Risk Assessment' section.\n\nSTRICT RULES:\n1. DO NOT modify ANY section except '🤖 AI-Powered Risk Assessment'.\n2. DO NOT repeat the numeric score, severity, publication date, or EPSS/KEV percentages in your analysis.\n3. DO NOT invent patch versions, dates, or vendor details.\n4. The analysis must be concise: maximum 150 words.\n5. Use only verified data; if something is logical inference, mark it with [INFERRED].\n6. Respond in English.\n\nINSTRUCTION:\n- Keep the exact Unicode box-drawing format.\n- The '🤖 AI-Powered Risk Assessment' section must contain your own technical analysis of impact and risk.\n- Everything else must remain EXACTLY as provided.";
    }

    // ─────────────────────────────────────────────────────────────────────
    // HTML renderer
    // ─────────────────────────────────────────────────────────────────────

    private function renderHtml(string $reportText, array $enriched): string {
        $cveId = htmlspecialchars($enriched['cve_id']);
        $severity = htmlspecialchars($enriched['severity']);

        // Escapar HTML pero mantener saltos de línea
        $html = htmlspecialchars($reportText, ENT_NOQUOTES, 'UTF-8');

        // Convertir URLs a enlaces
        $html = preg_replace(
            '#(https?://[^\s\)\]\>\"\'\`]+)#',
            '<a href="$1" target="_blank" rel="noopener" style="color:var(--primary);text-decoration:underline;">$1</a>',
            $html
        );

        // Badge de severidad
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

    // ─────────────────────────────────────────────────────────────────────
    // HTTP helper
    // ─────────────────────────────────────────────────────────────────────

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
        if ($resp === false || $code >= 400) {
            return null;
        }
        $data = json_decode($resp, true);
        return is_array($data) ? $data : null;
    }
}
