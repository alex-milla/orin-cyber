<?php
declare(strict_types=1);

/**
 * Utilidades para el convertidor IOC → STIX 2.1
 * Adaptado desde convert-IOCstoSTIX
 */

if (!defined('IOC_UPLOAD_DIR')) {
    define('IOC_UPLOAD_DIR', DATA_DIR . '/ioc_uploads/');
    define('IOC_OUTPUT_DIR', DATA_DIR . '/ioc_output/');
    define('IOC_RETENTION_HOURS', 24);
    define('IOC_MAX_FILE_SIZE', 10 * 1024 * 1024); // 10MB
    define('IOC_MAX_FILES', 20);
    define('IOC_SUPPORTED_EXTENSIONS', ['txt','list','dat','ioc','csv','json']);
    define('IOC_ALLOWED_MIME_TYPES', ['text/plain','text/csv','application/json','text/html']);
}

function iocCleanOldFiles(): void {
    $dirs = [IOC_UPLOAD_DIR, IOC_OUTPUT_DIR];
    $cutoff = time() - (IOC_RETENTION_HOURS * 3600);
    foreach ($dirs as $dir) {
        if (!is_dir($dir)) continue;
        foreach (glob($dir . '*') as $file) {
            if (is_file($file) && filemtime($file) < $cutoff) {
                @unlink($file);
            }
        }
    }
}

function iocProcessFiles(array $inputFiles, string $outputFormat, string $sourceName, string $threatActor, string $tags, int $confidence, string $tlpLevel, string $indicatorType, int $validDays): array {
    $uploadDir = IOC_UPLOAD_DIR;
    $outputDir = IOC_OUTPUT_DIR;
    if (!is_dir($uploadDir)) @mkdir($uploadDir, 0755, true);
    if (!is_dir($outputDir)) @mkdir($outputDir, 0755, true);

    $allValues = [];
    $fileStats = [];

    foreach ($inputFiles['tmp_name'] as $index => $tmpName) {
        $fileName = basename($inputFiles['name'][$index]);
        $fileExt = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        $filePath = $uploadDir . md5(uniqid((string)$index, true)) . '_' . $fileName;

        if (!move_uploaded_file($tmpName, $filePath)) {
            continue;
        }

        $values = iocReadFileContent($filePath, $fileExt, $fileStats);
        if (!empty($values)) {
            $allValues = array_merge($allValues, $values);
        }
    }

    $uniqueValues = array_unique($allValues);
    $duplicates = count($allValues) - count($uniqueValues);

    $stixResults = iocConvertToSTIX($uniqueValues, $sourceName, $threatActor, $tags, $confidence, $tlpLevel, $indicatorType, $validDays);

    $outputFiles = [];
    $downloadPaths = [];
    if ($outputFormat === 'split') {
        $byType = [];
        foreach ($stixResults as $stix) {
            $type = iocExtractStixType($stix);
            $byType[$type][] = $stix;
        }
        foreach ($byType as $type => $indicators) {
            $fileName = 'stix_' . $type . '_' . date('Ymd_His') . '.json';
            $filePath = $outputDir . $fileName;
            file_put_contents($filePath, json_encode($indicators, JSON_PRETTY_PRINT));
            $outputFiles[] = $fileName;
            $downloadPaths[$fileName] = $filePath;
        }
    } else {
        $fileName = 'stix_indicators_' . date('Ymd_His') . '.json';
        $filePath = $outputDir . $fileName;
        file_put_contents($filePath, json_encode($stixResults, JSON_PRETTY_PRINT));
        $outputFiles[] = $fileName;
        $downloadPaths[$fileName] = $filePath;
    }

    return [
        'success' => true,
        'processed' => count($uniqueValues),
        'duplicates' => $duplicates,
        'by_type' => iocCountByType($stixResults),
        'output_files' => $outputFiles,
        'download_paths' => $downloadPaths,
        'file_stats' => $fileStats,
        'timestamp' => date('Y-m-d H:i:s'),
    ];
}

function iocReadFileContent(string $filePath, string $ext, array &$fileStats): array {
    $fileStats[$filePath] = ['total' => 0, 'processed' => 0, 'skipped' => 0];
    try {
        switch ($ext) {
            case 'txt':
            case 'list':
            case 'dat':
            case 'ioc':
                $values = iocReadTextFile($filePath);
                break;
            case 'csv':
                $values = iocReadCSVFile($filePath);
                break;
            case 'json':
                $values = iocReadJSONFile($filePath);
                break;
            default:
                $fileStats[$filePath]['skipped'] = 'Formato no soportado';
                return [];
        }
        $fileStats[$filePath]['total'] = count($values);
        $fileStats[$filePath]['processed'] = count($values);
    } catch (Exception $e) {
        $fileStats[$filePath]['skipped'] = 'Error: ' . $e->getMessage();
        $values = [];
    }
    return $values;
}

function iocReadTextFile(string $filePath): array {
    $values = [];
    $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!$lines) return $values;
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#' || $line[0] === ';' || substr($line, 0, 2) === '//') {
            continue;
        }
        $values[] = $line;
    }
    return $values;
}

function iocReadCSVFile(string $filePath): array {
    $values = [];
    $handle = @fopen($filePath, 'r');
    if (!$handle) return $values;
    $header = fgetcsv($handle);
    $valueColumn = null;
    if ($header) {
        foreach ($header as $col) {
            $colLower = strtolower((string)$col);
            if (in_array($colLower, ['value','indicator','ioc','ip','domain','hash','url'])) {
                $valueColumn = $col;
                break;
            }
        }
        if (!$valueColumn && count($header) > 0) {
            $valueColumn = $header[0];
        }
    }
    while (($row = fgetcsv($handle)) !== false) {
        if (count($row) === 0) continue;
        $rowAssoc = array_combine($header ?: [], $row);
        if ($valueColumn && isset($rowAssoc[$valueColumn]) && $rowAssoc[$valueColumn] !== '') {
            $values[] = trim((string)$rowAssoc[$valueColumn]);
        }
    }
    fclose($handle);
    return $values;
}

function iocReadJSONFile(string $filePath): array {
    $values = [];
    $json = file_get_contents($filePath);
    $data = json_decode($json, true);
    if (!is_array($data)) return $values;
    foreach ($data as $item) {
        if (is_array($item)) {
            foreach ($item as $key => $value) {
                if (in_array(strtolower((string)$key), ['value','indicator','ioc','ip','domain','hash','url']) && !empty($value)) {
                    $values[] = trim((string)$value);
                    break;
                }
            }
        } elseif (is_string($item) && $item !== '') {
            $values[] = trim($item);
        }
    }
    return $values;
}

function iocConvertToSTIX(array $values, string $sourceName, string $threatActor, string $tags, int $confidence, string $tlpLevel, string $indicatorType, int $validDays): array {
    $tlpMarkings = [
        'white' => 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
        'green' => 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
        'amber' => 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
        'red'   => 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
    ];

    $now = new DateTime('now', new DateTimeZone('UTC'));
    $validUntil = (clone $now)->add(new DateInterval('P' . $validDays . 'D'));
    $tagsArray = !empty($tags) ? array_map('trim', explode(',', $tags)) : [];
    $indicators = [];

    foreach ($values as $value) {
        $type = iocDetectIOCType($value);
        $pattern = iocGenerateSTIXPattern($type, $value);
        if (!$pattern) continue;

        $indicator = [
            'type' => 'indicator',
            'id' => 'indicator--' . iocGenerateUUID(),
            'spec_version' => '2.1',
            'pattern' => $pattern,
            'pattern_type' => 'stix',
            'pattern_version' => '2.1',
            'created' => $now->format('Y-m-d\TH:i:s\Z'),
            'modified' => $now->format('Y-m-d\TH:i:s\Z'),
            'valid_from' => $now->format('Y-m-d\TH:i:s\Z'),
            'valid_until' => $validUntil->format('Y-m-d\TH:i:s\Z'),
            'name' => $sourceName . ' - ' . $value,
            'description' => "IOC ($type) from $sourceName",
            'indicator_types' => [$indicatorType],
            'revoked' => false,
            'labels' => array_merge([$type], $tagsArray),
            'confidence' => $confidence,
            'lang' => 'en',
            'object_marking_refs' => [$tlpMarkings[$tlpLevel] ?? $tlpMarkings['green']],
            'kill_chain_phases' => [],
            'external_references' => [],
            'granular_markings' => [],
            'extensions' => (object)[],
        ];

        if (!empty($threatActor)) {
            $indicator['threat_actor_names'] = [$threatActor];
        }

        $indicators[] = $indicator;
    }

    return $indicators;
}

function iocDetectIOCType(string $value): string {
    if (preg_match('/^(HKLM|HKCU|HKCR|HKU|HKCC|HK\w+)/i', $value)) {
        return 'windows-registry-key';
    } elseif (preg_match('/^[^\s@]+@[^\s@]+\.[^\s@]+$/', $value)) {
        return 'email-addr';
    } elseif (preg_match('/^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$|^[0-9a-f]{128}$/i', $value)) {
        return 'file';
    } elseif (preg_match('/^(https?|ftp):\/\//', $value)) {
        return 'url';
    } elseif (preg_match('/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/\d{1,3})?$/', $value)) {
        return 'ipv4-addr';
    } elseif (preg_match('/^([0-9a-fA-F:]+:+)+[0-9a-fA-F]+$/', $value)) {
        return 'ipv6-addr';
    } elseif (preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/', $value)) {
        return 'domain-name';
    } elseif (preg_match('/^(DOMAIN\\[A-Za-z0-9_\\]+|[A-Za-z0-9_]+@[A-Za-z0-9_.]+)$/', $value)) {
        return 'user-account';
    }
    return 'unknown';
}

function iocGenerateSTIXPattern(string $type, string $value): ?string {
    $safe = str_replace("'", "\\'", $value);
    return match ($type) {
        'ipv4-addr' => "[ipv4-addr:value = '$safe']",
        'ipv6-addr' => "[ipv6-addr:value = '$safe']",
        'domain-name' => "[domain-name:value = '$safe']",
        'url' => "[url:value = '$safe']",
        'file' => "[file:hashes.MD5 = '$safe']",
        'email-addr' => "[email-addr:value = '$safe']",
        'user-account' => "[user-account:value = '$safe']",
        'windows-registry-key' => "[windows-registry-key:key = '$safe']",
        default => null,
    };
}

function iocExtractStixType(array $stix): string {
    $pattern = $stix['pattern'] ?? '';
    if (str_contains($pattern, 'ipv4-addr')) return 'ipv4-addr';
    if (str_contains($pattern, 'ipv6-addr')) return 'ipv6-addr';
    if (str_contains($pattern, 'domain-name')) return 'domain-name';
    if (str_contains($pattern, 'windows-registry-key')) return 'windows-registry-key';
    if (str_contains($pattern, 'user-account')) return 'user-account';
    if (str_contains($pattern, 'email-addr')) return 'email-addr';
    if (str_contains($pattern, 'url')) return 'url';
    if (str_contains($pattern, 'file')) return 'file';
    return 'unknown';
}

function iocCountByType(array $stixResults): array {
    $counts = [];
    foreach ($stixResults as $stix) {
        $type = iocExtractStixType($stix);
        $counts[$type] = ($counts[$type] ?? 0) + 1;
    }
    return $counts;
}

function iocGenerateUUID(): string {
    return sprintf(
        '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
}

function iocGetHumanReadableType(string $type): string {
    return match ($type) {
        'ipv4-addr' => 'Dirección IPv4',
        'ipv6-addr' => 'Dirección IPv6',
        'domain-name' => 'Dominio',
        'url' => 'URL',
        'file' => 'Archivo (Hash)',
        'email-addr' => 'Email',
        'user-account' => 'Cuenta de Usuario',
        'windows-registry-key' => 'Clave de Registro',
        default => 'Desconocido',
    };
}

function iocFormatBytes(int $bytes, int $precision = 2): string {
    $units = ['B', 'KB', 'MB', 'GB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow));
    return round($bytes, $precision) . ' ' . $units[$pow];
}
