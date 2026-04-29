<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/functions.php';

requireAuth();
checkRateLimit();

$taskId = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$format = $_GET['format'] ?? 'md';
if (!in_array($format, ['md', 'docx'], true)) {
    http_response_code(400);
    exit('Formato no soportado');
}

$task = Database::fetchOne(
    'SELECT id, status, result_text, input_data, executed_by, created_at, completed_at
     FROM tasks WHERE id = ? AND task_type = ?',
    [$taskId, 'cve_search']
);

if (!$task || $task['status'] !== 'completed') {
    http_response_code(404);
    exit('Tarea no disponible');
}

$input = json_decode($task['input_data'] ?? '{}', true) ?: [];
$cveId = $input['cve_id'] ?? ('task-' . $taskId);
$body  = trim((string)($task['result_text'] ?? ''));

// Cabecera común en Markdown
$header  = "# Informe CVE — {$cveId}\n\n";
$header .= "- **Tarea:** #{$task['id']}\n";
$header .= "- **Creada:** {$task['created_at']}\n";
$header .= "- **Completada:** " . ($task['completed_at'] ?: '—') . "\n";
$header .= "- **Ejecutor:** " . ($task['executed_by'] ?: '—') . "\n\n---\n\n";

$markdown = $header . $body . "\n";
$safeName = preg_replace('/[^A-Za-z0-9_\-]/', '_', $cveId);

if ($format === 'md') {
    header('Content-Type: text/markdown; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $safeName . '.md"');
    echo $markdown;
    exit;
}

// --- Exportación a DOCX (formato Word minimalista, sin dependencias) ---
header('Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document');
header('Content-Disposition: attachment; filename="' . $safeName . '.docx"');
echo buildDocx($markdown);
exit;


/**
 * Construye un .docx mínimo en memoria a partir de Markdown simple.
 * Soporta: # / ## / ### títulos, listas con -, negrita **x**, párrafos.
 * Sin dependencias externas (usa la extensión ZipArchive de PHP).
 */
function buildDocx(string $md): string {
    $bodyXml = mdToWordXml($md);

    $documentXml = <<<XML
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
{$bodyXml}
<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr>
</w:body>
</w:document>
XML;

    $contentTypes = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        . '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        . '<Default Extension="xml" ContentType="application/xml"/>'
        . '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        . '</Types>';

    $rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        . '</Relationships>';

    $tmpFile = tempnam(sys_get_temp_dir(), 'orinsec_docx_');
    $zip = new ZipArchive();
    $zip->open($tmpFile, ZipArchive::OVERWRITE);
    $zip->addFromString('[Content_Types].xml', $contentTypes);
    $zip->addFromString('_rels/.rels', $rels);
    $zip->addFromString('word/document.xml', $documentXml);
    $zip->close();

    $bytes = file_get_contents($tmpFile);
    @unlink($tmpFile);
    return $bytes;
}

function mdToWordXml(string $md): string {
    $lines = preg_split("/\r\n|\n/", $md);
    $out = [];
    foreach ($lines as $line) {
        $line = rtrim($line);
        if ($line === '') {
            $out[] = '<w:p/>';
            continue;
        }
        // Encabezados
        if (preg_match('/^(#{1,3})\s+(.*)$/', $line, $m)) {
            $level = strlen($m[1]);
            $size = ['28', '24', '22'][$level - 1];
            $out[] = '<w:p><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>'
                   . '<w:r><w:rPr><w:b/><w:sz w:val="' . $size . '"/></w:rPr>'
                   . '<w:t xml:space="preserve">' . wordEscape($m[2]) . '</w:t>'
                   . '</w:r></w:p>';
            continue;
        }
        // Listas
        if (preg_match('/^[\-\*]\s+(.*)$/', $line, $m)) {
            $out[] = '<w:p><w:pPr><w:ind w:left="360"/></w:pPr>'
                   . '<w:r><w:t xml:space="preserve">• ' . wordEscape($m[1]) . '</w:t></w:r>'
                   . '</w:p>';
            continue;
        }
        // Párrafo normal con negrita simple
        $out[] = '<w:p>' . inlineMdToRuns($line) . '</w:p>';
    }
    return implode("\n", $out);
}

function inlineMdToRuns(string $text): string {
    // Divide por **...**
    $parts = preg_split('/(\*\*.+?\*\*)/u', $text, -1, PREG_SPLIT_DELIM_CAPTURE);
    $xml = '';
    foreach ($parts as $part) {
        if ($part === '') continue;
        if (preg_match('/^\*\*(.+)\*\*$/u', $part, $m)) {
            $xml .= '<w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">' . wordEscape($m[1]) . '</w:t></w:r>';
        } else {
            $xml .= '<w:r><w:t xml:space="preserve">' . wordEscape($part) . '</w:t></w:r>';
        }
    }
    return $xml;
}

function wordEscape(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_XML1, 'UTF-8');
}
