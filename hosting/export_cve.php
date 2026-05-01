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

$lang = strtolower($input['language'] ?? 'es');
if (!in_array($lang, ['es', 'en'], true)) {
    $lang = 'es';
}

if ($lang === 'en') {
    $header  = "# CVE Report — {$cveId}\n\n";
    $header .= "- **Task:** #{$task['id']}\n";
    $header .= "- **Created:** {$task['created_at']}\n";
    $header .= "- **Completed:** " . ($task['completed_at'] ?: '—') . "\n";
    $header .= "- **Executor:** " . ($task['executed_by'] ?: '—') . "\n\n---\n\n";
} else {
    $header  = "# Informe CVE — {$cveId}\n\n";
    $header .= "- **Tarea:** #{$task['id']}\n";
    $header .= "- **Creada:** {$task['created_at']}\n";
    $header .= "- **Completada:** " . ($task['completed_at'] ?: '—') . "\n";
    $header .= "- **Ejecutor:** " . ($task['executed_by'] ?: '—') . "\n\n---\n\n";
}

$markdown = $header . $body . "\n";
$safeName = preg_replace('/[^A-Za-z0-9_\-]/', '_', $cveId);

if ($format === 'md') {
    header('Content-Type: text/markdown; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $safeName . '.md"');
    echo $markdown;
    exit;
}

// --- Exportación a DOCX profesional (sin dependencias) ---
header('Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document');
header('Content-Disposition: attachment; filename="' . $safeName . '.docx"');
echo buildProfessionalDocx($body, $cveId, $task, $lang);
exit;


/**
 * Construye un .docx profesional en memoria a partir del texto box-drawing.
 *
 * Incluye: styles.xml profesional, portada, tablas, encabezados, pie de página,
 * fuente Calibri y paleta de colores corporativa.
 */
function buildProfessionalDocx(string $reportText, string $cveId, array $task, string $lang): string {
    $tmpFile = tempnam(sys_get_temp_dir(), 'orinsec_docx_');
    $zip = new ZipArchive();
    $zip->open($tmpFile, ZipArchive::OVERWRITE);

    // ── 1. [Content_Types].xml ──────────────────────────────────────────
    $zip->addFromString('[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        . '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        . '<Default Extension="xml" ContentType="application/xml"/>'
        . '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        . '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
        . '<Override PartName="/word/fontTable.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml"/>'
        . '<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>'
        . '</Types>');

    // ── 2. _rels/.rels ──────────────────────────────────────────────────
    $zip->addFromString('_rels/.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        . '</Relationships>');

    // ── 3. word/_rels/document.xml.rels ─────────────────────────────────
    $zip->addFromString('word/_rels/document.xml.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
        . '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable" Target="fontTable.xml"/>'
        . '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>'
        . '</Relationships>');

    // ── 4. word/settings.xml ────────────────────────────────────────────
    $zip->addFromString('word/settings.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        . '<w:zoom w:percent="100"/><w:defaultTabStop w:val="720"/>'
        . '<w:compat><w:compatSetting w:name="compatibilityMode" w:uri="http://schemas.microsoft.com/office/word" w:val="15"/></w:compat>'
        . '</w:settings>');

    // ── 5. word/fontTable.xml ───────────────────────────────────────────
    $zip->addFromString('word/fontTable.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<w:fonts xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        . '<w:font w:name="Calibri"><w:panose1 w:val="020F0502020204030204"/><w:charset w:val="00"/><w:family w:val="swiss"/><w:pitch w:val="variable"/></w:font>'
        . '<w:font w:name="Calibri Light"><w:panose1 w:val="020F0302020204030204"/><w:charset w:val="00"/><w:family w:val="swiss"/><w:pitch w:val="variable"/></w:font>'
        . '</w:fonts>');

    // ── 6. word/styles.xml ──────────────────────────────────────────────
    $stylesXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        . '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:eastAsia="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="22"/><w:szCs w:val="22"/><w:lang w:val="es-ES" w:eastAsia="en-US" w:bidi="ar-SA"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="160" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>'
        // Title
        . '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="22"/><w:szCs w:val="22"/></w:rPr></w:style>'
        . '<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/><w:jc w:val="center"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri Light" w:hAnsi="Calibri Light"/><w:b/><w:sz w:val="56"/><w:szCs w:val="56"/><w:color w:val="1F3864"/></w:rPr></w:style>'
        // Heading1 (secciones)
        . '<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="240" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri Light" w:hAnsi="Calibri Light"/><w:b/><w:sz w:val="32"/><w:szCs w:val="32"/><w:color w:val="2E74B5"/></w:rPr></w:style>'
        // Heading2 (sub-secciones)
        . '<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="200" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri Light" w:hAnsi="Calibri Light"/><w:b/><w:sz w:val="26"/><w:szCs w:val="26"/><w:color w:val="2E74B5"/></w:rPr></w:style>'
        // Quote (para análisis de riesgo)
        . '<w:style w:type="paragraph" w:styleId="Quote"><w:name w:val="Quote"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:left="720" w:right="720"/><w:jc w:val="both"/></w:pPr><w:rPr><w:sz w:val="22"/><w:szCs w:val="22"/><w:color w:val="404040"/><w:i/></w:rPr></w:style>'
        // Table style
        . '<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:basedOn w:val="TableNormal"/><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/><w:left w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/><w:right w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/><w:insideV w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/></w:tblBorders></w:tblPr></w:style>'
        // List bullet
        . '<w:style w:type="paragraph" w:styleId="ListBullet"><w:name w:val="List Bullet"/><w:basedOn w:val="Normal"/><w:pPr><w:pStyle w:val="ListParagraph"/><w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr></w:pPr></w:style>'
        . '<w:style w:type="paragraph" w:styleId="ListParagraph"><w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:left="720"/></w:pPr></w:style>'
        . '</w:styles>';
    $zip->addFromString('word/styles.xml', $stylesXml);

    // ── 7. word/document.xml ────────────────────────────────────────────
    $documentXml = buildDocumentXml($reportText, $cveId, $task, $lang);
    $zip->addFromString('word/document.xml', $documentXml);

    $zip->close();
    $bytes = file_get_contents($tmpFile);
    @unlink($tmpFile);
    return $bytes;
}


function buildDocumentXml(string $reportText, string $cveId, array $task, string $lang): string {
    $ns = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"';
    $nsR = 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"';

    $title = $lang === 'en' ? 'CVE Technical Report' : 'Informe Técnico CVE';
    $generated = $lang === 'en' ? 'Generated by OrinSec' : 'Generado por OrinSec';
    $taskLabel = $lang === 'en' ? 'Task' : 'Tarea';
    $dateLabel = $lang === 'en' ? 'Date' : 'Fecha';

    // Escapar para XML seguro
    $escTitle      = wordEscape($title);
    $escCveId      = wordEscape($cveId);
    $escTaskLabel  = wordEscape($taskLabel);
    $escDateLabel  = wordEscape($dateLabel);
    $escTaskId     = wordEscape((string)$task['id']);
    $escCreatedAt  = wordEscape((string)$task['created_at']);
    $escGenerated  = wordEscape($generated);

    // ── Portada ─────────────────────────────────────────────────────────
    $xml = <<<XML
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document {$ns} {$nsR}>
<w:body>

<!-- Portada -->
<w:p><w:pPr><w:pStyle w:val="Title"/></w:pPr><w:r><w:t>{$escTitle}</w:t></w:r></w:p>
<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:after="400"/></w:pPr>
  <w:r><w:rPr><w:rFonts w:ascii="Calibri Light" w:hAnsi="Calibri Light"/><w:b/><w:sz w:val="72"/><w:szCs w:val="72"/><w:color w:val="C00000"/></w:rPr><w:t xml:space="preserve">{$escCveId}</w:t></w:r>
</w:p>

<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:after="200"/></w:pPr>
  <w:r><w:rPr><w:color w:val="666666"/></w:rPr><w:t xml:space="preserve">{$escTaskLabel}: #{$escTaskId}  |  {$escDateLabel}: {$escCreatedAt}</w:t></w:r>
</w:p>

<w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="12" w:space="1" w:color="2E74B5"/></w:pBdr><w:spacing w:after="400"/></w:pPr></w:p>

XML;

    // ── Parsear secciones del texto box-drawing ─────────────────────────
    $lines = preg_split("/\r\n|\n/", $reportText);
    $inSection = false;
    $sectionContent = [];
    $currentSection = '';

    foreach ($lines as $line) {
        $line = rtrim($line);
        if ($line === '' || str_contains($line, '═') || str_contains($line, '╔') || str_contains($line, '╚')) {
            continue;
        }

        // Detectar inicio de sección: ┌───[ ... ]
        if (preg_match('/^[┌├└]───\[\s*([^\]]+)\s*\]/u', $line, $m)) {
            if ($currentSection && !empty($sectionContent)) {
                $xml .= renderSectionXml($currentSection, $sectionContent);
            }
            $currentSection = trim($m[1]);
            $sectionContent = [];
            $inSection = true;
            continue;
        }

        // Ignorar líneas de borde puras
        if (preg_match('/^[┌├├└│├┤├─╞╡╞═\s]+$/u', $line)) {
            continue;
        }

        // Limpiar prefijos de box-drawing
        $clean = preg_replace('/^[│├└]\s*/u', '', $line);
        $clean = preg_replace('/^\s+/', '', $clean);

        if ($clean !== '' && $inSection) {
            $sectionContent[] = $clean;
        }
    }

    // Última sección
    if ($currentSection && !empty($sectionContent)) {
        $xml .= renderSectionXml($currentSection, $sectionContent);
    }

    // ── Pie de página ───────────────────────────────────────────────────
    $xml .= <<<XML
<w:p><w:pPr><w:spacing w:before="400"/></w:pPr></w:p>
<w:p><w:pPr><w:pBdr><w:top w:val="single" w:sz="4" w:space="1" w:color="BFBFBF"/></w:pBdr><w:spacing w:before="200"/></w:pPr></w:p>
<w:p><w:pPr><w:jc w:val="center"/></w:pPr>
  <w:r><w:rPr><w:color w:val="999999"/><w:sz w:val="18"/></w:rPr><w:t xml:space="preserve">{$escGenerated} — OrinSec Cyber Intelligence</w:t></w:r>
</w:p>

<w:sectPr>
  <w:pgSz w:w="12240" w:h="15840"/>
  <w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/>
</w:sectPr>

</w:body>
</w:document>
XML;

    return $xml;
}


function renderSectionXml(string $sectionTitle, array $contentLines): string {
    $xml = '';
    $sectionTitleEsc = wordEscape(stripEmojis($sectionTitle));

    // Título de sección como Heading1
    $xml .= "<w:p><w:pPr><w:pStyle w:val=\"Heading1\"/></w:pPr><w:r><w:t>{$sectionTitleEsc}</w:t></w:r></w:p>\n";

    // Detectar si es tabla de campos clave:valor
    $isTable = true;
    $rows = [];
    foreach ($contentLines as $line) {
        if (preg_match('/^([^:]+):\s*(.+)$/u', $line, $m)) {
            $rows[] = ['label' => trim($m[1]), 'value' => trim($m[2])];
        } else {
            $isTable = false;
            break;
        }
    }

    if ($isTable && count($rows) >= 2) {
        // Renderizar como tabla profesional
        $xml .= '<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="5000" w:type="pct"/><w:tblLook w:val="04A0" w:firstRow="1" w:lastRow="0" w:firstColumn="1" w:lastColumn="0" w:noHBand="0" w:noVBand="1"/></w:tblPr><w:tblGrid>';
        $xml .= '<w:gridCol w:w="2880"/><w:gridCol w:w="7200"/></w:tblGrid>';

        foreach ($rows as $i => $row) {
            $label = wordEscape(stripEmojis($row['label']));
            $value = wordEscape(stripEmojis($row['value']));
            $isHeader = ($i === 0);
            $shd = $isHeader ? '<w:shd w:val="clear" w:color="auto" w:fill="2E74B5"/>' : '';
            $color = $isHeader ? '<w:color w:val="FFFFFF"/>' : '<w:color w:val="333333"/>';
            $bold = $isHeader ? '<w:b/>' : '';

            $xml .= '<w:tr><w:trPr><w:trHeight w:val="360"/></w:trPr>';
            // Celda label
            $xml .= "<w:tc><w:tcPr>{$shd}<w:tcW w:w=\"2880\" w:type=\"dxa\"/></w:tcPr>"
                . "<w:p><w:pPr><w:spacing w:after=\"0\"/></w:pPr><w:r><w:rPr>{$bold}{$color}</w:rPr><w:t>{$label}</w:t></w:r></w:p></w:tc>";
            // Celda value
            $xml .= "<w:tc><w:tcPr>{$shd}<w:tcW w:w=\"7200\" w:type=\"dxa\"/></w:tcPr>"
                . "<w:p><w:pPr><w:spacing w:after=\"0\"/></w:pPr><w:r><w:rPr>{$color}</w:rPr><w:t xml:space=\"preserve\">{$value}</w:t></w:r></w:p></w:tc>";
            $xml .= '</w:tr>';
        }
        $xml .= '</w:tbl>';
    } else {
        // Renderizar como párrafos normales o lista
        $isList = count($contentLines) > 1 && count(array_filter($contentLines, fn($l) => preg_match('/^[•\-\*\d]/u', $l))) > 1;

        foreach ($contentLines as $line) {
            $line = stripEmojis($line);
            $line = preg_replace('/^\s*[•\-\*]\s*/u', '', $line);

            if (preg_match('/^https?:\/\//', $line)) {
                // Link
                $url = wordEscape($line);
                $xml .= "<w:p><w:pPr><w:spacing w:after=\"80\"/></w:pPr><w:r><w:rPr><w:color w:val=\"0563C1\"/><w:u w:val=\"single\"/></w:rPr><w:t>{$url}</w:t></w:r></w:p>\n";
            } elseif (str_starts_with($line, '[') && str_ends_with($line, ']')) {
                // Placeholder
                $xml .= "<w:p><w:pPr><w:spacing w:after=\"80\"/></w:pPr><w:r><w:rPr><w:color w:val=\"999999\"/><w:i/></w:rPr><w:t>" . wordEscape($line) . "</w:t></w:r></w:p>\n";
            } else {
                $style = ($sectionTitle === '🤖 AI-Powered Risk Assessment' || $sectionTitle === 'AI-Powered Risk Assessment') ? 'Quote' : 'Normal';
                $xml .= "<w:p><w:pPr><w:pStyle w:val=\"{$style}\"/><w:spacing w:after=\"80\"/></w:pPr><w:r><w:t xml:space=\"preserve\">" . wordEscape($line) . "</w:t></w:r></w:p>\n";
            }
        }
    }

    return $xml;
}


function stripEmojis(string $text): string {
    // Eliminar emojis y caracteres de control gráfico comunes
    return preg_replace('/[\x{1F600}-\x{1F64F}\x{1F300}-\x{1F5FF}\x{1F680}-\x{1F6FF}\x{1F1E0}-\x{1F1FF}\x{2600}-\x{26FF}\x{2700}-\x{27BF}]/u', '', $text);
}


function wordEscape(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_XML1, 'UTF-8');
}
