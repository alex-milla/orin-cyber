<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

$taskId = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$task = Database::fetchOne(
    'SELECT id, task_type, status, result_html, result_text, error_message, input_data, created_at, completed_at 
     FROM tasks WHERE id = ?',
    [$taskId]
);

if (!$task) {
    http_response_code(404);
    $pageTitle = 'No encontrado — OrinSec';
    require __DIR__ . '/templates/header.php';
    echo '<div class="card"><h2>Tarea no encontrada</h2><p><a href="index.php">Volver al inicio</a></p></div>';
    require __DIR__ . '/templates/footer.php';
    exit;
}

$safeHtml = sanitizeReportHtml($task['result_html'] ?? '');

// Detectar idioma de la tarea
$taskInput = json_decode($task['input_data'] ?? '{}', true) ?: [];
$lang = strtolower($taskInput['language'] ?? 'es');
if (!in_array($lang, ['es', 'en'], true)) {
    $lang = 'es';
}
$l = [
    'es' => [
        'title' => 'Resultado',
        'tipo' => 'Tipo',
        'estado' => 'Estado',
        'creada' => 'Creada',
        'completada' => 'Completada',
        'esperando' => 'Esperando al worker...',
        'copiar' => '📋 Copiar texto plano',
        'error' => 'Error',
        'no_encontrado' => 'No encontrado',
        'volver' => 'Volver al inicio',
        'md' => '⬇️ Markdown',
        'docx' => '⬇️ Word (.docx)',
        'sin_contenido' => 'Sin contenido HTML.',
    ],
    'en' => [
        'title' => 'Result',
        'tipo' => 'Type',
        'estado' => 'Status',
        'creada' => 'Created',
        'completada' => 'Completed',
        'esperando' => 'Waiting for worker...',
        'copiar' => '📋 Copy plain text',
        'error' => 'Error',
        'no_encontrado' => 'Not found',
        'volver' => 'Back to home',
        'md' => '⬇️ Markdown',
        'docx' => '⬇️ Word (.docx)',
        'sin_contenido' => 'No HTML content.',
    ],
][$lang];

$pageTitle = $l['title'] . ' #' . $taskId . ' — OrinSec';
require __DIR__ . '/templates/header.php';
?>
<div class="card">
    <h2><?php echo $l['title']; ?> #<?php echo $taskId; ?></h2>
    <p class="small"><?php echo $l['tipo']; ?>: <?php echo htmlspecialchars($task['task_type']); ?> | 
       <?php echo $l['estado']; ?>: <span class="status-<?php echo $task['status']; ?>"><?php echo ucfirst(htmlspecialchars($task['status'])); ?></span> | 
       <?php echo $l['creada']; ?>: <?php echo htmlspecialchars($task['created_at']); ?>
       <?php if ($task['completed_at']): ?> | <?php echo $l['completada']; ?>: <?php echo htmlspecialchars($task['completed_at']); ?><?php endif; ?>
    </p>
    
    <?php if ($task['status'] === 'pending' || $task['status'] === 'processing'): ?>
        <div id="polling-area" data-task-id="<?php echo $taskId; ?>">
            <p><?php echo $l['esperando']; ?> <span class="spinner"></span></p>
            <div id="status-message" class="small"><?php echo $l['estado']; ?>: <span class="status-<?php echo $task['status']; ?>"><?php echo $task['status']; ?></span></div>
            <div id="result-area" class="hidden">
                <div id="result-content"></div>
                <div class="actions">
                    <button onclick="copyText()"><?php echo $l['copiar']; ?></button>
                </div>
            </div>
        </div>
        <script src="assets/js/polling.js?v=2"></script>
    <?php elseif ($task['status'] === 'error'): ?>
        <div class="alert alert-error">
            <p><strong><?php echo $l['error']; ?>:</strong> <?php echo nl2br(htmlspecialchars($task['error_message'] ?? 'Unknown error')); ?></p>
        </div>
    <?php else: ?>
        <div id="result-content">
            <?php if ($safeHtml): ?>
                <?php echo $safeHtml; ?>
            <?php else: ?>
                <div class="alert alert-error" style="margin-bottom:1rem;">
                    <strong>El worker completó la tarea pero no devolvió resultado.</strong><br>
                    Causas probables:
                    <ul style="margin:.5rem 0 0 1.2rem;">
                        <li>El worker de la Orin Nano no tiene el código actualizado (falta el flujo CSV Sentinel).</li>
                        <li>El worker falló silenciosamente antes de generar el informe.</li>
                        <li>El modelo LLM no respondió (OOM, llama-server caído).</li>
                    </ul>
                    <p style="margin:.5rem 0 0;">Revisa los logs del worker en la Orin Nano y asegúrate de que tiene la última versión del código.</p>
                </div>
            <?php endif; ?>
        </div>
        <div class="actions">
            <button onclick="copyText()"><?php echo $l['copiar']; ?></button>
            <a href="export_cve.php?id=<?php echo $taskId; ?>&format=md">
                <button class="secondary" type="button"><?php echo $l['md']; ?></button>
            </a>
            <a href="export_cve.php?id=<?php echo $taskId; ?>&format=docx">
                <button class="secondary" type="button"><?php echo $l['docx']; ?></button>
            </a>
        </div>
        <textarea id="plain-text" class="visually-hidden"><?php echo htmlspecialchars($task['result_text'] ?? ''); ?></textarea>
    <?php endif; ?>
</div>
<script>
function copyText() {
    const plain = document.getElementById('plain-text');
    if (!plain) return;
    plain.select();
    document.execCommand('copy');
    alert('Texto copiado al portapapeles');
}
</script>
<?php require __DIR__ . '/templates/footer.php'; ?>
