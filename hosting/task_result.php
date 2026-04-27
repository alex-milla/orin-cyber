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

$pageTitle = 'Resultado #' . $taskId . ' — OrinSec';
require __DIR__ . '/templates/header.php';
?>
<div class="card">
    <h2>Resultado tarea #<?php echo $taskId; ?></h2>
    <p class="small">Tipo: <?php echo htmlspecialchars($task['task_type']); ?> | 
       Estado: <span class="status-<?php echo $task['status']; ?>"><?php echo ucfirst($task['status']); ?></span> | 
       Creada: <?php echo htmlspecialchars($task['created_at']); ?>
       <?php if ($task['completed_at']): ?> | Completada: <?php echo htmlspecialchars($task['completed_at']); ?><?php endif; ?>
    </p>
    
    <?php if ($task['status'] === 'pending' || $task['status'] === 'processing'): ?>
        <div id="polling-area" data-task-id="<?php echo $taskId; ?>">
            <p>Esperando al worker... <span class="spinner"></span></p>
            <div id="status-message" class="small">Estado: <span class="status-<?php echo $task['status']; ?>"><?php echo $task['status']; ?></span></div>
            <div id="result-area" class="hidden">
                <div id="result-content"></div>
                <div class="actions">
                    <button onclick="copyText()">📋 Copiar texto plano</button>
                </div>
            </div>
        </div>
        <script src="assets/js/polling.js"></script>
    <?php elseif ($task['status'] === 'error'): ?>
        <div class="alert alert-error">
            <p><strong>Error:</strong> <?php echo nl2br(htmlspecialchars($task['error_message'] ?? 'Error desconocido')); ?></p>
        </div>
    <?php else: ?>
        <div id="result-content">
            <?php echo $safeHtml ?: '<p class="small">Sin contenido HTML.</p>'; ?>
        </div>
        <div class="actions">
            <button onclick="copyText()">📋 Copiar texto plano</button>
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
