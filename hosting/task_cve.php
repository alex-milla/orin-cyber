<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

$taskId = null;
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $product = trim($_POST['product'] ?? '');
    $version = trim($_POST['version'] ?? '');
    $year = trim($_POST['year'] ?? '');
    $severity = trim($_POST['severity'] ?? '');
    $maxResults = (int) ($_POST['max_results'] ?? 10);
    
    if ($product === '') {
        $error = 'El producto/software es obligatorio.';
    } else {
        $input = json_encode([
            'product' => $product,
            'version' => $version,
            'year' => $year,
            'severity' => $severity,
            'max_results' => $maxResults
        ], JSON_UNESCAPED_UNICODE);
        
        $taskId = Database::insert('tasks', [
            'task_type' => 'cve_search',
            'input_data' => $input,
            'status' => 'pending'
        ]);
    }
}

$pageTitle = 'Buscar CVE — OrinSec';
require __DIR__ . '/templates/header.php';
?>
<div class="card">
    <h2>🔍 Búsqueda de vulnerabilidades (CVE)</h2>
    
    <?php if ($taskId): ?>
        <div id="polling-area" data-task-id="<?php echo $taskId; ?>">
            <p>Tarea <strong>#<?php echo $taskId; ?></strong> creada. Esperando al worker...</p>
            <div class="spinner"></div>
            <div id="status-message" class="small" style="margin-top:.5rem;">Estado: <span class="status-pending">pendiente</span></div>
            <div id="result-area" style="margin-top:1rem; display:none;">
                <div id="result-content"></div>
                <div class="actions">
                    <button onclick="copyText()">📋 Copiar texto plano</button>
                    <a href="task_result.php?id=<?php echo $taskId; ?>"><button class="secondary">Ver página completa</button></a>
                </div>
            </div>
        </div>
        <script src="assets/js/polling.js"></script>
    <?php else: ?>
        <?php if ($error): ?>
            <p style="color:#c62828;"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
        <form method="POST">
            <label>Producto / Software *</label>
            <input type="text" name="product" placeholder="Ej: Apache HTTP Server" required>
            
            <label>Versión</label>
            <input type="text" name="version" placeholder="Ej: 2.4.51">
            
            <label>Año mínimo</label>
            <select name="year">
                <option value="">Cualquiera</option>
                <option value="2026">2026</option>
                <option value="2025">2025</option>
                <option value="2024">2024</option>
                <option value="2023">2023</option>
                <option value="2022">2022</option>
            </select>
            
            <label>Severidad mínima</label>
            <select name="severity">
                <option value="">Cualquiera</option>
                <option value="LOW">Baja</option>
                <option value="MEDIUM">Media</option>
                <option value="HIGH">Alta</option>
                <option value="CRITICAL">Crítica</option>
            </select>
            
            <label>Máximo de resultados</label>
            <select name="max_results">
                <option value="5">5</option>
                <option value="10" selected>10</option>
                <option value="20">20</option>
            </select>
            
            <button type="submit" style="margin-top:1rem;">Generar informe</button>
        </form>
    <?php endif; ?>
</div>
<?php require __DIR__ . '/templates/footer.php'; ?>
