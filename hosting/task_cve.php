<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

$taskId = null;
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verificar CSRF
    $token = $_POST['csrf_token'] ?? '';
    if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        $error = 'Token de seguridad inválido. Recarga la página.';
    } else {
        $cveId = validateInput($_POST['cve_id'] ?? '', 50, '/^CVE-\d{4}-\d+$/i') ?: '';
        $product = validateInput($_POST['product'] ?? '', 100);
        $version = validateInput($_POST['version'] ?? '', 50, '/^[\w\s\.\-+_\/]+$/u') ?: '';
        $year = validateInput($_POST['year'] ?? '', 4, '/^\d{0,4}$/') ?: '';
        $severity = validateInput($_POST['severity'] ?? '', 10, '/^(LOW|MEDIUM|HIGH|CRITICAL)?$/') ?: '';
        $maxResults = filter_input(INPUT_POST, 'max_results', FILTER_VALIDATE_INT) ?: 10;
        $maxResults = max(1, min($maxResults, 20));
        
        if (!$cveId && !$product) {
            $error = 'Introduce un CVE ID o un producto/software.';
        } else {
            $input = json_encode([
                'cve_id' => $cveId,
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
            <div id="status-message" class="small mt-1">Estado: <span class="status-pending">pendiente</span></div>
            <div id="result-area" class="mt-2 hidden">
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
            <p class="alert alert-error"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
        <form method="POST">
            <?php echo csrfInput(); ?>
            <label>CVE ID (búsqueda directa)</label>
            <input type="text" name="cve_id" placeholder="Ej: CVE-2024-3393" maxlength="50" pattern="CVE-\d{4}-\d+" title="Formato: CVE-YYYY-NNNNN">
            <p class="small">Si introduces un CVE ID, se ignoran los demás campos y se busca directamente.</p>

            <label>Producto / Software *</label>
            <input type="text" name="product" placeholder="Ej: Apache HTTP Server" maxlength="100">
            
            <label>Versión</label>
            <input type="text" name="version" placeholder="Ej: 2.4.51" maxlength="50">
            
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
            
            <button type="submit" class="mt-2">Generar informe</button>
        </form>
    <?php endif; ?>
</div>
<?php require __DIR__ . '/templates/footer.php'; ?>
