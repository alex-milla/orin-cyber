<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

$tasks = [];
try {
    $tasks = Database::fetchAll(
        "SELECT id, task_type, status, created_at, completed_at 
         FROM tasks 
         ORDER BY created_at DESC 
         LIMIT 20"
    );
} catch (Exception $e) {
    $tasks = [];
}

$pageTitle = 'Dashboard — OrinSec';
require __DIR__ . '/templates/header.php';
?>
<div class="card">
    <h2>👋 Bienvenido, <?php echo htmlspecialchars($_SESSION['username']); ?></h2>
    <p class="small" style="color:var(--text-muted);">OrinSec — Plataforma de ciberseguridad asistida por IA local</p>
</div>

<div class="card">
    <h2>🛠️ Herramientas disponibles</h2>
    <div class="tools-grid">
        <a href="task_cve.php" class="tool-card">
            <div class="icon">🔍</div>
            <h3>Búsqueda CVE</h3>
            <p>Consulta vulnerabilidades en NVD, EPSS, CISA KEV y GitHub con análisis de IA.</p>
        </a>
        <div class="tool-card disabled">
            <div class="icon">⏳</div>
            <h3>Próximamente</h3>
            <p>Nuevas herramientas se añadirán aquí automáticamente.</p>
        </div>
    </div>
</div>

<div class="card">
    <h2>📋 Historial de tareas</h2>
    <?php if (empty($tasks)): ?>
        <p class="small">No hay tareas todavía.</p>
    <?php else: ?>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Tipo</th>
                    <th>Estado</th>
                    <th>Creada</th>
                    <th>Acción</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($tasks as $t): ?>
                <tr>
                    <td>#<?php echo $t['id']; ?></td>
                    <td><?php echo htmlspecialchars($t['task_type']); ?></td>
                    <td class="status-<?php echo $t['status']; ?>">
                        <?php echo ucfirst(htmlspecialchars($t['status'])); ?>
                    </td>
                    <td class="small"><?php echo htmlspecialchars($t['created_at']); ?></td>
                    <td>
                        <?php if ($t['status'] === 'completed' || $t['status'] === 'error'): ?>
                            <a href="task_result.php?id=<?php echo $t['id']; ?>">Ver</a>
                        <?php else: ?>
                            <span class="small">Esperando...</span>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>
<?php require __DIR__ . '/templates/footer.php'; ?>
