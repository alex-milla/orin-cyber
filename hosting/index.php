<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

$tasks = Database::fetchAll(
    "SELECT id, task_type, status, created_at, completed_at 
     FROM tasks 
     ORDER BY created_at DESC 
     LIMIT 20"
);

$pageTitle = 'Dashboard — OrinSec';
require __DIR__ . '/templates/header.php';
?>
<div class="card">
    <h2>Panel principal</h2>
    <p>Bienvenido, <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong>.</p>
    <p><a href="task_cve.php"><button>➕ Nueva búsqueda de CVE</button></a></p>
    <?php if (isAdmin()): ?>
    <p><a href="admin.php"><button class="secondary">⚙️ Panel de administración</button></a></p>
    <?php endif; ?>
</div>

<div class="card">
    <h2>Historial de tareas</h2>
    <?php if (empty($tasks)): ?>
        <p class="small">No hay tareas todavía.</p>
    <?php else: ?>
        <table style="width:100%; border-collapse:collapse;">
            <thead>
                <tr style="border-bottom:2px solid #ddd;">
                    <th style="text-align:left; padding:.5rem;">ID</th>
                    <th style="text-align:left; padding:.5rem;">Tipo</th>
                    <th style="text-align:left; padding:.5rem;">Estado</th>
                    <th style="text-align:left; padding:.5rem;">Creada</th>
                    <th style="text-align:left; padding:.5rem;">Acción</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($tasks as $t): ?>
                <tr style="border-bottom:1px solid #eee;">
                    <td style="padding:.5rem;">#<?php echo $t['id']; ?></td>
                    <td style="padding:.5rem;"><?php echo htmlspecialchars($t['task_type']); ?></td>
                    <td style="padding:.5rem;" class="status-<?php echo $t['status']; ?>">
                        <?php echo ucfirst(htmlspecialchars($t['status'])); ?>
                    </td>
                    <td style="padding:.5rem;" class="small"><?php echo htmlspecialchars($t['created_at']); ?></td>
                    <td style="padding:.5rem;">
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
