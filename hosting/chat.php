<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

// ── URL DEL TÚNEL CLOUDFLARE ──
$tunnelUrl = 'https://chat-orin.cyberintelligence.dev';

$pageTitle = 'Chat — OrinSec';
require_once __DIR__ . '/templates/header.php';
?>

<h2>💬 Chat con el modelo</h2>

<?php if (empty($tunnelUrl)): ?>
    <div class="alert alert-info" style="margin-top:1rem;">
        <strong>Túnel no configurado.</strong><br>
        El chat ahora se sirve directamente desde el Orin mediante Cloudflare Tunnel.<br>
        Completa los pasos de instalación en el Orin y actualiza la variable
        <code>$tunnelUrl</code> en este archivo con la URL del túnel.
    </div>
<?php else: ?>
    <p class="text-muted">Interfaz directa del modelo a través de Cloudflare Tunnel.</p>
    <div style="width:100%; height: calc(100vh - 200px); min-height: 500px; margin-top: .5rem;">
        <iframe src="<?php echo htmlspecialchars($tunnelUrl, ENT_QUOTES, 'UTF-8'); ?>"
                style="width:100%; height:100%; border:1px solid var(--border); border-radius:.5rem;"
                allow="clipboard-write">
        </iframe>
    </div>
<?php endif; ?>

<?php require_once __DIR__ . '/templates/footer.php'; ?>
