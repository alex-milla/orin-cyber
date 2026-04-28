<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

$tunnelUrl = 'https://chat-orin.cyberintelligence.dev';

$pageTitle = 'Chat — OrinSec';
require_once __DIR__ . '/templates/header.php';
?>

<h2>💬 Chat con el modelo</h2>
<p class="text-muted">Interfaz directa del modelo a través de Cloudflare Tunnel (protegido con MFA).</p>

<div style="margin-top: 2rem; padding: 2rem; border: 2px dashed var(--border); border-radius: .75rem; text-align: center; background: var(--bg-secondary);">
    <p style="font-size: 1.1rem; margin-bottom: 1.5rem;">
        El chat se abre en una ventana segura protegida por Cloudflare Access.<br>
        Se te pedirá un código de verificación por email.
    </p>
    <a href="<?php echo htmlspecialchars($tunnelUrl, ENT_QUOTES, 'UTF-8'); ?>" target="_blank" rel="noopener noreferrer" class="btn btn-primary" style="font-size: 1.1rem; padding: .75rem 1.5rem;">
        🚀 Abrir Chat en nueva pestaña
    </a>
</div>

<?php require_once __DIR__ . '/templates/footer.php'; ?>
