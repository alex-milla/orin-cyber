<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

// Lee la URL del llama-server configurada en Admin → Workers
$configRow = Database::fetchOne("SELECT value FROM config WHERE key = 'local_llm_url'");
$chatUrl = $configRow['value'] ?? '';

if ($chatUrl !== '') {
    header('Location: ' . $chatUrl);
    exit;
}

// Si no hay URL configurada, mostrar instrucciones
$pageTitle = 'Chat — OrinSec';
require_once __DIR__ . '/templates/header.php';
?>
<div class="card" style="max-width:600px;margin:3rem auto;text-align:center;">
    <h2>💬 Chat con el modelo local</h2>
    <p class="small" style="color:var(--text-secondary);margin:1.5rem 0;">
        El chat se sirve directamente desde el <strong>llama-server</strong> del Orin Nano
        a través de tu túnel de Cloudflare.
    </p>
    <div class="alert alert-warning" style="text-align:left;">
        <strong>⚠️ URL del llama-server no configurada</strong><br>
        Ve a <strong>Admin → Workers → URL del llama-server (Chat Local)</strong> y establece la URL
        de tu túnel (por ejemplo: <code>https://chat-orin.cyberintelligence.dev</code>).
    </div>
    <?php if (isAdmin()): ?>
    <p style="margin-top:1.5rem;">
        <a href="admin.php"><button>Ir al Admin →</button></a>
    </p>
    <?php endif; ?>
</div>
<?php require_once __DIR__ . '/templates/footer.php'; ?>
