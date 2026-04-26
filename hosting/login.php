<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

if (!file_exists(DB_PATH)) {
    header('Location: install.php');
    exit;
}

if (isLoggedIn()) {
    header('Location: index.php');
    exit;
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $user = trim($_POST['username'] ?? '');
        $pass = $_POST['password'] ?? '';
        $result = loginUser($user, $pass);
        if ($result['success']) {
            header('Location: index.php');
            exit;
        }
        $error = $result['error'];
    } catch (Exception $e) {
        $error = 'Error del servidor: ' . $e->getMessage();
    }
}

$pageTitle = 'Login — OrinSec';
require __DIR__ . '/templates/header.php';
?>
<div class="card" style="max-width:400px; margin:3rem auto;">
    <h2>Iniciar sesión</h2>
    <?php if ($error): ?>
        <p style="color:#c62828;"><?php echo htmlspecialchars($error); ?></p>
    <?php endif; ?>
    <form method="POST">
        <?php echo csrfInput(); ?>
        <label>Usuario</label>
        <input type="text" name="username" required autofocus maxlength="64" autocomplete="username">
        <label>Contraseña</label>
        <input type="password" name="password" required maxlength="128" autocomplete="current-password">
        <button type="submit" style="margin-top:1rem; width:100%;">Entrar</button>
    </form>
</div>
<?php require __DIR__ . '/templates/footer.php'; ?>
