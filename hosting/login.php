<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/auth.php';

if (isLoggedIn()) {
    header('Location: index.php');
    exit;
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = trim($_POST['username'] ?? '');
    $pass = $_POST['password'] ?? '';
    if (loginUser($user, $pass)) {
        header('Location: index.php');
        exit;
    }
    $error = 'Usuario o contraseña incorrectos.';
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
        <label>Usuario</label>
        <input type="text" name="username" required autofocus>
        <label>Contraseña</label>
        <input type="password" name="password" required>
        <button type="submit" style="margin-top:1rem; width:100%;">Entrar</button>
    </form>
</div>
<?php require __DIR__ . '/templates/footer.php'; ?>
