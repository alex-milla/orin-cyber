<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

if (isLoggedIn()) {
    header('Location: index.php');
    exit;
}

// Si no existe la base de datos, redirigir a instalador
if (!file_exists(DB_PATH)) {
    header('Location: install.php');
    exit;
}

// Comprobar si el registro está permitido
$allowReg = Database::fetchOne("SELECT value FROM config WHERE key = 'allow_registration'");
$registrationOpen = !$allowReg || $allowReg['value'] === '1';

// Si no hay usuarios en el sistema, permitir registro del primer admin siempre
$userCount = Database::fetchOne("SELECT COUNT(*) as c FROM users")['c'] ?? 0;
$isFirstUser = ((int)$userCount) === 0;
if ($isFirstUser) {
    $registrationOpen = true;
}

$error = '';
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($registrationOpen || $isFirstUser)) {
    $username = validateInput($_POST['username'] ?? '', 64);
    $password = $_POST['password'] ?? '';
    $password2 = $_POST['password_confirm'] ?? '';

    if (!$username || strlen($username) < 3) {
        $error = 'Usuario inválido (mínimo 3 caracteres, solo letras, números, guiones, puntos y @)';
    } elseif (strlen($password) < 8) {
        $error = 'La contraseña debe tener al menos 8 caracteres';
    } elseif ($password !== $password2) {
        $error = 'Las contraseñas no coinciden';
    } else {
        $admin = $isFirstUser; // El primer usuario siempre es admin
        if (registerUser($username, $password, $admin)) {
            // Si es el primer usuario, marcar instalación como completa y cerrar registro
            if ($isFirstUser) {
                Database::query("INSERT OR REPLACE INTO config (key, value) VALUES ('allow_registration', '0')");
                $lockFile = DATA_DIR . '/.installed';
                if (!file_exists($lockFile)) {
                    file_put_contents($lockFile, date('c'));
                }
            }
            $success = true;
        } else {
            $error = 'El usuario ya existe';
        }
    }
}

$pageTitle = 'Registro — OrinSec';
require __DIR__ . '/templates/header.php';
?>
<div class="card" style="max-width:400px; margin:3rem auto;">
    <h2>Crear cuenta</h2>
    
    <?php if ($success): ?>
        <p style="color:#2e7d32;">✅ Cuenta creada correctamente.</p>
        <p><a href="login.php"><button style="width:100%;">Ir al login</button></a></p>
    <?php elseif (!$registrationOpen && !$isFirstUser): ?>
        <p style="color:#c62828;">El registro público está desactivado. Contacta con un administrador para que te cree una cuenta.</p>
        <p><a href="login.php">Volver al login</a></p>
    <?php else: ?>
        <?php if ($isFirstUser): ?>
            <p class="small" style="color:var(--accent);">🔧 No hay usuarios en el sistema. Al registrarte serás el <strong>administrador principal</strong>.</p>
        <?php endif; ?>
        <?php if ($error): ?>
            <p style="color:#c62828;"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
        <form method="POST">
            <?php echo csrfInput(); ?>
            <label>Usuario</label>
            <input type="text" name="username" required maxlength="64" pattern="[\w\-.@]+" autocomplete="username">
            <label>Contraseña</label>
            <input type="password" name="password" required minlength="8" maxlength="128" autocomplete="new-password">
            <label>Confirmar contraseña</label>
            <input type="password" name="password_confirm" required minlength="8" maxlength="128" autocomplete="new-password">
            <button type="submit" style="margin-top:1rem; width:100%;">Crear cuenta</button>
        </form>
        <p style="text-align:center; margin-top:1rem;"><a href="login.php">Ya tengo cuenta</a></p>
    <?php endif; ?>
</div>
<?php require __DIR__ . '/templates/footer.php'; ?>
