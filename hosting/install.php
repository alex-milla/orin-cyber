<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';

$lockFile = DATA_DIR . '/.installed';
$alreadyInstalled = file_exists(DB_PATH) || file_exists($lockFile);

if ($alreadyInstalled) {
    http_response_code(403);
    header('Content-Type: text/html; charset=utf-8');
    echo '<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><title>Instalación completada</title>'
        . '<style>body{font-family:system-ui,sans-serif;max-width:600px;margin:3rem auto;padding:0 1rem;text-align:center;}'
        . '.box{border:1px solid #ddd;border-radius:8px;padding:1.5rem;}'
        . '.ok{color:#2e7d32;background:#e8f5e9;padding:1rem;border-radius:4px;}</style></head>'
        . '<body><div class="box"><h1>✅ OrinSec ya está instalado</h1>'
        . '<p class="ok">El sistema ya está configurado. Si necesitas reinstalar, elimina <code>data/orinsec.db</code> y <code>data/.installed</code>.</p>'
        . '<p><a href="login.php">Ir al login</a></p></div></body></html>';
    exit;
}

header('Content-Type: text/html; charset=utf-8');

$error = '';
$success = false;
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validar CSRF
    $token = $_POST['csrf_token'] ?? '';
    if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        $error = 'Token de seguridad inválido. Recarga la página.';
    } else {
        try {
            $adminUser = validateInput($_POST['admin_user'] ?? '', 64);
            $adminPass = $_POST['admin_pass'] ?? '';
            
            if (!$adminUser || strlen($adminUser) < 3) {
                throw new RuntimeException('Usuario inválido (mínimo 3 caracteres, solo letras, números, guiones y puntos)');
            }
            if ($adminPass !== '' && strlen($adminPass) < 8) {
                throw new RuntimeException('La contraseña debe tener al menos 8 caracteres');
            }
            if ($adminPass === '') {
                $adminPass = generateSecureToken(16);
            }

            $db = Database::getInstance();

            $db->exec("CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_type TEXT NOT NULL,
                input_data TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                result_html TEXT,
                result_text TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                started_at DATETIME,
                completed_at DATETIME,
                error_message TEXT
            )");

            $db->exec("CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )");

            $db->exec("CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )");

            $apiKey = generateSecureToken(32);
            $db->prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)")
               ->execute(['api_key', $apiKey]);

            $version = '0.1.0';
            $db->prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)")
               ->execute(['version', $version]);

            $hash = password_hash($adminPass, PASSWORD_BCRYPT);
            $db->prepare("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)")
               ->execute([$adminUser, $hash]);

            file_put_contents($lockFile, date('c'));

            $self = __FILE__;
            $renamed = @rename($self, $self . '.bak');

            $success = true;
            $message = "Instalación completada. API Key: {$apiKey}. Usuario admin: {$adminUser} / {$adminPass}";
            if (!$renamed) {
                $message .= "\nNota: No se pudo renombrar install.php automáticamente. Por seguridad, renómbralo manualmente a install.php.bak";
            }
        } catch (Exception $e) {
            $error = $e->getMessage();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Instalación OrinSec</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 600px; margin: 3rem auto; padding: 0 1rem; }
        .box { border: 1px solid #ddd; border-radius: 8px; padding: 1.5rem; }
        input { width: 100%; padding: .5rem; margin: .5rem 0 1rem; box-sizing: border-box; }
        button { padding: .6rem 1.2rem; cursor: pointer; }
        .ok { color: #2e7d32; background: #e8f5e9; padding: 1rem; border-radius: 4px; word-break: break-all; }
        .err { color: #c62828; background: #ffebee; padding: 1rem; border-radius: 4px; }
        code { background: #f5f5f5; padding: .2rem .4rem; border-radius: 3px; word-break: break-all; }
    </style>
</head>
<body>
    <div class="box">
        <h1>🛠️ Instalación OrinSec</h1>
        <?php if ($success): ?>
            <p class="ok"><?php echo nl2br(htmlspecialchars($message)); ?></p>
            <p><strong>Guarda la API key y las credenciales. No se mostrarán de nuevo.</strong></p>
            <p><a href="login.php">Ir al login</a></p>
        <?php else: ?>
            <?php if ($error): ?>
                <p class="err">Error: <?php echo htmlspecialchars($error); ?></p>
            <?php endif; ?>
            <form method="POST">
                <?php echo csrfInput(); ?>
                <label>Usuario administrador</label>
                <input type="text" name="admin_user" value="admin" required maxlength="64" pattern="[\w\-.@]+" title="Letras, números, guiones, puntos y @">
                <label>Contraseña administrador</label>
                <input type="password" name="admin_pass" placeholder="Dejar en blanco para generar aleatoria (mín. 8 chars)">
                <button type="submit">Instalar</button>
            </form>
        <?php endif; ?>
    </div>
</body>
</html>
