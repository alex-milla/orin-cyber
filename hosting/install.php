<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';

header('Content-Type: text/html; charset=utf-8');

$installed = file_exists(DB_PATH);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$installed) {
    try {
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

        $adminUser = $_POST['admin_user'] ?? 'admin';
        $adminPass = $_POST['admin_pass'] ?? generateSecureToken(16);
        $hash = password_hash($adminPass, PASSWORD_BCRYPT);
        
        $db->prepare("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)")
           ->execute([$adminUser, $hash]);

        $success = true;
        $message = "Instalación completada. API Key: {$apiKey}. Usuario admin: {$adminUser} / {$adminPass}";
    } catch (Exception $e) {
        $error = $e->getMessage();
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
        .ok { color: #2e7d32; background: #e8f5e9; padding: 1rem; border-radius: 4px; }
        .err { color: #c62828; background: #ffebee; padding: 1rem; border-radius: 4px; }
        code { background: #f5f5f5; padding: .2rem .4rem; border-radius: 3px; word-break: break-all; }
    </style>
</head>
<body>
    <div class="box">
        <h1>🛠️ Instalación OrinSec</h1>
        <?php if ($installed): ?>
            <p class="ok">La base de datos ya existe. No es necesario reinstalar.</p>
        <?php elseif (isset($success)): ?>
            <p class="ok"><?php echo htmlspecialchars($message); ?></p>
            <p><strong>Guarda la API key y las credenciales. No se mostrarán de nuevo.</strong></p>
            <p><a href="login.php">Ir al login</a></p>
        <?php else: ?>
            <?php if (isset($error)): ?>
                <p class="err">Error: <?php echo htmlspecialchars($error); ?></p>
            <?php endif; ?>
            <form method="POST">
                <label>Usuario administrador</label>
                <input type="text" name="admin_user" value="admin" required>
                <label>Contraseña administrador</label>
                <input type="password" name="admin_pass" placeholder="Dejar en blanco para generar aleatoria">
                <button type="submit">Instalar</button>
            </form>
        <?php endif; ?>
    </div>
</body>
</html>
