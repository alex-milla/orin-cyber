<?php
declare(strict_types=1);
if (!isset($pageTitle)) $pageTitle = 'OrinSec';
?>
<!DOCTYPE html>
<html lang="es" data-theme="system">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($pageTitle); ?></title>
    <link rel="stylesheet" href="assets/css/style.css?v=2">
    <script>
    (function() {
        const saved = localStorage.getItem('orinsec-theme') || 'system';
        document.documentElement.setAttribute('data-theme', saved);
    })();
    function setTheme(mode) {
        document.documentElement.setAttribute('data-theme', mode);
        localStorage.setItem('orinsec-theme', mode);
        document.querySelectorAll('.theme-switcher button').forEach(b => b.classList.toggle('active', b.dataset.theme === mode));
    }
    document.addEventListener('DOMContentLoaded', function() {
        const saved = localStorage.getItem('orinsec-theme') || 'system';
        setTheme(saved);
    });
    </script>
</head>
<body>
<header>
    <h1>🔒 OrinSec</h1>
    <?php if (isLoggedIn()): ?>
    <nav>
        <a href="index.php">Inicio</a>
        <a href="task_cve.php">Buscar CVE</a>
        <?php if (isAdmin()): ?><a href="admin.php">Admin</a><?php endif; ?>
        <span class="user-greeting">Hola, <?php echo htmlspecialchars($_SESSION['username']); ?></span>
        <a href="logout.php">Salir</a>
        <div class="theme-switcher">
            <button data-theme="light" onclick="setTheme('light')" title="Claro">☀️</button>
            <button data-theme="dark" onclick="setTheme('dark')" title="Oscuro">🌙</button>
            <button data-theme="system" onclick="setTheme('system')" title="Sistema">💻</button>
        </div>
    </nav>
    <?php else: ?>
    <nav>
        <div class="theme-switcher">
            <button data-theme="light" onclick="setTheme('light')" title="Claro">☀️</button>
            <button data-theme="dark" onclick="setTheme('dark')" title="Oscuro">🌙</button>
            <button data-theme="system" onclick="setTheme('system')" title="Sistema">💻</button>
        </div>
    </nav>
    <?php endif; ?>
</header>
<main>
