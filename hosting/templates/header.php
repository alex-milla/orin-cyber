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
    <link rel="stylesheet" href="assets/css/style.css?v=3">
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
    <h1><a href="index.php" style="text-decoration:none;color:inherit;">🔒 OrinSec</a></h1>
    <?php if (isLoggedIn()): ?>
    <nav>
        <a href="index.php">Inicio</a>
        <div class="dropdown" id="tools-dropdown">
            <span class="dropdown-toggle" onclick="event.stopPropagation();document.getElementById('tools-dropdown').classList.toggle('open');">Herramientas <span class="dropdown-arrow">▾</span></span>
            <div class="dropdown-menu">
                <div class="dropdown-menu-inner">
                    <a href="task_cve.php">🔍 Búsqueda CVE</a>
                </div>
            </div>
        </div>
        <?php if (isAdmin()): ?><a href="admin.php">Admin</a><?php endif; ?>
        <span class="user-greeting">Hola, <?php echo htmlspecialchars($_SESSION['username']); ?></span>
        <a href="logout.php">Salir</a>
        <div class="theme-switcher">
            <button data-theme="light" onclick="setTheme('light')" title="Claro">☀️</button>
            <button data-theme="dark" onclick="setTheme('dark')" title="Oscuro">🌙</button>
            <button data-theme="system" onclick="setTheme('system')" title="Sistema">💻</button>
        </div>
    </nav>
    <script>
    document.addEventListener('click', function() {
        document.getElementById('tools-dropdown').classList.remove('open');
    });
    </script>
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
