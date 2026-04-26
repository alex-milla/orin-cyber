<?php
declare(strict_types=1);
if (!isset($pageTitle)) $pageTitle = 'OrinSec';
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($pageTitle); ?></title>
    <style>
        :root { --primary:#1a237e; --accent:#00acc1; --bg:#f5f7fa; --card:#fff; --text:#333; --border:#ddd; }
        * { box-sizing: border-box; }
        body { margin:0; font-family: system-ui,-apple-system,sans-serif; background:var(--bg); color:var(--text); line-height:1.5; }
        header { background:var(--primary); color:#fff; padding:1rem 2rem; display:flex; justify-content:space-between; align-items:center; }
        header h1 { margin:0; font-size:1.3rem; }
        header nav a { color:#fff; text-decoration:none; margin-left:1.5rem; opacity:.9; }
        header nav a:hover { opacity:1; text-decoration:underline; }
        main { max-width:900px; margin:2rem auto; padding:0 1rem; }
        .card { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:1.5rem; margin-bottom:1.5rem; box-shadow:0 2px 4px rgba(0,0,0,.04); }
        h2 { margin-top:0; color:var(--primary); }
        label { display:block; margin:.8rem 0 .3rem; font-weight:600; font-size:.9rem; }
        input, select, textarea { width:100%; padding:.55rem; border:1px solid var(--border); border-radius:4px; font:inherit; }
        button { background:var(--accent); color:#fff; border:none; padding:.65rem 1.4rem; border-radius:4px; font:inherit; cursor:pointer; }
        button:hover { filter:brightness(1.1); }
        .small { font-size:.85rem; color:#666; }
        .spinner { display:inline-block; width:18px; height:18px; border:2px solid #ccc; border-top-color:var(--accent); border-radius:50%; animation:spin 1s linear infinite; vertical-align:middle; margin-left:.5rem; }
        @keyframes spin { to { transform:rotate(360deg); } }
        .status-pending { color:#f57c00; }
        .status-processing { color:#1976d2; }
        .status-completed { color:#388e3c; }
        .status-error { color:#c62828; }
        pre { background:#f5f5f5; padding:1rem; border-radius:4px; overflow-x:auto; }
        .actions { margin-top:1rem; }
        .actions button { margin-right:.5rem; }
        .secondary { background:#78909c; }
    </style>
</head>
<body>
<header>
    <h1>🔒 OrinSec</h1>
    <?php if (isLoggedIn()): ?>
    <nav>
        <a href="index.php">Inicio</a>
        <a href="task_cve.php">Buscar CVE</a>
        <span style="opacity:.7;">Hola, <?php echo htmlspecialchars($_SESSION['username']); ?></span>
        <a href="logout.php">Salir</a>
    </nav>
    <?php endif; ?>
</header>
<main>
