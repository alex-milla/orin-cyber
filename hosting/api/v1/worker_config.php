<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/auth.php';

$keyRow = requireApiKey();

$pref = Database::fetchOne("SELECT value FROM config WHERE key = 'preferred_model'");
jsonResponse([
    'preferred_model' => $pref['value'] ?? null,
]);
