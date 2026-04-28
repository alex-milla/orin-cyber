<?php
declare(strict_types=1);
header('Content-Type: application/json');
echo json_encode([
    'ok' => true,
    'method' => $_SERVER['REQUEST_METHOD'],
    'time' => date('Y-m-d H:i:s'),
    'msg' => 'Si ves esto, la ruta api/v1/ funciona correctamente.'
]);
