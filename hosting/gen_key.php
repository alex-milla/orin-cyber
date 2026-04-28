<?php
declare(strict_types=1);
header('Content-Type: text/plain; charset=utf-8');
echo bin2hex(random_bytes(32));
