<?php
  error_reporting(E_ALL);
  ini_set('display_errors', '1');
  echo "<pre>\n";
  echo "=== DIAGNOSTICO ===\n\n";

  $files = [
      'includes/config.php',
      'includes/db.php',
      'includes/functions.php',
      'includes/auth.php',
      'includes/rag.php',
  ];

  foreach ($files as $f) {
      echo "Probando {$f}... ";
      try {
          require_once $f;
          echo "OK\n";
      } catch (Throwable $e) {
          echo "ERROR: " . get_class($e) . ": " . $e->getMessage() . "\n";
          echo "En: " . $e->getFile() . ":" . $e->getLine() . "\n";
          break;
      }
  }
  echo "\n=== FIN ===\n";