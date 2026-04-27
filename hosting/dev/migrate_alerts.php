<?php
/**
 * Migración: crea tablas para sistema de alertas (Fase C).
 * Ejecutar una sola vez tras actualizar a v0.6.1+.
 */
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';

requireAdmin();

header('Content-Type: text/plain; charset=utf-8');

try {
    $db = Database::getInstance();

    $db->exec("CREATE TABLE IF NOT EXISTS alert_subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL DEFAULT 1,
        type TEXT NOT NULL CHECK(type IN ('product','vendor','keyword','severity')),
        value TEXT NOT NULL,
        severity_threshold TEXT DEFAULT 'LOW',
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )");

    $db->exec("CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT,
        score REAL,
        epss_score REAL,
        kev INTEGER DEFAULT 0,
        source TEXT DEFAULT 'NVD',
        matched_subscription TEXT,
        read_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )");

    $db->exec("CREATE INDEX IF NOT EXISTS idx_alerts_cve ON alerts(cve_id)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_alerts_read ON alerts(read_at)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_subs_user ON alert_subscriptions(user_id, active)");

    echo "OK: Tablas alert_subscriptions y alerts creadas con índices.\n";
} catch (Exception $e) {
    echo "ERROR: " . $e->getMessage() . "\n";
    exit(1);
}
