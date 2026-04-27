<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

class Database {
    private static ?PDO $instance = null;
    private static bool $migrated = false;

    public static function getInstance(): PDO {
        if (self::$instance === null) {
            if (!file_exists(DATA_DIR)) {
                if (!@mkdir(DATA_DIR, 0755, true)) {
                    throw new RuntimeException('No se pudo crear el directorio de datos: ' . DATA_DIR);
                }
            }
            if (!is_writable(DATA_DIR)) {
                throw new RuntimeException('El directorio de datos no tiene permisos de escritura: ' . DATA_DIR);
            }
            self::$instance = new PDO('sqlite:' . DB_PATH);
            self::$instance->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            self::$instance->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            self::$instance->exec('PRAGMA foreign_keys = ON;');
            self::ensureSchema();
        }
        return self::$instance;
    }

    /**
     * Auto-migración: asegura que todas las tablas e índices existan.
     * Idempotente — puede llamarse en cada request sin riesgo.
     */
    private static function ensureSchema(): void {
        if (self::$migrated) return;
        self::$migrated = true;
        $db = self::$instance;
        if (!$db) return;

        // Tabla de configuración
        $db->exec("CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT
        )");

        // Usuarios
        $db->exec("CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        // API keys
        $db->exec("CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            api_key TEXT NOT NULL UNIQUE,
            is_active INTEGER DEFAULT 1,
            last_used TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        // Tareas
        $db->exec("CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_type TEXT NOT NULL,
            input_data TEXT,
            status TEXT DEFAULT 'pending',
            result_html TEXT,
            result_text TEXT,
            error_message TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            started_at TEXT,
            completed_at TEXT
        )");

        // Heartbeats
        $db->exec("CREATE TABLE IF NOT EXISTS worker_heartbeats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key_id INTEGER NOT NULL,
            hostname TEXT,
            ip_address TEXT,
            cpu_percent REAL,
            memory_percent REAL,
            memory_total_mb INTEGER,
            memory_used_mb INTEGER,
            gpu_info TEXT,
            temperature_c REAL,
            disk_percent REAL,
            model_loaded TEXT,
            available_models TEXT,
            uptime_seconds INTEGER,
            status TEXT DEFAULT 'online',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        // Comandos
        $db->exec("CREATE TABLE IF NOT EXISTS worker_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key_id INTEGER NOT NULL,
            command TEXT NOT NULL,
            payload TEXT,
            executed_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        // Alertas — Fase C
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

        // Índices Fase A + C
        $db->exec("CREATE INDEX IF NOT EXISTS idx_tasks_status_created ON tasks(status, created_at)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_apikeys_key_active ON api_keys(api_key, is_active)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_workerhb_apikey_created ON worker_heartbeats(api_key_id, created_at)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_workercommands_apikey_executed ON worker_commands(api_key_id, executed_at)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_alerts_cve ON alerts(cve_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_alerts_read ON alerts(read_at)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_subs_user ON alert_subscriptions(user_id, active)");

        // Migraciones de columnas para tablas existentes
        self::_addColumnIfNotExists('worker_heartbeats', 'available_models', 'TEXT');
    }

    private static function _addColumnIfNotExists(string $table, string $column, string $type): void {
        $db = self::$instance;
        if (!$db) return;
        try {
            $cols = $db->query("PRAGMA table_info({$table})")->fetchAll(PDO::FETCH_COLUMN, 1);
            if (!in_array($column, $cols, true)) {
                $db->exec("ALTER TABLE {$table} ADD COLUMN {$column} {$type}");
            }
        } catch (PDOException $e) {
            // Ignorar si la tabla no existe todavía
        }
    }

    public static function query(string $sql, array $params = []): PDOStatement {
        $db = self::getInstance();
        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }

    public static function insert(string $table, array $data): int {
        $columns = implode(', ', array_keys($data));
        $placeholders = implode(', ', array_fill(0, count($data), '?'));
        $sql = "INSERT INTO {$table} ({$columns}) VALUES ({$placeholders})";
        self::query($sql, array_values($data));
        return (int) self::getInstance()->lastInsertId();
    }

    public static function fetchOne(string $sql, array $params = []): ?array {
        $stmt = self::query($sql, $params);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public static function fetchAll(string $sql, array $params = []): array {
        $stmt = self::query($sql, $params);
        return $stmt->fetchAll();
    }

    public static function update(string $table, array $data, string $where, array $whereParams = []): int {
        $sets = [];
        foreach (array_keys($data) as $col) {
            $sets[] = "{$col} = ?";
        }
        $sql = "UPDATE {$table} SET " . implode(', ', $sets) . " WHERE {$where}";
        $stmt = self::query($sql, array_merge(array_values($data), $whereParams));
        return $stmt->rowCount();
    }
}
