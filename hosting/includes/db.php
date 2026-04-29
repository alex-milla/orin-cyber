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
            recent_logs TEXT,
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

        // Catálogo de modelos (etiquetas legibles) — Fase 4
        $db->exec("CREATE TABLE IF NOT EXISTS model_catalog (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL UNIQUE,
            label TEXT NOT NULL,
            tier TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_modelcatalog_pattern ON model_catalog(pattern)");

        // Inserts iniciales (idempotentes: IGNORE en UNIQUE conflict)
        // Los patrones usan el nombre de archivo GGUF para evitar falsos positivos.
        $defaults = [
            ['*qwen3.5*4b*', 'Qwen 4B', 'small'],
            ['*qwen3.5*9b*', 'Qwen 9B', 'large'],
            ['*phi*4*', 'Phi-4', 'small'],
            ['*gemma*4b*', 'Gemma 4B', 'small'],
            ['*glm*', 'GLM-4.6V', 'large'],
            ['*deepseek*7b*', 'DeepSeek 7B', 'medium'],
            ['*granite*8b*', 'Granite 8B', 'medium'],
            ['*mimo*7b*', 'MiMo-VL 7B', 'large'],
            ['*nemotron*4b*', 'Nemotron 4B', 'small'],
        ];
        $stmt = $db->prepare("INSERT OR IGNORE INTO model_catalog (pattern, label, tier) VALUES (?, ?, ?)");
        foreach ($defaults as $row) {
            $stmt->execute($row);
        }

        // Proveedores externos (APIs cloud)
        $db->exec("CREATE TABLE IF NOT EXISTS external_providers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            label TEXT NOT NULL,
            base_url TEXT NOT NULL,
            api_key_encrypted TEXT NOT NULL,
            api_key_hint TEXT,
            is_active INTEGER DEFAULT 1,
            timeout_seconds INTEGER DEFAULT 60,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS external_models (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_id INTEGER NOT NULL,
            model_id TEXT NOT NULL,
            label TEXT NOT NULL,
            context_window INTEGER DEFAULT 8192,
            cost_per_1k_input REAL,
            cost_per_1k_output REAL,
            is_active INTEGER DEFAULT 1,
            tags TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (provider_id) REFERENCES external_providers(id) ON DELETE CASCADE,
            UNIQUE(provider_id, model_id)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS external_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            provider_id INTEGER NOT NULL,
            model_id TEXT NOT NULL,
            tokens_input INTEGER DEFAULT 0,
            tokens_output INTEGER DEFAULT 0,
            cost_usd REAL,
            duration_ms INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        // Conversaciones y mensajes de chat (histórico)
        $db->exec("CREATE TABLE IF NOT EXISTS chat_conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT,
            system_prompt TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user','assistant','system')),
            content TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (conversation_id) REFERENCES chat_conversations(id) ON DELETE CASCADE
        )");

        // Índices externos + chat
        $db->exec("CREATE INDEX IF NOT EXISTS idx_extusage_user_date ON external_usage(user_id, created_at DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_extusage_provider_date ON external_usage(provider_id, created_at DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_extmodels_active ON external_models(provider_id, is_active)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_chatconv_user ON chat_conversations(user_id, updated_at DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_chatmsg_conv ON chat_messages(conversation_id, created_at)");

        // ─── BLUE TEAM INTELLIGENCE ─────────────────────────────────────────
        // Entidades monitoreadas
        $db->exec("CREATE TABLE IF NOT EXISTS entities (
            entity_id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT CHECK(entity_type IN ('user','device','ip','application','domain','url','hash')),
            entity_value TEXT UNIQUE NOT NULL,
            first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            total_incidents INTEGER DEFAULT 0,
            current_risk_score REAL DEFAULT 0.0,
            baseline_profile TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        // Incidentes procesados
        $db->exec("CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            sentinel_number TEXT,
            title TEXT,
            description TEXT,
            severity TEXT,
            status TEXT DEFAULT 'open',
            source TEXT DEFAULT 'manual',
            created_time TEXT,
            llm_verdict TEXT CHECK(llm_verdict IN ('True Positive','False Positive','Needs Review')),
            mitre_tactic TEXT,
            mitre_technique TEXT,
            raw_data TEXT,
            result_html TEXT,
            result_text TEXT,
            blue_team_task_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        // Relación incidente-entidad
        $db->exec("CREATE TABLE IF NOT EXISTS incident_entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT REFERENCES incidents(incident_id) ON DELETE CASCADE,
            entity_value TEXT NOT NULL,
            role TEXT CHECK(role IN ('victim','attacker','source','target','related')),
            risk_contribution REAL DEFAULT 0.0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (entity_value) REFERENCES entities(entity_value) ON DELETE CASCADE
        )");

        // Timeline histórico por entidad
        $db->exec("CREATE TABLE IF NOT EXISTS entity_timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_value TEXT NOT NULL,
            event_type TEXT CHECK(event_type IN ('logon','network','process','alert','ioc_seen','incident_linked','verdict_changed')),
            event_time TEXT DEFAULT CURRENT_TIMESTAMP,
            incident_id TEXT,
            event_data TEXT,
            anomaly_score REAL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (entity_value) REFERENCES entities(entity_value) ON DELETE CASCADE
        )");

        // IOCs
        $db->exec("CREATE TABLE IF NOT EXISTS iocs (
            ioc_id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_value TEXT UNIQUE NOT NULL,
            ioc_type TEXT CHECK(ioc_type IN ('ip','domain','hash','url')),
            first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'sospechosa' CHECK(status IN ('sospechosa','confirmada_maliciosa','falsa_alarma','whitelist')),
            declared_by TEXT,
            declared_at TEXT,
            notes TEXT,
            osint_vt_score INTEGER,
            osint_abuse_score INTEGER,
            is_targeted INTEGER DEFAULT 0,
            targeted_evidence TEXT,
            campaign_tag TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        // Relación IOC-incidente
        $db->exec("CREATE TABLE IF NOT EXISTS ioc_incidents (
            ioc_value TEXT NOT NULL,
            incident_id TEXT NOT NULL,
            appearance_time TEXT DEFAULT CURRENT_TIMESTAMP,
            context TEXT,
            PRIMARY KEY (ioc_value, incident_id),
            FOREIGN KEY (ioc_value) REFERENCES iocs(ioc_value) ON DELETE CASCADE,
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
        )");

        // Queries de hunting generadas
        $db->exec("CREATE TABLE IF NOT EXISTS hunting_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT REFERENCES incidents(incident_id) ON DELETE CASCADE,
            query_type TEXT DEFAULT 'kql',
            query_text TEXT NOT NULL,
            description TEXT,
            created_by TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        // Índices Blue Team
        $db->exec("CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(entity_value)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_entities_risk ON entities(current_risk_score DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_time DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_incidents_sentinel ON incidents(sentinel_number)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_incident_entities_incident ON incident_entities(incident_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_incident_entities_value ON incident_entities(entity_value)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_timeline_entity ON entity_timeline(entity_value, event_time DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(ioc_value)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_iocs_status ON iocs(status)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_iocs_campaign ON iocs(campaign_tag)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_hunting_incident ON hunting_queries(incident_id)");

        // Migración lazy: añadir blue_team_task_id a incidents si no existe
        self::_addColumnIfNotExists('incidents', 'blue_team_task_id', 'INTEGER');

        // Migraciones de columnas para tablas existentes
        self::_addColumnIfNotExists('tasks', 'assignment', 'TEXT DEFAULT "worker"');
        self::_addColumnIfNotExists('tasks', 'executed_by', 'TEXT');
        self::_addColumnIfNotExists('worker_heartbeats', 'available_models', 'TEXT');
        self::_addColumnIfNotExists('worker_commands', 'status', 'TEXT');
        self::_addColumnIfNotExists('worker_commands', 'status_message', 'TEXT');
        self::_addColumnIfNotExists('worker_commands', 'status_updated_at', 'TEXT');
        self::_addColumnIfNotExists('worker_heartbeats', 'recent_logs', 'TEXT');
        self::_addColumnIfNotExists('users', 'monthly_external_budget_usd', 'REAL DEFAULT 5.0');
        self::_addColumnIfNotExists('external_models', 'tags', 'TEXT');
        self::_addColumnIfNotExists('tasks', 'cvss_base_score', 'REAL');
        self::_addColumnIfNotExists('tasks', 'cvss_severity', 'TEXT');

        // Plantillas de informe personalizables
        $db->exec("CREATE TABLE IF NOT EXISTS report_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_type TEXT NOT NULL DEFAULT 'cve_search',
            name TEXT NOT NULL,
            content TEXT NOT NULL,
            is_default INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_templates_task_default ON report_templates(task_type, is_default)");

        // Limpiar duplicados de plantilla por defecto (bug v0.10.29)
        $db->exec("DELETE FROM report_templates WHERE id NOT IN (
            SELECT MIN(id) FROM report_templates WHERE name = 'Plantilla por defecto' AND task_type = 'cve_search'
        ) AND name = 'Plantilla por defecto' AND task_type = 'cve_search'");

        // Plantilla por defecto CVE — solo si no existe ninguna para este task_type
        $existing = $db->query("SELECT 1 FROM report_templates WHERE task_type = 'cve_search' LIMIT 1")->fetch();
        if (!$existing) {
            $templateFile = dirname(__DIR__) . '/plantilla-cve-boxdrawing.md';
            if (file_exists($templateFile)) {
                $defaultTemplate = file_get_contents($templateFile);
                $defaultName = 'Informe tipo ASCII / Box-drawing';
            } else {
                $defaultTemplate = "Eres un analista de ciberseguridad experto. Genera un informe en español sobre la vulnerabilidad proporcionada.\n\n" .
                    "Estructura obligatoria (usa exactamente estos títulos en markdown):\n" .
                    "## CONTEXTO\n" .
                    "## IMPACTO\n" .
                    "## RECOMENDACIONES\n" .
                    "## NOTAS\n\n" .
                    "Sé conciso (máximo 300 palabras). Usa markdown básico.";
                $defaultName = 'Plantilla por defecto';
            }
            $stmt = $db->prepare("INSERT INTO report_templates (task_type, name, content, is_default) VALUES (?, ?, ?, ?)");
            $stmt->execute(['cve_search', $defaultName, $defaultTemplate, 1]);
        }
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
