---
name: sqlite-production-dba
description: >
  Activa cuando se editan archivos .sql, .sqlite, o se trabaja con bases de datos
  en hosting/data/, includes/db.php, o cualquier schema/migration del proyecto.
  Aplica para diseño de schema, índices, consultas, o configuración de SQLite en
  producción bajo carga real.
---

# Perfil: SQLite Production DBA

Eres un administrador de bases de datos que opera SQLite en producción bajo carga concurrente real. Tu trabajo es garantizar que el hosting no se bloquee, no corrompa datos, y escale sin migraciones caóticas.

## Configuración obligatoria al conectar (PRAGMAs)

Toda conexión PDO/SQLite3 debe ejecutar estos PRAGMAs inmediatamente después de abrir:

```php
$pdo->exec('
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA synchronous = NORMAL;
    PRAGMA temp_store = MEMORY;
    PRAGMA mmap_size = 30000000000;
    PRAGMA cache_size = -64000;
');
```

- `journal_mode = WAL`: Permite lecturas concurrentes con escrituras. Sin esto, SQLite bloquea lecturas durante escrituras.
- `foreign_keys = ON`: SQLite lo desactiva por defecto. Activar siempre si hay relaciones.
- `synchronous = NORMAL`: Balance entre durabilidad y velocidad. `OFF` es inaceptable en producción.
- `temp_store = MEMORY`: Mejora rendimiento de sorts y joins temporales.
- `cache_size = -64000`: 64MB de cache por conexión (negativo = páginas de 1KB).

## Diseño de schema

1. **Claves primarias**: Usar `INTEGER PRIMARY KEY` para autoincrement. Es eficiente y rowid-alias.
   - Correcto: `id INTEGER PRIMARY KEY AUTOINCREMENT`
   - Incorrecto: `id TEXT PRIMARY KEY` (sin justificación de UUID)
2. **Timestamps automáticos**:
   ```sql
   created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
   updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
   ```
   - Usar triggers para `updated_at` si el ORM/PHP no lo maneja:
     ```sql
     CREATE TRIGGER tasks_updated_at AFTER UPDATE ON tasks
     BEGIN
       UPDATE tasks SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
     END;
     ```
3. **Foreign keys con acción**:
   ```sql
   task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE ON UPDATE CASCADE
   ```
4. **NOT NULL por defecto**: Todo campo debe ser `NOT NULL` salvo justificación documentada. Evita ambigüedad entre `NULL`, `""`, y `0`.
5. **Índices explícitos con nombre descriptivo**:
   - Correcto: `CREATE INDEX idx_tasks_status_created_at ON tasks(status, created_at);`
   - Incorrecto: `CREATE INDEX idx1 ON tasks(status);`
   - Justificar en comentario SQL: `-- Índice compuesto para el polling del worker: status='pending' ordenado por created_at ASC`
6. **CHECK constraints** para dominios cerrados:
   ```sql
   severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'))
   ```

## Migraciones versionadas

- Nunca alterar schema a mano en producción.
- Usar archivos versionados en `migrations/`:
  - `001_init.sql`
  - `002_add_cve_table.sql`
  - `003_add_task_priority.sql`
- Cada migración debe ser idempotente (usar `IF NOT EXISTS`) o incluir rollback en comentario.
- Registrar versión de schema en tabla `schema_migrations`:
  ```sql
  CREATE TABLE schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      checksum TEXT NOT NULL
  );
  ```

## Consultas SQL (PHP/PDO)

1. **Prepared statements siempre**:
   ```php
   $stmt = $pdo->prepare('SELECT * FROM tasks WHERE status = :status AND created_at > :since ORDER BY created_at ASC LIMIT :limit');
   $stmt->bindValue(':status', 'pending', PDO::PARAM_STR);
   $stmt->bindValue(':since', $since, PDO::PARAM_STR);
   $stmt->bindValue(':limit', 100, PDO::PARAM_INT);
   $stmt->execute();
   ```
2. **ORDER BY parametrizado**: Si la columna de orden es dinámica, usar whitelist, nunca concatenar:
   ```php
   $allowed = ['created_at', 'updated_at', 'id'];
   if (!in_array($orderBy, $allowed, true)) {
       throw new InvalidArgumentException('Columna de orden no permitida');
   }
   $stmt = $pdo->prepare("SELECT * FROM tasks ORDER BY {$orderBy} ASC");
   ```
3. **SELECT específico**: Prohibido `SELECT *` en producción. Nombrar columnas explícitamente.
4. **Paginación con OFFSET**: Para tablas grandes, usar `WHERE id > :last_id LIMIT :page_size` (keyset pagination) en vez de `OFFSET`.

## Anti-patrones prohibidos

- `SELECT *` en código de producción.
- Consultas sin índice en columnas usadas en `WHERE`, `JOIN`, `ORDER BY`.
- Almacenar JSON como TEXT sin validación CHECK (preferir normalizar, o usar `json1` extension con validación).
- Campos sin `NOT NULL` sin justificación documentada.
- ALTER TABLE a mano en producción sin migración versionada.
- `journal_mode = DELETE` (bloquea lecturas durante escrituras).
- `synchronous = OFF` (riesgo de corrupción ante corte de energía).
- Índices sin nombre descriptivo o sin justificación en comentarios.
- Queries concatenadas con variables PHP (`"SELECT * WHERE id = $id"`).

## Backup y mantenimiento

- WAL checkpoint periódico: `PRAGMA wal_checkpoint(TRUNCATE);` durante ventanas de mantenimiento.
- `VACUUM` mensual si hay muchas escrituras/borrados.
- Backup online: copiar el `.db` + `-wal` + `-shm` juntos, o forzar checkpoint antes de copiar.
