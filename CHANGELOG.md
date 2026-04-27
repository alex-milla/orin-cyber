# Changelog

## [v0.7.5] — 2026-04-28

### Added
- **Panel de logs en tiempo real** en `admin.php` → Workers:
  - Nueva columna "📜 Logs" en la tabla de workers. Al hacer clic, se expande un panel con las últimas líneas del log del worker (equivalente a `journalctl -u orinsec-worker -f`).
  - El panel se actualiza automáticamente cada 5 segundos vía polling AJAX.
  - El worker envía las últimas 30 líneas de su archivo de log en cada heartbeat.
  - Cleanup automático de heartbeats antiguos: ahora se conservan **7 días** (antes solo 50 registros).

### Changed
- `hosting/api/v1/heartbeat.php`: recibe y almacena campo `recent_logs`; cambiado el cleanup a retención de 7 días.
- `worker/worker.py`: función `_tail_log_file()` lee las últimas N líneas del log y las adjunta al heartbeat.

---

## [v0.7.4] — 2026-04-27

### Fixed
- **Worker**: `_free_jetson_memory()` ahora se ejecuta también en el **arranque inicial** del worker (no solo en cambios de modelo). Esto evita que tras un reinicio del sistema el primer arranque falle por fragmentación de memoria.
- **Hosting (admin.php)**: el polling JS de `change_model` ahora es robusto. Pasa el nombre del modelo como parámetro en lugar de leerlo del DOM (evita errores si el usuario interactúa mientras carga). Verifica que los elementos existen antes de modificarlos y detiene el spinner correctamente al recibir `ready`/`error`.

### Added
- `worker/config.ini.example`: plantilla de configuración conservadora con todos los flags y contextos recomendados para el bug JetPack r36.4.7. El `config.ini` real sigue ignorado por git (seguridad de API keys).

---

## [v0.7.3] — 2026-04-27

### Fixed
- **Mitigación OOM en Jetson Orin Nano** (bug JetPack r36.4.7 — fragmentación de memoria CUDA):
  - `worker/config.ini`: restaurados flags conservadores globales y por modelo (`-fa on`, `--cache-type-k q8_0`, `--cache-type-v q8_0`, `--batch-size 256`, `--ubatch-size 256`, `--no-mmap`, `--mlock`). `context_size` reducido a valores seguros (4096/2048/1536).
  - `worker/utils/model_catalog.py`: heurística `_recommended_context` dividida por la mitad para evitar reservas grandes de KV-cache en el kernel buggy. `_extra_args_for_arch` ahora inyecta flags conservadores automáticamente (sin `-fa` en arquitecturas `phi*` por compatibilidad b8932).
  - `worker/worker.py`:
    - `_free_jetson_memory()`: ejecuta `drop_caches` + `compact_memory` con sudo entre cambios de modelo para desfragmentar memoria física.
    - `_retry_with_minimal_args()`: si el primer arranque falla, reintenta automáticamente con `-ngl 0 -c 1024 --cache-type-k/v q4_0 --batch-size 64` (CPU-only mínimo).
    - `_classify_llama_failure()`: clasifica errores (`oom_cuda`, `oom_compute_buffers`, `oom_cuda_weights`, `shape_mismatch_likely_phi_fa`) y los reporta al hosting para diagnóstico visible en `admin.php`.
    - `_build_llama_args()`: soporta `executable_path_cpu` en `config.ini` para modelos >5 GB (fallback a binario sin CUDA).
    - Frecuencia de re-escaneo de catálogo reducida de 10 a 120 heartbeats (~1 h) para reducir I/O innecesaria.
  - `worker/orinsec-worker.service`: añadidas variables de entorno `GGML_CUDA_NO_PINNED=1`, `GGML_SCHED_DEBUG=0`, `CUDA_LAUNCH_BLOCKING=0`.
  - `worker/install-service.sh`: crea reglas `sudoers.d/orinsec` NOPASSWD para `drop_caches` y `compact_memory`.

---

## [v0.7.1] — 2026-04-27

### Fixed
- **Fase 4 hotfixes** — correcciones críticas tras el release v0.7.0:
  - `gguf_reader.py`: usar `field.contents()` para extraer valores GGUF correctamente; normalizar tipos numpy (`np.int64`, etc.) a Python nativos para JSON serializable.
  - `gguf_reader.py`: asignar `file_size_mb` antes de su uso en `_model_entry_from_metadata()`.
  - `gguf_reader.py`: mejorar regex de `size_label` para capturar variantes `[BbMm]`; priorizar extracción desde filename sobre heurística por archivo.
  - `model_catalog.py`: eliminar inyección automática de `--chat-template` (conflictaba con `--jinja` de llama.cpp build b8932).
  - `worker.py`: robustecer startup de llama-server tras Fase 4 (`shlex.split()` para args con comillas, rollback de config si `change_model` falla, detectar subprocess muerto durante wait).

### Changed
- **Configuración por modelo simplificada** (`config.ini`): todas las secciones `[model_*]` reducidas a `-ngl XX` únicamente. Elimina flags agresivos (`-fa on`, `--cache-type-k q8_0`, `--batch-size`, `--threads`, etc.) que causaban crash (`ggml_reshape_2d` → `llm_build_phi3`) al cargar **Phi-4-mini-instruct** en build b8932. Se mantiene `context_size` por modelo.

---

## [v0.7.0] — 2026-04-27

### Added
- **Gestión dinámica de modelos LLM (Fases 1-4)**:
  - **Fase 1 — Dropdown dinámico**: `admin.php` popula el selector de modelos desde `worker_heartbeats.available_models` (heartbeat del worker). Nuevos `.gguf` aparecen automáticamente en ≤30s.
  - **Fase 2 — Latencia de change_model optimizada**: `restart_llama_server_with()` mata el proceso inmediatamente (~2s) y arranca el nuevo modelo. `ensure_llama_server_running()` reutiliza proceso sano en arranque/tareas. Polling adaptativo `[0.5×4, 1×3, 2×3, luego 3s]`.
  - **Fase 3 — Feedback de progreso en tiempo real**: columnas `status`, `status_message`, `status_updated_at` en `worker_commands`. El worker reporta fases (`executing` → `loading` → `ready`/`error`). El frontend hace polling cada 2s mostrando spinner y mensaje de estado.
  - **Fase 4 — Auto-configuración desde headers GGUF**:
    - `worker/utils/gguf_reader.py`: lee metadatos GGUF (arquitectura, contexto, cuantización, parámetros estimados).
    - `worker/utils/model_catalog.py`: genera `worker/data/models.json` con heurísticas de contexto recomendado, tiempo de carga estimado y `extra_args` (chat-template) según arquitectura. Cache por `mtime`.
    - `worker.py` integra el catálogo: prioridad `[model_<name>]` en config.ini > catálogo > config global. Ajusta `max_wait_s` dinámicamente según tamaño del modelo.
    - Hosting: tabla `model_catalog` con patrones glob, etiquetas legibles y tier. `admin.php` resuelve etiquetas vía glob-to-regex en JS.

### Changed
- `worker/requirements.txt`: añadida dependencia `gguf>=0.10`.

---

## [v0.6.2] — 2026-04-27

### Fixed
- **Auto-migración en bootstrap**: `includes/db.php` ahora ejecuta `CREATE TABLE IF NOT EXISTS` e índices automáticamente al inicializar la conexión SQLite. Elimina la dependencia frágil de scripts manuales en `dev/` que causaban 500 en shared hosting.

## [v0.6.1] — 2026-04-27

### Added
- **Sistema de Alertas (Fase C)**:
  - Tablas `alert_subscriptions` y `alerts` con índices SQLite.
  - API endpoint `api/v1/alerts.php`: GET subscriptions (worker), POST batch create (worker), GET list, POST mark_read.
  - Worker `AlertScanTask`: busca CVEs recientes en NVD (últimas 48h), filtra por suscripciones activas, enriquece con EPSS/CISA KEV/OSV, y envía alertas coincidentes al hosting vía API.
  - `ApiClient.send_alerts()` y `ApiClient.get_alert_subscriptions()` para comunicación worker→hosting.
  - Página `alerts.php`: listado con filtros (no leídas, severidad), marcar leídas individualmente o en batch.
  - Badge de alertas no leídas en el header de navegación.
  - Pestaña "Alertas" en `admin.php`: gestión de suscripciones (producto, vendor, keyword, severidad) con umbral de severidad.
  - Migración: `hosting/dev/migrate_alerts.php`.

### Changed
- NVD scraper: nueva función `get_recent_cves(hours, max_results)` para búsqueda por rango de fecha.
- Worker task registry: añadido `alert_scan` junto a `cve_search`.

---

## [v0.6.0] — 2026-04-27

### Added
- **OSV.dev scraper**: nueva fuente `worker/scrapers/osv.py` que consulta `api.osv.dev` para extraer paquetes afectados (ecosistema, nombre, versión introducida), versiones `fixed_in`, severidad y referencias. TTL 12h en caché SQLite.
- **Caché SQLite persistente**: `worker/utils/cache.py` con tabla `cache(key, value, expires_at)`. Integrada en NVD (24h), EPSS (12h), CISA KEV (4h), GitHub exploits (1h) y OSV (12h). Reduce drásticamente las llamadas repetidas a APIs externas.
- **Batch CVE lookup**: el formulario de `task_cve.php` acepta hasta 20 CVE IDs separados por coma, espacio o salto de línea. El worker enriquece todos y genera un informe comparativo con tabla resumen + tarjetas de detalle. En modo batch se omite la llamada al LLM para evitar exceso de tokens/tiempo.
- **Respuesta JSON estructurada del LLM**: nuevo método `LlmClient.chat_json()` parsea bloques `\`\`\`json` o JSON raw con fallback a `None`. El prompt ahora exige JSON con campos `contexto_es`, `impacto`, `recomendaciones`, `notas`. El worker construye el informe desde el dict parseado, eliminando el regex frágil `CONTEXTO`.

### Changed
- **Prompt actualizado**: incluye referencia a datos de OSV.dev (`fixed_in`) y mantiene la regla de concisión (máx. 200 palabras).
- **Cleanup de hosting**: eliminados `hosting/diagnose.php`, `hosting/emergency_fix.php` y `hosting/migrate_010_to_020.php` (ya migrados a `hosting/dev/` en v0.5.8).

---

## [v0.5.8] — 2026-04-27

### Security
- **Scripts de diagnóstico protegidos**: `diagnose.php`, `emergency_fix.php` y `migrate_010_to_020.php` movidos a `hosting/dev/` con bloqueo vía `.htaccess` (`Require all denied`) y `requireAdmin()` como defense in depth.
- **Cookies Secure automáticas**: `session.cookie_secure` se activa automáticamente cuando se detecta HTTPS (incluyendo proxies con `X-Forwarded-Proto`).
- **Sanitización de informes HTML**: nueva función `sanitizeReportHtml()` elimina atributos `on*` (event handlers) y URLs `javascript:` del HTML generado por el worker. Aplicada tanto en `task_result.php` como en `ajax_check_status.php`.

### Fixed
- **Race condition en rate limiting**: `checkRateLimit()` y `checkBruteForce()` ahora usan `flock` en vez de `file_get_contents`/`file_put_contents` directos, evitando que peticiones simultáneas se salten el límite.
- **Duplicación de cancelación de tareas**: código idéntico en 3 rutas (`ajax_admin.php`, `api/v1/tasks.php`, `api/v1/task_cancel.php`) centralizado en `cancelTaskById()` en `functions.php`. Eliminado `task_cancel.php` (obsoleto desde v0.5.3).

### Performance
- **Índices SQLite faltantes**: añadidos 4 índices (`tasks/status+created`, `api_keys/key+active`, `worker_heartbeats/api_key+created`, `worker_commands/api_key+executed`) para acelerar las queries más frecuentes. Incluido script `dev/migrate_indexes.php` para instalaciones existentes.

### Changed
- **Refactor parser NVD**: eliminada duplicación masiva entre `search_cves()` y `get_cve_by_id()`. Extraídos `_parse_cve_item()` y `_query_nvd()` como funciones compartidas.
- **Limpieza de código muerto**: eliminado `LlmClient.translate()` (sin uso desde v0.4.0).
- **Logs verbosos reducidos a DEBUG**: logs que contenían datos de entrada del usuario (CVE IDs, productos, versiones) pasan a nivel `DEBUG`. Solo eventos del sistema quedan en `INFO`, reduciendo retención de PII.

---

## [v0.5.7] — 2026-04-27

### Added
- **Captura de logs de llama-server**: stdout/stderr ya no van a `/dev/null`. Ahora se escriben a `logs/llama-server.log` con rotación automática.
- **Rotación de logs**: `RotatingFileHandler` con 10 MB por archivo, máximo 4 backups = 50 MB total tanto para el worker como para llama-server.
- **Buffer circular en memoria**: las últimas 100 líneas de llama-server se mantienen en RAM para diagnóstico inmediato.
- **Diagnóstico automático ante fallo de carga**: si un modelo no responde en 120 s, el worker vuelca esas 100 líneas al log principal como `ERROR`.

---

## [v0.5.6] — 2026-04-27

### Fixed
- **Protección crítica al cambiar modelo**: `change_model` ya no reinicia el worker completo. Solo reinicia `llama-server`, evitando que systemd mate el proceso mientras carga un modelo grande.
- **Espera de 120 s para modelos grandes**: antes de matar un `llama-server` existente, el worker espera hasta 120 s a que responda (algunos modelos de 4GB+ tardan 20-30 s en cargar).
- **Verificación antes de cada tarea**: si `llama-server` no responde antes de ejecutar una tarea, se reinicia automáticamente.

---

## [v0.5.5] — 2026-04-27

### Added
- **Configuración por modelo**: sección `[model_<nombre>]` en `config.ini` permite `context_size` y `extra_args` específicos por modelo.
- **Nuevos modelos en dropdown**: GLM-4.6V-Flash (4K context) y DeepSeek-R1-Distill-Qwen-7B.

---

## [v0.5.4] — 2026-04-27

### Fixed
- **Worker online status en admin**: comparación de timestamps forzada a UTC en `admin.php` para evitar falsos "Offline".

---

## [v0.5.3] — 2026-04-27

### Fixed
- **Cancelación de tareas en hosting**: movido el endpoint de cancelación a `ajax_admin.php` porque `task_cancel.php` no se incluía en los deploys ZIP.

---

## [v0.5.2] — 2026-04-27

### Fixed
- **Worker widget "Offline"**: comparación de timestamps ahora fuerza UTC (evita desfase de timezone entre hosting y Orin).
- **llama-server no responde**: worker ahora hace polling durante 60 s (cada 2 s) en lugar de esperar 10 s fijos. Los modelos de 2.7GB+ necesitan ~20-30 s para cargar en Jetson Orin Nano.
- **Tareas atascadas en "processing"**: endpoint `tasks.php?action=pending` ahora marca automáticamente como `error` las tareas que llevan >15 min sin respuesta del worker.
- **Rate limit 429**: causado por dos instancias de worker corriendo simultáneamente (manual + systemd).

### Added
- **Botón "Cancelar"** en historial de CVEs para tareas `pending` o `processing`.
- **Nuevo endpoint** `api/v1/task_cancel.php` — cancelación vía sesión web con protección CSRF.
- **Estilos CSS** `.status-cancelled` y `.btn.small.danger`.

---

## [v0.5.1] — 2026-04-26

### Fixed
- Worker reinicia llama-server automáticamente en `change_model` y luego se reinicia a sí mismo.
- Instalador de servicio systemd (`install-service.sh`) para auto-boot del worker.

---

## [v0.5.0] — 2026-04-25

### Added
- Worker auto-management: mata/levanta llama-server según el modelo seleccionado en admin.
- Detección automática de llama-server al arranque del worker.

---

## [v0.4.6] — 2026-04-25

### Fixed
- UI redesign con dashboard de herramientas y navegación dropdown.
- CVE search con worker widget, historial, tags y PRG pattern.

---

## [v0.4.0] — 2026-04-24

### Changed
- CVE pipeline: single LLM call para traducción + análisis.
- Fallback automático cuando el LLM devuelve respuesta vacía.
- Compact markdown renderer sin datos duplicados.
