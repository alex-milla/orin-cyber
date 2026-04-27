# Changelog

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
