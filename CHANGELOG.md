# Changelog

## [v0.10.21] — 2026-04-29

### Fixed
- **Fallback ampliado a rate limits**: ahora también captura `Rate limit exceeded`, `Too many requests` y `Provider returned error` como errores recuperables. Antes de reintentar con otro modelo, espera 2 segundos para no bombardear la API.

## [v0.10.20] — 2026-04-29

### Fixed
- **Formato de informes CVE mejorado**: antes el LLM devolvía Markdown crudo que aparecía como un párrafo gigante sin formato. Ahora `CveSearchTaskPhp::mdToHtml()` convierte automáticamente `## Título` → `<h2>`, `**negrita**` → `<strong>`, listas `- item` → `<li>`, y respeta los saltos de línea. Añadidos estilos CSS para `.cve-report`, `.cve-body h2/h3`, listas y pie de página.

## [v0.10.19] — 2026-04-29

### Added
- **Fallback automático para modelos cloud**: si un modelo devuelve `No endpoints found` o `Model not found`, el Virtual Worker intenta automáticamente con otro modelo activo del mismo proveedor (elegido al azar). La tarea se marca como completada con el modelo fallback y `executed_by` refleja el cambio.

## [v0.10.18] — 2026-04-28

### Fixed
- **Tareas cloud quedaban atascadas en `pending`**: el procesamiento dependía de `polling.js`, que solo se carga en la página de espera tras enviar el formulario. Añadido `virtual_worker_pulse.js` que dispara `ajax_virtual_worker.php` cada 15s desde cualquier página autenticada. También se endureció `tasks.php` para que el worker local nunca coja tareas con `assignment LIKE 'provider:%'`.
- **Historial CVE no refrescaba tras completarse**: añadido polling ligero (5s) sobre filas en estado `pending`/`processing` en `task_cve.php`, que actualiza estado, ejecutor y botón de acción sin recargar la página.

## [v0.10.17] — 2026-04-28

### Fixed
- **Tareas cloud ejecutaban en worker local (CRÍTICO)**: `validateInput()` en `task_cve.php` usaba el patrón por defecto `/^[\w\s\-.@:]+$/u` que **rechazaba la barra `/`** de los model IDs OpenRouter (ej: `deepseek/deepseek-r1:free`). Esto hacía que el assignment cayera siempre a `'worker'`, ignorando la selección del usuario. Ahora se valida con una regex específica: `/^provider:\d+:[\w\-.@:\/]+$/`.

## [v0.10.16] — 2026-04-28

### Added
- **Columna "Consulta" en historial CVE**: muestra el CVE ID o producto buscado, extraído del `input_data` JSON.
- **Pie de página en informes CVE**: cada resultado incluye al final `🤖 Generado por: {Ejecutor}` (Worker local o Proveedor → Modelo) para identificar claramente quién generó el análisis.

### Fixed
- **`executed_by` para tareas cloud**: antes estaba hardcodeado a `"OpenRouter → {model_id}"`. Ahora obtiene el nombre real del proveedor desde la BD (`external_providers.label`) y lo guarda correctamente tanto en éxito como en error.
- **`VirtualWorker`**: nuevo método `getProviderLabel()` que devuelve el label real del proveedor desde la BD.

## [v0.10.15] — 2026-04-28

### Fixed
- **Historial CVE se actualiza en tiempo real (fix timing)**: `polling.js` ahora usa `requestAnimationFrame` para esperar a que el DOM del historial esté listo antes de intentar actualizar la fila. La tabla del historial tiene ahora `id="cve-history-table"` para selección precisa sin depender de `document.querySelector('table')`.

## [v0.10.14] — 2026-04-28

### Fixed
- **Historial CVE se actualiza en tiempo real**: cuando el polling detecta que la tarea está `completed` o `error`, actualiza dinámicamente la fila correspondiente en la tabla de historial (estado, ejecutor y botón de acción cambian de "Cancelar" a "Ver resultado").
- `ajax_check_status.php`: ahora devuelve también `executed_by` para poder reflejar el ejecutor en el historial.

## [v0.10.13] — 2026-04-28

### Added
- **Tags en modelos cloud**: nueva columna `tags` en `external_models`. Los catálogos JSON incluyen `tags: ["recommended", "reasoning", "cybersecurity", "free"]`.
- **Visualización de tags en Admin → Proveedores**: cada modelo muestra badges de colores: 🛡️ cybersecurity (naranja), 🧠 reasoning (azul), ⭐ recommended (verde).
- **Tags en selector de tareas CVE**: el dropdown de ejecutor muestra emojis ⭐🛡️🧠 junto a cada modelo cloud para identificar rápidamente los adecuados para ciberseguridad.

## [v0.10.12] — 2026-04-28

### Added
- **Catálogos JSON por familia de modelo**: nueva carpeta `models/` con archivos JSON listos para importar en Admin → Proveedores: `deepseek.json`, `nvidia.json`, `google.json`, `meta.json`, `microsoft.json`, `mistral.json`, `qwen.json`, `openai.json`, `z-ai.json`, `openrouter-misc.json`.

### Fixed
- **CSS badges en Admin → Proveedores**: definida la variable `--primary-bg` que faltaba, por lo que los badges de modelos ahora se renderizan con fondo y bordes redondeados en lugar de texto plano amontonado. Bumped `style.css?v=3` → `v=4`.

## [v0.10.11] — 2026-04-28

### Fixed
- **Importación bulk JSON**: ahora incluye un input `<input type="file" accept=".json">` para cargar el archivo directamente desde disco, además del textarea para pegar el JSON manualmente.

## [v0.10.10] — 2026-04-28

### Added
- **Importación bulk de modelos desde JSON**: en Admin → Proveedores, nueva sección "📥 Importar modelos desde JSON". Pega un array JSON con múltiples modelos para importarlos masivamente al proveedor seleccionado. Los modelos que ya existen se saltan automáticamente. Muestra conteo de importados, saltados y errores.
- **Nuevo endpoint `import_models`**: `admin_providers.php` acepta `POST` con `provider_id` + `models[]`. Valida cada entrada, duplica el regex de `create_model`, y devuelve `{imported, skipped, errors}`.

## [v0.10.9] — 2026-04-28

### Added
- **Polling desde navegador para Virtual Workers**: cuando el usuario tiene abierta la página de CVE esperando resultado, el navegador llama automáticamente a `ajax_virtual_worker.php` cada 10 segundos. Esto procesa las tareas cloud pendientes sin necesidad de cron en el hosting.
- **Nuevo endpoint `ajax_virtual_worker.php`**: versión web de `run_virtual_tasks.php` que ejecuta una tarea cloud por llamada, protegida con CSRF.

## [v0.10.8] — 2026-04-28

### Added
- **Virtual Workers**: los modelos cloud configurados aparecen ahora como "Virtual Workers" en Admin → Workers, con estado ☁️ Online.
- **Selector de ejecutor en CVE**: al crear una tarea CVE puedes elegir entre el Worker local (Orin) o cualquier Virtual Worker (modelo cloud). El selector se genera dinámicamente desde los modelos configurados, funcionando con cualquier proveedor.

## [v0.10.7] — 2026-04-28

### Added
- **Ejecutor configurable para tareas**: en Admin → Configuración puedes elegir el ejecutor por defecto para tareas CVE (worker local o cualquier modelo cloud configurado).
- **Columna `executed_by`** en tabla `tasks`: muestra quién procesó cada tarea — "Worker local" o "OpenRouter → Modelo".
- **Historial CVE**: nueva columna "Ejecutor" en la tabla de historial.

### Changed
- `task_cve.php`: lee `default_task_executor` desde config para asignar tareas al ejecutor elegido.
- `run_virtual_tasks.php`: guarda el modelo cloud usado en `executed_by`.
- `tasks.php` (endpoint worker): marca `executed_by = 'Worker local'` al completar.

## [v0.10.6] — 2026-04-28

### Fixed
- **Admin providers API**: `create_model` ahora permite paréntesis `()` en el Label. Los labels como `DeepSeek V3 (Free)` eran rechazados por el patrón de validación.

## [v0.10.5] — 2026-04-28

### Fixed
- **Admin providers API**: `create_model` ahora permite barras `/` en el Model ID. Los IDs de OpenRouter (ej: `deepseek/deepseek-chat:free`) usan el formato `editor/modelo` y el patrón de validación lo rechazaba.

## [v0.10.4] — 2026-04-28

### Fixed
- **Admin providers JS**: `loadProvidersAdmin()` ahora espera `DOMContentLoaded` antes de ejecutarse, evitando el error `apiFetch is not defined`.
- **Admin providers API**: `create_provider` ahora captura `UNIQUE constraint failed` y devuelve HTTP 409 con mensaje claro en lugar de 500.

## [v0.10.3] — 2026-04-28

### Fixed
- **Admin providers**: errores al cargar la lista ya no quedan silenciosos. El contenedor muestra el mensaje de error en lugar de quedarse en "Cargando...".
- **Chat externo**: si hay proveedores configurados pero sin modelos, el selector muestra un hint informativo apuntando a Admin → Proveedores.
- **Admin providers tabla**: cuando un proveedor no tiene modelos asociados, se muestra un aviso "⚠️ Añade modelos abajo para usarlos en el chat".

## [v0.10.2] — 2026-04-28

### Fixed
- **`api/v1/.htaccess`**: añadidos `admin_providers.php` y `chat_external.php` a la lista blanca. El archivo bloqueaba **todo** excepto `tasks.php`, `heartbeat.php` y `commands.php`, devolviendo 403 Forbidden de Apache antes de que PHP se ejecutara.

## [v0.10.0] — 2026-04-28

### Added
- **APIs externas (proveedores cloud)** — OpenRouter, OpenAI, Nvidia NIM accesibles directamente desde el hosting:
  - Nuevas tablas SQLite: `external_providers`, `external_models`, `external_usage`, `chat_conversations`, `chat_messages`.
  - `hosting/includes/crypto.php`: cifrado AES-256-CBC para API keys. La clave maestra `MASTER_ENCRYPTION_KEY` se define en `config.php` (lee de variable de entorno `ORINSEC_MASTER_KEY` si existe).
  - `hosting/includes/external_client.php`: cliente HTTP síncrono compatible con OpenAI Chat Completions.
  - `hosting/api/v1/chat_external.php`: endpoint REST para chat con modelos externos. Soporta historial de conversación, rate limit (2s/IP) y control de presupuesto mensual por usuario (`users.monthly_external_budget_usd`, default $5.0).
  - `hosting/chat.php`: selector de proveedor que permite elegir entre **🏠 Local** (Orin vía Cloudflare Tunnel) y **☁️ Proveedores cloud**. Los modelos locales abren el túnel en nueva pestaña; los modelos externos usan el chat integrado con historial.
  - `hosting/api/v1/admin_providers.php`: endpoint admin para CRUD de proveedores/modelos, test de conexión (`/v1/models`) y métricas de uso del mes.
  - `hosting/admin.php`: nueva pestaña "Proveedores" con gestión completa de proveedores cloud, modelos asociados y estadísticas de consumo.

### Security
- Las API keys de proveedores externos se almacenan cifradas en la base de datos. Nunca se exponen al cliente; solo se muestra un hint (`sk-...abcd`).
- Validación estricta de `provider_id` + `model_id` contra la base de datos antes de cada llamada externa.

### Notes
- El worker del Orin **no se modifica**. La ruta local sigue funcionando exactamente igual a través del Cloudflare Tunnel.
- **Importante**: cambiar `MASTER_ENCRYPTION_KEY` en producción antes de añadir proveedores reales.

---

## [v0.10.1] — 2026-04-28

### Fixed
- **Auth**: `requireAuth()` y `requireAdmin()` ahora usan `isApiRequest()` para detectar si la petición viene de un endpoint `/api/` y devuelven JSON en lugar de HTML. Esto evita el error `Unexpected token '<', "<!DOCTYPE..."` cuando el frontend olvida enviar `X-Requested-With`.
- **Admin providers**: `admin_providers.php` ahora valida el token CSRF en todas las peticiones POST (`X-CSRF-Token`).
- **Admin JS**: Todas las llamadas `fetch` de la pestaña Proveedores usan el helper `apiFetch()` que envía automáticamente `X-Requested-With: XMLHttpRequest`, `X-CSRF-Token` y detecta respuestas no-JSON.

### Added
- **VirtualWorker** (`hosting/includes/virtual_worker.php`): adaptador PHP que expone la misma interfaz que `LlmClient` del worker Python (`chat()`, `chatJson()`) pero ejecutando contra proveedores externos. Permite reutilizar la lógica de tareas con modelos cloud.
- **Tareas virtuales** (`hosting/run_virtual_tasks.php`): script CLI con file-lock para ejecutar tareas asignadas a proveedores externos. Procesa una tarea por invocación, reclama atómicamente, gestiona timeouts y guarda resultados en la BD.
- **CVE Search en PHP** (`hosting/includes/tasks/cve_search_task.php`): versión PHP de la tarea CVE que enriquece datos vía NVD API + EPSS API y genera el informe con VirtualWorker.
- **Columna `assignment`** en tabla `tasks`: permite elegir `worker` (por defecto) o `provider:{id}:{model_id}` para tareas cloud.
- **Filtrado en `tasks.php`**: el worker físico solo recibe tareas con `assignment = 'worker'`, evitando que coja tareas destinadas a proveedores externos.

---

## [v0.9.0] — 2026-04-28

### Changed
- **Arquitectura del chat rediseñada** (de worker+ polling → Cloudflare Tunnel directo):
  - Eliminado todo el código legacy del chat por worker: `worker/tasks/chat_task.py`, `hosting/chat_api.php`, thread `_chat_poll_loop` en `worker.py`, y filtrado `type`/`exclude_type` en `worker/utils/api_client.py` y `hosting/api/v1/tasks.php`.
  - La pestaña **Chat** ahora carga la UI nativa de llama-server mediante un **iframe** apuntando al túnel de Cloudflare. Esto elimina la latencia mínima de 2s por polling y permite interacción directa con el modelo.
  - `hosting/chat.php`: reemplazada la interfaz de chat custom (JS, polling, textarea) por un iframe simple a `https://chat-orin.cyberintelligence.dev`.

### Added
- **Cloudflare Tunnel** (`cloudflared`) en el Orin Nano:
  - Túnel persistente `orin-chat` que expone `localhost:8080` (llama-server) a Internet vía `chat-orin.cyberintelligence.dev`.
  - Servicio systemd `cloudflared` para auto-arranque.
- **Cloudflare Access (Zero Trust)** con MFA:
  - Aplicación "Orin Chat" protegida en `chat-orin.cyberintelligence.dev`.
  - Autenticación por email + PIN de un solo uso. Solo el email autorizado puede acceder.

### Security
- El chat ya no está expuesto públicamente sin protección. Cloudflare Access bloquea cualquier acceso no autorizado antes de que llegue al Orin.

---

## [v0.8.8] — 2026-04-28

### Fixed
- **Chat**: filtrado de bloques `<think>...</think>` en las respuestas del modelo. Los modelos de razonamiento (MiMo, DeepSeek-R1, etc.) incluyen su cadena de pensamiento interna entre estas etiquetas. Ahora el worker la elimina antes de enviar la respuesta al usuario.

---

## [v0.8.7] — 2026-04-28

### Fixed
- **Chat**: movido el endpoint de `api/v1/chat.php` a `chat_api.php` en la raíz. El directorio `api/v1/` devolvía **403 Forbidden** desde Apache/Cloudflare, bloqueando todas las peticiones POST del chat.

---

## [v0.8.6] — 2026-04-28

### Fixed
- **Chat**: sustituido `continue` ilegal por `return` dentro del callback de `setInterval`. El `continue` rompía todo el script con `SyntaxError`, impidiendo que se registraran los event listeners del botón.
- **Chat**: CSS corregido para evitar descentrado (`width: 100%` en lugar de `max-width: 900px` anidado) y desbordamiento (`min-height: 60vh` + `max-height: calc(100vh - 200px)` en lugar de `calc(100vh - 220px)` frágil).
- **Chat**: textarea ahora hereda estilos del tema (fondo, borde, color).
- **Worker**: `_chat_poll_loop` ahora inicializa `ChatTask` dentro del loop con reintento cada 30s. Antes, si fallaba al arrancar, el thread moría para siempre y las tareas de chat quedaban atascadas en `pending`.

---

## [v0.8.5] — 2026-04-28

### Fixed
- **Chat**: eliminado `DOMContentLoaded` del script. Al estar al final del `<body>`, el evento ya se había disparado antes de registrar el listener, por lo que la IIFE nunca se ejecutaba y el botón no respondía.

---

## [v0.8.4] — 2026-04-28

### Added
- **Cola dedicada para chat** (latencia reducida de ~15s a ~2s):
  - `hosting/api/v1/tasks.php`: filtrado por `type` y `exclude_type` en la acción `pending`.
  - `worker/utils/api_client.py`: `get_pending_tasks()` acepta `type` y `exclude_type`.
  - `worker/worker.py`: thread daemon `_chat_poll_loop` que procesa solo tareas `chat` cada 2s. El loop principal excluye chats (`exclude_type=chat`), evitando que CVEs pesadas bloqueen el chat.

---

## [v0.8.3] — 2026-04-28

### Fixed
- **Chat**: script envuelto en `document.addEventListener('DOMContentLoaded', ...)` para asegurar que el DOM esté listo antes de registrar event listeners.
- **Chat**: añadida verificación de elementos DOM y log de consola para diagnóstico de inicialización.

---

## [v0.8.2] — 2026-04-28

### Fixed
- **Chat**: CSS corregido para que el contenedor quepa dentro de la pantalla (`height: calc(100vh - 220px)` en lugar de `100vh - 180px`).
- **Chat**: añadido diagnóstico en consola del navegador (URL, status HTTP y respuesta cruda) para identificar errores de conexión con el endpoint.
- **Chat**: endpoint `api/v1/chat.php` envuelto en `try/catch` + `set_error_handler` para que cualquier error PHP se devuelva como JSON en vez de página HTML.
- **Chat**: pollTask ahora parsea el body manualmente con `JSON.parse` para evitar errores de doble-consumo del stream.

---

## [v0.8.1] — 2026-04-28

### Fixed
- **Chat**: añadido `credentials: 'same-origin'` a los fetch para que las peticiones AJAX envíen la cookie de sesión. Esto evita el error `"<!DOCTYPE... is not valid JSON"` causado por redirección a login.php.
- **Chat**: movido el enlace del menú desplegable "Herramientas" a pestaña principal del header.
- **Chat**: muestra el modelo activo cargado (`worker_heartbeats.model_loaded`) en la interfaz.

---

## [v0.8.0] — 2026-04-28

### Added
- **Chat integrado en la app web** ( Opción B — vía worker ):
  - `worker/tasks/chat_task.py`: nueva tarea `chat` que envía mensajes a llama-server vía `LlmClient.chat()` y devuelve la respuesta al hosting.
  - `worker/worker.py`: registrada `ChatTask` en `TASK_REGISTRY`.
  - `hosting/api/v1/chat.php`: endpoint REST para crear tareas `chat` (POST) y consultar respuestas (GET). Protegido por sesión de usuario.
  - `hosting/chat.php`: interfaz de chat con historial visual, envío por AJAX y polling cada 3 s hasta recibir la respuesta del worker.
  - `hosting/templates/header.php`: enlace "💬 Chat" en el dropdown de Herramientas.

---

## [v0.7.9] — 2026-04-28

### Changed
- `hosting/admin.php`: añadidos `console.log` / `console.warn` / `console.error` en `pollCommandStatus` para permitir diagnóstico en tiempo real desde la consola del navegador (F12). Esto ayudará a identificar por qué el polling no detecta el estado `ready` cuando el modelo ya ha cargado.

---

## [v0.7.8] — 2026-04-28

### Fixed
- **Hosting commands.php**: `validateInput` en el `message` del comando rechazaba caracteres especiales (`(`, `)`, `/`, etc.), guardando mensajes vacíos. Ahora usa `substr` sin filtrado.
- **Hosting ajax_admin.php**: el endpoint `command_status` devolvía `null` cuando el status de la BD era NULL, en lugar de `'pending'`. El JS no coincidía con `'ready'`/`'error'` y se quedaba en timeout. Cambiado `??` por `?:`.
- **Worker api_client.py**: `report_command_status` ahora loggea a **WARNING** (visible en el panel de logs) cuando el hosting rechaza o falla al reportar estado.

---

## [v0.7.7] — 2026-04-28

### Fixed
- **Hosting heartbeat.php**: `validateInput` rechazaba caracteres especiales presentes en los logs del worker (`[`, `]`, `%`, `/`, etc.), guardando siempre `NULL`. Ahora se usa `substr` directamente para limitar a 20KB sin filtrar caracteres.

### Added
- `hosting/dev/check_logs.php`: script de diagnóstico temporal para verificar si los `recent_logs` llegan correctamente a la base de datos sin necesidad de acceso SSH/sqlite3.

---

## [v0.7.6] — 2026-04-28

### Fixed
- **Worker**: acumular logs en memoria (`_DequeLogHandler`) para enviar al panel de admin, en lugar de leer el archivo de log desde disco (que podía fallar por permisos o rutas).
- **Hosting heartbeat.php**: variable `$recentLogs` no estaba definida, por lo que se guardaba siempre `NULL` en la base de datos. Ahora se lee y valida correctamente del JSON del worker.

---

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
