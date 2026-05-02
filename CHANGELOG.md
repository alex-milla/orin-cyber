# Changelog

## [v0.13.1] — 2026-05-03

### Fixed
- **BUG-1 (Crítico)**: `search_similar_incidents()` añadido en `worker/utils/api_client.py` — sin este método el worker no podía completar tareas `rag_enrich`.
- **BUG-2**: `getRateLimitInfo()` reimplementado con contador real de peticiones en ventana deslizante (antes devolvía siempre 60/60).
- **BUG-3**: `invalidateEnrichCacheForEntities()` ahora parsea JSON y compara coincidencias exactas en campos relevantes, evitando falsos positivos por `LIKE %valor%`.
- **BUG-4**: Batching activado en `worker/worker.py` — tras reclamar una tarea `rag_enrich`, el worker reclama hasta 4 tareas adicionales del mismo tipo/prioridad y las agrupa en una sola llamada al LLM.

### Added
- `hosting/dev/backfill_embeddings.php`: script CLI para generar embeddings retroactivos de incidentes cerrados existentes. Soporta `--dry-run` y `--limit=N`.
- Pestaña "🧠 RAG" en `admin.php` con KPI cards (indexados, 7d, 30d, consultas) y tabla de queries recientes. Endpoint `ajax_admin.php?action=rag_stats`.
- `docs/sentinel-integration.md`: documentación completa de integración con Microsoft Sentinel (watchlist, KQL queries sync/hybrid, automation rules).
- `tests/test_rag_smoke.py`: smoke tests mínimos para validar que los componentes críticos del RAG importan correctamente.
- `install-sqlite-vec.php` actualizado para descargar `vec0.so` directamente desde la release v0.13.0 de GitHub (evita bloqueos de hosting compartido a GitHub releases externos).

## [v0.13.0] — 2026-05-03

### Added
- **RAG de Incidentes Históricos — Fase 2 (Embeddings + sqlite-vec + AI Worker)**:
  - Scripts de Orin Nano (`scripts/orin/`):
    - `download-embedding-model.sh`: descarga automática de `bge-small-en-v1.5-q8_0.gguf` desde HuggingFace.
    - `orinsec-embeddings.service`: servicio systemd para `llama-server --embedding --port 8081`.
    - `setup-embeddings-service.sh`: instalación automática del servicio systemd.
    - `setup-cloudflare-tunnel.sh`: configura túnel Cloudflare para `embed-orin.cyberintelligence.dev`.
    - `setup-sqlite-vec.sh`: instala la extensión `sqlite-vec` en el servidor de hosting.
    - `setup-rag-phase2.sh`: script maestro que orquesta toda la instalación en la Orin.
  - Worker Python:
    - `worker/utils/embeddings.py`: cliente `EmbeddingClient` que habla con el embed-server vía API OpenAI-compatible `/v1/embeddings`.
    - `worker/tasks/rag_enrich.py`: tarea `rag_enrich` completa con búsqueda de similares, prompt al LLM, respuesta JSON estructurada, fallback por votación, generación de KQL hunting, y soporte para batch.
    - `worker/utils/api_client.py`: nuevo método `search_similar_incidents()` para que el worker consulte al hosting.
    - `worker/worker.py`: `RagEnrichTask` registrado en `TASK_REGISTRY`.
  - Hosting PHP:
    - `hosting/includes/embedding_client.php`: cliente PHP para el servicio de embeddings con soporte Cloudflare Access headers.
    - `hosting/api/v1/enrich.php`: endpoint REST completo para Sentinel/KQL con modos `sync`/`async`/`hybrid`, rate limiting, caché, overflow policy y cola con prioridad.
    - `hosting/api/v1/rag_feedback.php`: actualizado para generar embeddings reales y guardar vectores en `incident_embeddings_vec` (sqlite-vec).
    - `hosting/api/v1/rag_search.php`: endpoint unificado para búsqueda vectorial (sqlite-vec) o full-text fallback (LIKE).
    - `hosting/includes/rag.php`: motor completo con `searchSimilarIncidentsVector()`, caché de enriquecimientos (`enrich_cache`), invalidación de caché, y fallback a texto cuando sqlite-vec no está disponible.
    - `hosting/includes/db.php`: tabla `enrich_cache` y tabla virtual `incident_embeddings_vec` (vec0).
    - `hosting/includes/config.php`: `LOCAL_EMBED_URL`, `EMBEDDING_MODEL`, `EMBEDDING_DIM`, `RAG_OVERFLOW_POLICY`.
    - `hosting/includes/functions.php`: `createTask()` con soporte de `priority` y `parent_task_id`.
    - `hosting/api/v1/tasks.php`: reclamación atómica ordenada por `priority ASC, created_at ASC`.
    - `hosting/api/v1/.htaccess`: whitelist de `enrich.php`.
  - **Todo listo para descargar desde GitHub Release** y copiar a la Orin Nano + hosting.

### Changed
- `searchSimilarIncidents()` ahora intenta búsqueda vectorial (Fase 2) y cae a full-text (Fase 1) si sqlite-vec no está disponible.
- `rag_feedback.php` genera embeddings reales vía `EmbeddingClient` y persiste vectores cuando sqlite-vec está activo.

## [v0.12.7] — 2026-05-02

### Added
- **RAG de Incidentes Históricos — Fase 1 (Base + Frontend)**:
  - Nuevo módulo `🧠 Memoria Histórica de Incidentes` que permite buscar casos similares a partir de IPs, hashes, dominios o descripciones textuales.
  - `hosting/includes/rag.php`: motor del RAG con funciones de búsqueda full-text (LIKE), alimentación (feedback), logging de queries, métricas e indexación de incidentes cerrados.
  - `hosting/rag_incidents.php`: interfaz web completa con KPI cards (indexados, 7d, 30d, consultas), gráficos de barras por veredicto y severidad, buscador con filtro por tipo de entidad (IP, hash, dominio, URL, usuario, texto libre), tarjetas de resultados con similitud visualizada, tabla de incidentes indexados recientes y formulario para alimentar la memoria manualmente.
  - `hosting/api/v1/rag_search.php`: endpoint REST seguro (`X-API-Key`) para búsqueda vectorial (texto exacto en Fase 1; upgrade a embeddings/sqlite-vec en Fase 2).
  - `hosting/api/v1/rag_feedback.php`: endpoint REST seguro para alimentar la memoria con incidentes cerrados manualmente.
  - Tablas en SQLite:
    - `incident_embeddings`: almacena metadatos de incidentes cerrados listos para enriquecimiento vectorial (Fase 2).
    - `rag_query_log`: auditoría de consultas realizadas (consulta, timestamp, fuente, resultados, latencia).
  - Integración en navegación (`Tools` → `🧠 RAG Incidentes`) y quick-actions del dashboard.
  - **Prerrequisitos documentados para Fase 2** (embeddings + sqlite-vec + worker AI): descargar modelo `bge-small-en-v1.5-q8_0.gguf` al Orin Nano, crear servicio `orinsec-embeddings.service` (puerto 8081), túnel Cloudflare `embed-orin.cyberintelligence.dev`, instalar `sqlite-vec` en hosting, desplegar `embeddings.py` y `rag_enrich.py` en worker y registrar en `TASK_REGISTRY`.

## [v0.12.6] — 2026-05-02

### Added
- **Nueva herramienta: Convertidor IOC → STIX 2.1**:
  - `hosting/ioc_converter.php`: interfaz completa con estilo OrinSec para convertir listas de indicadores de compromiso a formato STIX 2.1.
  - `hosting/includes/ioc_converter_utils.php`: motor de conversión con soporte para txt, list, dat, ioc, csv y json.
  - `hosting/ioc_download.php`: endpoint seguro para descargar los archivos JSON generados.
  - Detección automática de tipos de IOC: IPv4, IPv6, dominio, URL, hash, email, cuenta de usuario, clave de registro.
  - Configuración de metadatos STIX: fuente, actor de amenaza, tags, confianza (1-100), nivel TLP, tipo de indicador y validez en días.
  - Dos modos de salida: separado por tipo (archivos individuales por categoría) o archivo único combinado.
  - Resumen visual con gráfico de barras por tipo de indicador detectado.
  - Integrada en el menú de navegación (Herramientas → IOC → STIX) y en el dashboard de accesos rápidos.

## [v0.12.5] — 2026-05-02

### Added
- **CVE Search — Historial mejorado con filtros y eliminación**:
  - KPI cards en la parte superior del historial con contadores por estado: Todas, Pendientes, En curso, Completadas, Con error, Canceladas.
  - Filtro por estado: al hacer clic en un KPI card se filtran las filas de la tabla.
  - Botón **🗑️ Eliminar** para tareas finalizadas (completed, error, cancelled). Solo se pueden borrar tareas que ya terminaron; las activas deben cancelarse primero.
  - Nueva función `deleteTaskById()` en `includes/functions.php` y endpoint `ajax_admin.php?action=delete_task`.
  - Status pills visuales en el historial con icono + color + texto.
  - Mejoras visuales: tabla más compacta, botones de acción agrupados, fechas en formato `dd/mm HH:mm`.

### Changed
- `hosting/task_cve.php`: rediseño del panel de historial manteniendo intactos el formulario de búsqueda, el widget de worker, el polling y las opciones de exportación.

## [v0.12.4] — 2026-05-02

### Changed
- **URL del llama-server ahora es una constante estática** (`LOCAL_LLM_URL` en `includes/config.php`):
  - Ya no es necesario configurar la URL en la base de datos ni en el panel de admin.
  - El valor por defecto es `https://chat-orin.cyberintelligence.dev`.
  - Todos los enlaces (header, dashboard, chat.php, chat_external.php) usan la constante directamente.
  - El panel de Admin → Workers solo mantiene los campos de **Cloudflare Access** (Client ID / Client Secret) si el túnel está protegido con Zero Trust.

## [v0.12.3] — 2026-05-02

### Fixed
- **Enlace de Chat ahora apunta directamente al túnel sin pasar por chat.php**:
  - `templates/header.php` lee `local_llm_url` desde la BD y, si está configurada, el enlace 💬 Chat abre la URL externa directamente en nueva pestaña.
  - `index.php` (dashboard): el quick-action de Chat también usa la URL directa cuando está disponible.
  - Si no hay URL configurada, ambos enlaces fallback a `chat.php` que muestra el mensaje informativo.
  - Esto elimina la pantalla intermedia y la confusión de "abrir ventana en lugar de pestaña".

## [v0.12.2] — 2026-05-02

### Changed
- **Chat simplificado — redirección directa al túnel de Cloudflare**:
  - `hosting/chat.php` reescrito: ya no carga la UI de chat integrado con JS. Ahora redirige automáticamente a la URL configurada en `local_llm_url` (el túnel de Cloudflare que expone el llama-server del Orin).
  - Si no hay URL configurada, muestra un mensaje informativo con enlace al Admin para completar la configuración.
  - El enlace de navegación "💬 Chat" en `header.php` y en el dashboard ahora abre en **nueva pestaña** (`target="_blank"`) porque es una experiencia externa al hosting.
  - Eliminada la lógica legacy del chat integrado (textarea, polling JS, historial inline) de `chat.php`. El historial de conversaciones sigue disponible en la base de datos pero ya no se expone en la UI.

## [v0.12.1] — 2026-05-02

### Fixed
- **Chat local roto tras unificación local/cloud (v0.10.45)**:
  - `chatLocal()` en `hosting/api/v1/chat_external.php` tenía `http://localhost:8080` hardcodeado. Esto fallaba cuando el hosting PHP y el llama-server están en máquinas distintas (arquitectura estándar de OrinSec).
  - Ahora `chatLocal()` lee la URL desde `config('local_llm_url')` con fallback a `localhost:8080` para compatibilidad con setups locales.
  - Añadido soporte para **Cloudflare Access (Zero Trust)** via headers `CF-Access-Client-Id` y `CF-Access-Client-Secret` configurables.
  - Nuevo panel en **Admin → Workers**: formulario para configurar la URL del llama-server y las credenciales de Cloudflare Access.

## [v0.12.0] — 2026-05-02

### Added
- **Dashboard intuitivo v2** — Rediseño completo de la pantalla de inicio (`index.php`):
  - KPI cards superiores con métricas clave: tareas totales/pendientes, alertas sin leer, incidentes abiertos y estado del worker Orin.
  - Gráfico de barras horizontales (CSS puro) mostrando la distribución de severidad de alertas.
  - Widget de estado del worker con métricas en tiempo real: CPU, memoria, disco, temperatura y modelo cargado.
  - Sección de acceso rápido con cards grandes e iconos para Búsqueda CVE, Blue Team, Chat IA, Alertas y Admin.
  - Panel de últimas alertas con badges de severidad y enlaces directos a la consulta CVE.
  - Tabla compacta de tareas recientes con pills de estado visuales (icono + color + texto).
  - Banner de bienvenida con degradado que destaca la identidad de la plataforma.

### Changed
- `hosting/assets/css/style.css` v6: nuevas clases de diseño para dashboards — grids responsive, KPI cards, mini bar charts, status pills, quick action buttons y worker mini widgets.
- `hosting/templates/header.php`: el enlace de navegación "Inicio" ahora muestra "📊 Dashboard" para reforzar la nueva identidad de la página principal.

## [v0.11.0] — 2026-05-01

### Added
- **CVE Official Sources + i18n — Re-creación del módulo CVE**:
  - Nuevo scraper `worker/scrapers/cve_org.py`: consulta CVE Services API (`cveawg.mitre.org`) como **fuente canónica** del registro CVE. Extrae metadatos, descripciones por idioma, productos afectados, métricas CNA, CWEs y referencias.
  - `worker/scrapers/nvd.py` refactorizado: ahora actúa como **fuente de enriquecimiento secundaria** (`get_cve_enrichment()`). Aporta CVSS, CPE, CWE y referencias adicionales cuando el CNA no las publica.
  - Estrategia de fusión: descripción de CVE.org tiene prioridad; si NVD aporta CVSS/CPE, se añade; fallback automático a NVD si CVE.org falla.
  - Prompt `worker/prompts/cve_report.txt` reescrito: el informe se **pre-rellena** con datos oficiales en formato box-drawing Unicode exacto. El LLM solo debe reescribir la sección "🤖 AI-Powered Risk Assessment", eliminando repeticiones y alucinaciones.
  - Soporte de **idioma** (`es` / `en`): selector en `task_cve.php`, propagado a worker y VirtualWorker. Descripciones preferentes según idioma con fallback a inglés.
  - Paridad Cloud/Local: `hosting/includes/tasks/cve_search_task.php` ahora también consulta **CVE.org**, **CISA KEV**, **GitHub Exploits** y **EPSS**, igual que el worker Python.
  - Renderizado HTML mejorado: `worker/utils/formatter.py` y PHP usan `<pre>` con `white-space: pre-wrap` para preservar la estructura box-drawing sin romper los caracteres Unicode.
  - Exportación Markdown/Word adaptada al idioma de la tarea.

### Changed
- `worker/tasks/cve_search.py` completamente refactorizado con arquitectura de tres capas: Canónico (CVE.org) → Enriquecimiento (NVD) → Priorización (CISA KEV) + Complementarias (EPSS, GitHub, OSV).

## [v0.10.44] — 2026-05-01

### Added
- **Selector de modelo para el Chat desde el panel Admin**:
  - Nueva sección "🤖 Modelo del Chat (llama-server)" en Admin → Workers.
  - El administrador puede seleccionar cualquier modelo disponible en el worker local desde un dropdown.
  - Al guardar, se almacena el modelo preferido en la BD del hosting (`config.preferred_model`) y se envía un comando `change_model` al worker para cambio en caliente.
  - El worker, al arrancar, consulta el hosting por el modelo preferido **antes** de iniciar llama-server. Si difiere del `.current_model` local, lo actualiza y arranca con el modelo correcto. Esto garantiza persistencia tras reinicios del Orin.
  - Nuevo endpoint `hosting/api/v1/worker_config.php` para que el worker lea su configuración remota.
  - Nuevo método `ApiClient.get_preferred_model()` en el worker.

## [v0.10.43] — 2026-04-30

### Fixed
- **Critical hotfix**: `hosting/api/v1/tasks.php` tenía una llave de cierre (`}`) de más en el post-procesamiento de `azure_sync`. Esto provocaba un **parse error** en PHP, haciendo que el endpoint `tasks.php?action=pending` devolviera **500** y el worker nunca recibiera tareas. Todos los incidentes Blue Team se quedaban en estado *Pendiente*.

## [v0.10.42] — 2026-04-30

### Fixed
- **Blue Team Toolkit — Fase 1-3**: múltiples fixes de estabilidad y UX.
  - `IncidentAnalysisTask.__init__` faltaba `self.config_path = config_path`, causando `AttributeError` al consultar OSINT.
  - `blue_team.php` ahora redirige automáticamente a `task_result.php` tras subir un CSV, mostrando polling en tiempo real sin necesidad de refrescar manualmente.
  - Worker `TASK_REGISTRY` actualizado con `incident_analysis` y `azure_sync`; limpieza de `__pycache__` recomendada tras deploy.

## [v0.10.41] — 2026-04-30

### Added
- **Blue Team Intelligence Toolkit — Fase 3**: Azure Sentinel sync + KQL hunting queries.
  - Nuevo `worker/utils/azure_sentinel.py`: autenticación Azure CLI device code flow, ejecución de queries KQL contra Log Analytics, generación automática de queries KQL de hunting por IP/dominio/hash/URL/usuario/device.
  - Nuevo task type `azure_sync`: sincroniza incidentes desde Sentinel directamente a la base de datos local. El usuario introduce el Workspace ID y el worker consulta la API de Sentinel usando el token del `az login` previo.
  - Nuevo endpoint REST `api/v1/azure_sync.php` (sync, status, hunting_queries).
  - Sección **Azure Sentinel Sync** en `blue_team.php`: formulario para Workspace ID, días de lookback, número de incidente opcional, polling de estado en tiempo real.
  - El task `incident_analysis` ahora genera automáticamente queries KQL de hunting para cada entidad extraída (IPs, dominios, hashes, URLs). Se muestran en el informe HTML como bloques `<details>` con syntax highlighting, y se persisten en `hunting_queries`.
  - Post-procesamiento en `tasks.php`: al completar `azure_sync`, los incidentes extraídos se insertan automáticamente en `incidents`. Al completar `incident_analysis`, las queries KQL se guardan en `hunting_queries`.

## [v0.10.40] — 2026-04-30

### Added
- **Blue Team Intelligence Toolkit — Fase 2**: integración OSINT + IOC Tracker.
  - Nuevo `worker/utils/osint_client.py`: consulta VirusTotal, AbuseIPDB, URLhaus y AlienVault OTX con caché SQLite local, rate limiting automático y TTL por fuente.
  - El task `incident_analysis` ahora enriquece automáticamente cada entidad con OSINT antes de enviar al LLM. El informe HTML incluye tabla de scores VT/AbuseIPDB/URLhaus/OTX.
  - Prompt LLM actualizado: ahora también clasifica el incidente como **GENÉRICO** o **DIRIGIDO** con confianza.
  - Nueva sección **IOC Tracker** en `blue_team.php`: estadísticas por estado, tabla de IOCs con VT/AbuseIPDB scores, formulario para añadir IOC manual, cambio de estado inline (sospechosa/confirmada/falsa_alarma/whitelist).
  - Nuevo endpoint REST `api/v1/ioc_tracker.php` (list, get, add, update_status, delete, stats).
  - Nueva sección `[osint]` en `config.ini.example` para API keys de VT, AbuseIPDB y OTX.

### Changed
- `tasks.php` post-procesamiento: ahora también captura `blue_team_classification` (GENÉRICO/DIRIGIDO).

## [v0.10.39] — 2026-04-30

### Added
- **Blue Team Intelligence Toolkit — Fase 1**: nueva funcionalidad SOC para análisis de incidentes, tracking de entidades e inteligencia de IOCs.
  - Nuevas tablas SQLite: `entities`, `incidents`, `incident_entities`, `entity_timeline`, `iocs`, `ioc_incidents`, `hunting_queries`.
  - Nueva página web `blue_team.php` con dashboard, tarjetas de resumen, formulario de upload CSV, tabla de incidentes y entidades monitoreadas.
  - Nuevo endpoint REST `api/v1/blue_team.php` para listar/obtener incidentes y entidades.
  - Nuevo task type `incident_analysis` en el worker: parsea CSV con Polars, extrae entidades (IPs, dominios, emails, hashes) vía regex, llama al LLM local para veredicto TP/FP + MITRE ATT&CK.
  - Prompt LLM optimizado para modelos 4B: genera JSON estructurado con veredicto, confianza, tactic, technique, justificación, entidades riesgosas y recomendaciones.
  - Post-procesamiento automático: cuando el worker termina el análisis, `tasks.php` actualiza `incidents.llm_verdict`, `mitre_tactic`, `result_html` y `result_text`.
  - Link en navbar "🛡️ Blue Team" bajo el menú Herramientas.

### Dependencies
- Worker: añadidos `polars>=1.0.0` y `networkx>=3.0` a `requirements.txt`.

## [v0.10.38] — 2026-04-29

### Fixed
- **Catálogo NVIDIA NIM corregido con modelos verificados**: se reemplazaron los modelos que no existen en la API de NVIDIA NIM (`deepseek-ai/deepseek-r1`, `microsoft/phi-4`, `qwen/qwen2.5-72b-instruct`) por los IDs reales devueltos por la API (`deepseek-ai/deepseek-v3.2`, `deepseek-ai/deepseek-v4-pro`, `microsoft/phi-4-mini-instruct`, `microsoft/phi-4-multimodal-instruct`, `qwen/qwen3-coder-480b-a35b-instruct`). También se añadieron modelos confirmados como `mistralai/mistral-large`, `moonshotai/kimi-k2.5` y `nvidia/nemotron-4-340b-instruct`.

### Added
- **Validación real contra API de NVIDIA NIM**: el catálogo `models/nvidia-nim.json` ahora contiene únicamente modelos verificados mediante llamada real a `GET https://integrate.api.nvidia.com/v1/models` con la API key del usuario. Esto elimina los errores 404/410 por modelos inexistentes.

## [v0.10.37] — 2026-04-29

### Fixed
- **403 Forbidden persistente en polling**: `polling.js` (usado en `task_cve.php` y `task_result.php`) seguía obteniendo el CSRF token desde `input[name="csrf_token"]`, que no siempre existe en la página. Ahora lee primero del `<meta name="csrf-token">` (igual que `virtual_worker_pulse.js`), con fallback al input. Ambos scripts llevan `?v=2` para invalidar cache del navegador/Cloudflare.

## [v0.10.36] — 2026-04-29

### Fixed
- **403 Forbidden en polling de Virtual Worker**: `virtual_worker_pulse.js` ejecutaba la búsqueda del `<meta name="csrf-token">` como IIFE inmediato, antes de que el DOM estuviera listo. El token llegaba vacío (`Content-Length: 11`), provocando que `verifyCsrf()` devolviera 403 y Cloudflare bloqueara la petición. Ahora espera explícitamente a `DOMContentLoaded`.

### Added
- **Catálogo `models/nvidia-nim.json`**: 13 modelos NVIDIA NIM cloud directo (sin pasar por OpenRouter) filtrados para ciberseguridad: Mistral Large 3, Llama 4 Maverick, Llama 3.3/3.1, Nemotron 70B/340B, DeepSeek R1, Phi 4, Gemma 3/2, Mixtral 8x22B, Qwen 2.5. Excluidos deprecated y modelos no-texto (embeddings, visión-only, rerankers).

## [v0.10.35] — 2026-04-29

### Added
- **Auto-importación de modelos OpenRouter (free + paid)**: nuevo endpoint `fetch_openrouter_models` en `admin_providers.php` que consulta directamente `https://openrouter.ai/api/v1/models` y devuelve la lista completa con precios reales.
- **UI de importación masiva en admin**: nueva sección "🔄 Importar modelos desde OpenRouter" en la pestaña Proveedores. Permite filtrar por `all` (todos), `free` (solo gratuitos) o `paid` (solo de pago), previsualizar en tabla con costos, seleccionar individualmente o en bloque, e importar masivamente. Los duplicados se saltan automáticamente.

### Fixed
- **Compatibilidad PHP**: reemplazado `str_contains()` (PHP 8+) por `strpos(...) !== false` para máxima compatibilidad con versiones anteriores de PHP.

## [v0.10.34] — 2026-04-29

### Fixed
- **Plantilla box-drawing no se aplicaba por defecto**: la plantilla "Informe tipo ASCII / Box-drawing" tenía `is_default = 0` y no había otra plantilla por defecto. Al crear una tarea sin seleccionar explícitamente una plantilla, `input_data` quedaba sin campo `template`. Esto provocaba que el Worker Local usara su formato estructurado nativo (Vulnerability Information, OSV.dev, EPSS, etc.) y el Virtual Worker usara su prompt por defecto (`CONTEXTO` / `IMPACTO` / `RECOMENDACIONES` / `NOTAS`). Ahora la plantilla box-drawing es la por defecto (`is_default = 1`).

### Changed
- **`db.php`**: en nuevas instalaciones, la plantilla por defecto se lee del archivo `plantilla-cve-boxdrawing.md` en lugar de la plantilla simple markdown anterior.

## [v0.10.33] — 2026-04-29

### Fixed
- **Plantillas personalizadas ignoradas por cloud AI**: los modelos cloud (OpenRouter/OpenAI free tier) tendían a ignorar las instrucciones de formato cuando la plantilla iba en el system prompt. Ahora el Virtual Worker coloca la plantilla en el **user prompt** con un system prompt genérico mínimo, alineando el comportamiento con cómo estos modelos realmente procesan las instrucciones.

## [v0.10.32] — 2026-04-29

### Fixed
- **Botones Editar/Preview no respondían en admin**: el contenido de las plantillas se inyectaba directamente en atributos `onclick` mediante JSON sin escapar adecuadamente, rompiendo el HTML cuando el contenido tenía saltos de línea o comillas. Reemplazado por delegación de eventos con atributos `data-*`.

## [v0.10.31] — 2026-04-29

### Fixed
- **CSRF "Token inválido" al guardar/borrar plantillas**: `ajax_admin.php` solo aceptaba `csrf_token` vía `$_POST`/`$_GET`. Ahora también acepta el header `X-CSRF-Token`. El JS de admin usa `FormData` en lugar de JSON para el envío.

## [v0.10.30] — 2026-04-29

### Fixed
- **Bug de replicación de plantillas por defecto**: la migración de `report_templates` usaba `INSERT OR IGNORE` sin clave única, provocando que cada request creara una nueva plantilla por defecto. Ahora se verifica primero si existe alguna plantilla antes de insertar, y se limpian automáticamente los duplicados existentes.

## [v0.10.29] — 2026-04-29

### Added
- **Plantillas de informe CVE personalizables**: nueva tabla `report_templates` con CRUD completo en el panel de admin (tab "Plantillas"). El usuario puede crear, editar, previsualizar y eliminar plantillas `.md` que actúan como base del system prompt. El sistema añade automáticamente reglas de seguridad.
- **Selector de plantilla en task_cve.php**: dropdown para elegir la plantilla de informe al crear una tarea. La plantilla se inyecta en `input_data` y viaja con la tarea, funcionando tanto para Worker Local (Python) como Virtual Worker (PHP).
- **Modo Markdown libre en Worker Python**: cuando se proporciona plantilla personalizada, el worker usa `llm.chat()` en lugar de `llm.chat_json()`, generando Markdown libre que se convierte a HTML.
- **Modo plantilla en Virtual Worker PHP**: `CveSearchTaskPhp::buildSystemPromptFromTemplate()` combina la plantilla del usuario con las reglas del sistema.

## [v0.10.28] — 2026-04-29

### Fixed
- **Tareas cloud quedaban atascadas en `pending`**: el procesamiento dependía de
  `polling.js`, que sólo se carga en la página de espera. Añadido
  `virtual_worker_pulse.js` que dispara `ajax_virtual_worker.php` cada 15s desde
  cualquier página autenticada.
- **Historial CVE no refrescaba tras completarse**: añadido polling ligero (5s)
  sobre filas en estado `pending`/`processing` en `task_cve.php`.

### Added
- **Exportación a Markdown y Word**: nuevo endpoint `export_cve.php?format=md|docx`
  con botones en `task_result.php`. El `.docx` se genera con `ZipArchive` sin
  dependencias externas.
- **Filtro de búsqueda en historial CVE**: input encima de la tabla con filtrado
  client-side instantáneo por cualquier campo visible.
- **Columna "Score" en historial CVE**: muestra CVSS Base Score con badge de
  color según severidad (Low/Medium/High/Critical). Persistido en nuevas
  columnas `tasks.cvss_base_score` y `tasks.cvss_severity`.

## [v0.10.27] — 2026-04-29

### Changed
- **Múltiples CVEs crean tareas individuales**: `task_cve.php` ahora genera una tarea independiente en la cola por cada CVE introducido, en lugar de una sola tarea con `cve_list`. El worker las procesa de 1 en 1. El historial muestra cada CVE como una entrada separada.

## [v0.10.26] — 2026-04-29

### Changed
- **Procesamiento de CVEs múltiples en cola**: `cve_search.py` ahora procesa cada CVE **individualmente** (uno tras otro) en lugar de en modo batch. Cada CVE recibe análisis del LLM propio. Los resultados se combinan en un único informe HTML con separadores.

## [v0.10.25] — 2026-04-29

### Fixed
- **Release packaging corregido**: asegura que todos los archivos modificados (`admin.php`, `monitoring.py`, `model_catalog.py`, `db.php`, `config.ini`) se incluyen correctamente en los zips.

## [v0.10.24] — 2026-04-29

### Fixed
- **Dropdown de modelos en admin**: ahora muestra correctamente el nombre del archivo sin `.gguf` (ej. `Qwen3.5-4B-Q4_K_M`) en lugar del label amigable. El label se mantiene como tooltip.
- **Rebuild completo de model_catalog**: migración que limpia todos los patrones viejos conflictivos (`*qwen*4*`, `*gemma*2*`, etc.) y deja solo los específicos.

## [v0.10.23] — 2026-04-29

### Added
- **Dropdown de modelos muestra nombres de archivo**: el selector de cambio de modelo en `admin.php` ahora muestra el nombre completo del archivo sin `.gguf` (ej. `Qwen3.5-4B-Q4_K_M`) en lugar del label amigable, permitiendo diferenciar modelos con labels idénticos.
- **Filtrado por tamaño en worker**: `monitoring.py` ignora archivos `.gguf` menores a 500 MB, descartando mmproj corruptos o shards parciales.

### Fixed
- **Patrones de model_catalog más específicos**: eliminados globs laxos (`*qwen*4*`, `*gemma*2*`, etc.) que causaban falsos positivos. Ahora se usan patrones con versión y quant (`*qwen3.5*4b*`, `*gemma*4b*`, etc.).
- **Filtrado de mmproj en catálogo**: `model_catalog.py` también excluye archivos que contienen `mmproj`.

## [v0.10.22] — 2026-04-27

### Added
- **Catálogo de modelos actualizado**: nuevos patrones para Gemma 4B, Granite 8B, MiMo-VL 7B y Nemotron 4B en `model_catalog`.
- **Nombres legibles en toda la UI**: `admin.php` y `task_cve.php` ahora muestran etiquetas amigables (ej. "DeepSeek 7B (medium)") en lugar del nombre crudo del archivo `.gguf`.

### Fixed
- **`mmproj` excluido de listados**: `monitoring.py` y `model_catalog.py` filtran archivos con `mmproj` en el nombre, evitando que aparezcan como modelos disponibles en el admin.
- **Configuración conservadora para 9 modelos**: `config.ini` regenerado con parámetros ajustados por tamaño de modelo (contexto, `-ngl`, flash attention) para evitar OOM en Jetson Orin Nano 8GB.

### Changed
- **Modelo por defecto**: ahora es `NVIDIA-Nemotron3-Nano-4B-Q4_K_M.gguf` (más ligero y estable para arranque).

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
