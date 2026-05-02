# OrinSec — Auditoría Real del Estado de Implementación del RAG

**Fecha del análisis:** 2026-05-03
**Versión auditada:** `v0.13.0` (CHANGELOG actualizado, 2026-05-03)
**Método:** Inspección directa del código fuente del ZIP proporcionado
**Documento de referencia:** `orinsec-rag-incidentes-historicos.md` v1.0
**Documento previo (a corregir):** `orinsec-rag-estado-pendiente.md` (basado solo en CHANGELOG público — incorrecto)

---

## 0. Disculpa y rectificación

> ⚠️ **Mi análisis anterior estaba mal.** Me basé exclusivamente en el CHANGELOG público de GitHub, que en ese momento marcaba la última versión como `v0.12.6`. Asumí que no se había implementado nada, cuando en realidad **ya existe `v0.13.0` con la mayor parte de la Fase 2 desplegada**.
>
> Auditando el código real:
> - 122 líneas de `enrich.php` ✅
> - 129 líneas de `rag_feedback.php` ✅
> - 58 líneas de `rag_search.php` ✅
> - 345 líneas de `rag.php` ✅
> - 314 líneas de `rag_incidents.php` (UI web, no estaba en el plan original) ✅
> - 267 líneas de `rag_enrich.py` ✅
> - 5 scripts de instalación en `scripts/orin/` ✅
> - Migraciones SQL completas en `db.php` ✅
>
> Aproximadamente **el 80% del plan está implementado**. Lo que sigue es la lista honesta de qué falta y qué tiene bugs.

---

## 1. Resumen ejecutivo del estado real

### ✅ COMPLETO (80%)

| Área | Estado | Comentario |
|---|---|---|
| Migraciones SQL (`db.php`) | ✅ | Tablas `incident_embeddings`, `incident_embeddings_vec`, `enrich_cache`, `rag_query_log` + columnas `priority`, `parent_task_id` en `tasks`. |
| `enrich.php` | ✅ | Modos `sync`/`async`/`hybrid`, rate limit, overflow policy. |
| `rag_feedback.php` | ✅ | GET para listar + POST con embedding real. Mejor que el diseño original (fallback graceful si no hay sqlite-vec). |
| `rag_search.php` | ✅ | Búsqueda vectorial + fallback a LIKE. |
| `rag.php` | ✅ | Motor completo con **mejora**: fallback automático LIKE si sqlite-vec falla. |
| `embedding_client.php` | ✅ | Con soporte CF Access headers. |
| `worker/utils/embeddings.py` | ✅ | Cliente Python OpenAI-compatible. |
| `worker/tasks/rag_enrich.py` | ✅ | Lógica completa, batching, prompt builder, fallback por votación, generador KQL. |
| Registro en `TASK_REGISTRY` | ✅ | `worker.py` línea 49. |
| `.htaccess` whitelist | ✅ | `enrich.php`, `rag_search.php`, `rag_feedback.php` listados. |
| `claim` ordena por `priority` | ✅ | `tasks.php:42` `ORDER BY priority ASC, created_at ASC`. |
| Constantes config | ✅ | `LOCAL_EMBED_URL`, `EMBEDDING_MODEL`, `EMBEDDING_DIM`, `RAG_OVERFLOW_POLICY`. |
| `createTask()` con priority | ✅ | `functions.php` acepta `priority` y `parent_task_id`. |
| Scripts del Orin | ✅ | 5 scripts en `scripts/orin/` + maestro `setup-rag-phase2.sh`. |
| UI web `rag_incidents.php` | ✅ | **Bonus no planificado**: página completa con stats, búsqueda interactiva, listado de embeddings. |
| Link en navegación | ✅ | `header.php:46` → `🧠 RAG Incidentes`. |
| Instalador sqlite-vec PHP | ✅ | `install-sqlite-vec.php` con detección automática de plataforma. |

### 🟡 PARCIAL / CON BUGS (10%)

| Área | Problema |
|---|---|
| `worker/utils/api_client.py` | **🔴 BUG CRÍTICO**: el CHANGELOG declara que se añadió el método `search_similar_incidents()`, pero **no existe en el archivo**. Esto rompe `rag_enrich.py` en runtime (líneas 43 y 99 lo invocan). |
| `getRateLimitInfo()` en `rag.php` | Stub que devuelve siempre `60` y `+60s`, sin leer estado real del rate limiter. |
| `invalidateEnrichCacheForEntities()` | Implementación con `LIKE %valor%` sobre `response_json` — funciona pero ineficiente; podría devolver falsos positivos si el valor aparece en otro contexto. |

### 🔴 NO IMPLEMENTADO (10%)

| Área | Plan original | Estado |
|---|---|---|
| Backfill CLI | Script `hosting/dev/backfill_embeddings.php` para indexar histórico existente | ❌ No existe (verificado: solo hay `check_logs.php`, `diagnose.php`, `emergency_fix.php`, `migrate_010_to_020.php`, `migrate_alerts.php`, `migrate_indexes.php`) |
| Sección "🧠 RAG" en `admin.php` | Métricas RAG en el panel admin con KPIs | ❌ No hay ni mención de "rag" o "embedding" en `admin.php` |
| Endpoint AJAX para métricas RAG | `ajax_admin.php?action=rag_stats` | ❌ No existe |
| KQL queries de ejemplo | Queries listas para Sentinel | ❌ No hay archivos `.kql`, ni docs `sentinel-integration.md` |
| Logic App / Automation Rule | Para el feedback al cerrar incidente en Sentinel | ❌ No hay artefactos |
| Watchlist `OrinSecCredentials` | Setup en Sentinel | ❌ No documentado |
| Lógica de batching real en `worker.py` | `claim_batch()` que reclama N tareas y `_execute_batch()` agrupa | 🟡 `rag_enrich.py:31` detecta `batch` pero `worker.py` **nunca lo activa** — falta `claim_batch` en el loop |
| Tests unitarios e integración | 7 tests del plan | ❌ Cero tests añadidos |
| `enrich_log` para auditoría | Tabla opcional de auditoría | ❌ No creada |
| Documentación `docs/rag.md` | Guía operativa | ❌ No existe |

---

## 2. Bugs concretos a corregir (urgente antes del primer despliegue)

### 🔴 BUG-1 — Método faltante en `ApiClient`

**Archivo:** `worker/utils/api_client.py`
**Síntoma:** `RagEnrichTask.execute()` lanzará `AttributeError: 'ApiClient' object has no attribute 'search_similar_incidents'` en la primera tarea `rag_enrich`.
**Evidencia:**
```bash
$ grep "search_similar" worker/utils/api_client.py
# (sin resultados)

$ grep "search_similar" worker/tasks/rag_enrich.py
43:        similar = self.api.search_similar_incidents(entity=entity, k=k)
99:                similar_map[i] = self.api.search_similar_incidents(ent, k=k)
```
**Fix necesario:** añadir al final de `ApiClient` (antes del cierre de la clase):

```python
def search_similar_incidents(self, entity: dict, k: int = 5) -> list:
    """Pide al hosting incidentes similares vía búsqueda vectorial o full-text fallback."""
    try:
        data = self._request(
            "POST",
            "/api/v1/rag_search.php",
            json={"entity": entity, "k": k},
        )
        if data and "similar" in data:
            return data["similar"]
    except requests.RequestException as exc:
        logger.warning("Failed to fetch similar incidents: %s", exc)
    return []
```

**Severidad:** 🔴 Bloqueante. Sin esto, ninguna tarea `rag_enrich` puede completarse.

### 🟡 BUG-2 — `getRateLimitInfo()` devuelve datos mentirosos

**Archivo:** `hosting/includes/rag.php` (líneas 340-345)
**Síntoma:** la respuesta de `enrich.php` al cliente KQL siempre dice `remaining: 60`, sin reflejar el consumo real.
**Evidencia:**
```php
function getRateLimitInfo(string $key): array {
    return [
        'remaining' => 60,
        'reset_at' => date('c', time() + 60),
    ];
}
```
**Fix necesario:** leer del mismo archivo de lock que usa `checkRateLimit()` en `functions.php` (introducido en v0.5.8 con `flock`).

**Severidad:** 🟡 Funcional pero engañoso. KQL podría no enterarse de que está cerca del límite.

### 🟡 BUG-3 — `invalidateEnrichCacheForEntities` puede generar falsos positivos

**Archivo:** `hosting/includes/rag.php` (líneas 279-293)
**Síntoma:** si se cierra un incidente con la IP `10.0.0.1`, se borrará cualquier entrada de caché que contenga la cadena `10.0.0.1` en cualquier parte del JSON, incluso si era un campo distinto.
**Fix sugerido:** parsear el JSON antes de comparar y comprobar coincidencia exacta en campos relevantes (`entity_value`, `similar_cases[].entity`).
**Severidad:** 🟢 Bajo. Solo afecta a la eficiencia de la caché, no a la corrección del sistema.

### 🟡 BUG-4 — Batching declarado pero no activado

**Archivos:** `worker/tasks/rag_enrich.py` (línea 31) + `worker/worker.py`
**Síntoma:** `RagEnrichTask.execute()` detecta `input_data["batch"]` y procesa en lote, pero `worker.py` **nunca crea tareas con campo `batch`** porque no implementa la lógica `claim_batch()` del plan original.
**Estado:** la capacidad existe, falta el hilo que la dispare.
**Fix necesario:** en `worker.py`, después de un `claim` exitoso de `rag_enrich`, intentar reclamar hasta N-1 tareas más del mismo tipo y mismo `priority` y agruparlas con un `parent_task_id` común.
**Severidad:** 🟡 No bloqueante. El sistema funciona en modo 1-tarea-1-llamada-LLM, simplemente sin la optimización prevista.

---

## 3. Lo que sigue pendiente

### 3.1 Backfill (importante para el primer despliegue real)

Sin backfill, el RAG empieza vacío y no puede recomendar basándose en histórico hasta que se acumulen suficientes cierres nuevos. Para SOCs con `incidents` ya pobladas (como confirma el repo en v0.10.39 con tabla `incidents`), conviene generar embeddings retroactivos.

**A crear:** `hosting/dev/backfill_embeddings.php`
**Patrón ya disponible en el plan:** documento de implementación, sección 12.
**Operativa:** ejecutar 1 vez tras instalar `sqlite-vec`, con `--dry-run` primero.
**Esfuerzo:** ~2-3 horas.

### 3.2 Sección "🧠 RAG" en `admin.php`

`admin.php` tiene 84KB con muchas pestañas (Workers, Plantillas, Proveedores, Alertas, Modelos…) pero **ninguna con métricas del RAG**. La función `getRagStats()` existe en `rag.php:205` y devuelve todo lo necesario:

```php
return [
    'total_embeddings' => $total,
    'last_7d' => $last7d,
    'last_30d' => $last30d,
    'total_queries' => $totalQueries,
    'by_verdict' => $byVerdict,
    'by_severity' => $bySeverity,
];
```

Falta solo la pestaña que la consuma y muestre KPI cards al estilo del Dashboard v2 (v0.12.0). En `rag_incidents.php` ya hay UI para usuario final, pero no en el panel admin operativo.

**Esfuerzo:** ~3-4 horas (replicar el patrón de la pestaña "Alertas" de v0.6.1).

### 3.3 Integración Sentinel (todo el bloque KQL)

Lo más visible y de mayor impacto pendiente. **Cero artefactos** de Sentinel en el repo:
- No hay `.kql` files de ejemplo
- No hay documentación de cómo configurar `OrinSecCredentials` watchlist
- No hay Logic App template para automation
- No hay capturas/instrucciones del setup en Cloudflare Access (Service Token)

Esta es la parte que **convierte el RAG de feature interna a punto de integración real con el SOC**. Sin esto, el RAG funciona pero solo se alimenta manualmente.

**Esfuerzo:** ~1-2 días de trabajo (la mayoría documentación y pruebas, las queries ya están en el documento de implementación sección 8).

### 3.4 Tests

No hay tests del RAG. Riesgos:

- Regresión silenciosa en `searchSimilarIncidents()` si se cambia el modelo de embeddings y la dimensión.
- Bug-1 (método faltante) **se habría detectado en CI** con un test trivial de smoke.
- No hay forma sistemática de validar que `enrich.php` cumple latencia <500ms en modo `sync`.

**Recomendación mínima:** añadir 3 tests críticos:
1. Smoke test: `python -c "from worker.tasks.rag_enrich import RagEnrichTask; t = RagEnrichTask(); t.api.search_similar_incidents({'subject':'test'})"` debe devolver `[]` sin excepción.
2. Test PHP: `enrich.php` con body válido devuelve estructura JSON esperada.
3. Test E2E: `feedback.php` POST → `rag_search.php` POST con keywords del summary devuelve el incidente recién insertado.

**Esfuerzo:** ~4-6 horas para los 3 críticos.

---

## 4. Lo que se hizo MEJOR de lo planeado

Para ser justos, hay decisiones tomadas durante la implementación que **mejoran el plan original**:

### 4.1 Fallback automático a LIKE cuando sqlite-vec no está disponible

`rag.php:53-63` implementa un patrón de degradación elegante:

```php
function searchSimilarIncidents(array $entity, int $k = 5): array {
    if (isVecAvailable()) {
        try {
            return searchSimilarIncidentsVector($entity, $k);
        } catch (Exception $e) {
            error_log("Vector search failed, falling back to text search: " . $e->getMessage());
        }
    }
    return searchSimilarIncidentsText($entity, $k);
}
```

Esto **resuelve elegantemente el riesgo crítico identificado en el documento previo** (Fase 0 — validar `sqlite-vec` en hosting compartido). Si la extensión no carga, el sistema **sigue funcionando** con búsqueda full-text por palabras. Es una solución mucho más pragmática que el plan B que yo proponía (mover todo al worker o usar VPS).

### 4.2 UI web `rag_incidents.php` no estaba en el plan

314 líneas de página dedicada con:
- KPI cards (`getRagStats()`)
- Búsqueda interactiva por tipo de entidad
- Listado de embeddings recientes
- Logging de queries en `rag_query_log`

El plan original solo contemplaba métricas dentro de `admin.php`. Esta página es de **usuario final**, no admin, y permite que un analista busque manualmente sin depender de KQL. Buena decisión.

### 4.3 `install-sqlite-vec.php` web-installer

127 líneas que detectan plataforma (`x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, `aarch64-darwin`), descargan el `.so` correcto, lo colocan en el `extension_dir`, y verifican carga. Ahorra al usuario el dolor de compilar/buscar binarios a mano. No estaba en el plan.

### 4.4 `setup-rag-phase2.sh` como script maestro

Orquesta los 3 pasos en el Orin (modelo + servicio + tunnel) en una sola ejecución con confirmaciones. Mejor UX que ejecutar 5 scripts a mano.

### 4.5 Modos `sync`/`async`/`hybrid` validados con whitelist en `enrich.php`

```php
$mode = in_array($input['mode'] ?? '', ['sync', 'async', 'hybrid']) 
    ? ($input['mode'] ?? 'hybrid') : 'hybrid';
```

Defensa en profundidad: si llega un modo inválido, fallback a `hybrid` en lugar de error. Pequeño detalle pero correcto.

### 4.6 `rag_feedback.php` con fallback graceful sin sqlite-vec

Si la generación del embedding falla (servicio caído, sqlite-vec ausente), el incidente **igual se guarda con su texto**. El embedding se puede regenerar después con un backfill. Operacionalmente más robusto que mi diseño original que abortaba la transacción entera.

---

## 5. Checklist priorizado de lo que falta

### 🔴 Crítico (hacer antes del primer despliegue real)

- [ ] **BUG-1**: añadir `search_similar_incidents()` en `worker/utils/api_client.py` — sin esto el RAG no funciona en absoluto
- [ ] Smoke test que valide BUG-1 en CI

### 🟡 Importante (semana 1 post-despliegue)

- [ ] Crear `hosting/dev/backfill_embeddings.php` para indexar el histórico existente de la tabla `incidents`
- [ ] Implementar `claim_batch()` en `worker.py` para activar el batching ya soportado por `rag_enrich.py`
- [ ] Documentar/compartir KQL queries de ejemplo (sección 8 del documento de implementación)
- [ ] Crear watchlist `OrinSecCredentials` en Sentinel y documentar el procedimiento
- [ ] Configurar al menos una Automation Rule de prueba en Sentinel para feedback al cerrar
- [ ] Fix BUG-2 (`getRateLimitInfo` real)

### 🟢 Deseable (mes 1-2 post-despliegue)

- [ ] Pestaña "🧠 RAG" en `admin.php` con KPIs y métricas operativas
- [ ] Endpoint AJAX `ajax_admin.php?action=rag_stats` para refresco en vivo
- [ ] Tests unitarios e integración mínimos (3 críticos arriba)
- [ ] Fix BUG-3 (`invalidateEnrichCacheForEntities` con parsing JSON)
- [ ] Tabla `enrich_log` para auditoría con TTL 90 días
- [ ] Documentación operativa `docs/rag.md`
- [ ] Documentación de integración Sentinel `docs/sentinel-integration.md`

### 🔵 Opcional (cuando haya tiempo)

- [ ] Logic App template para Sentinel (`.json` exportable)
- [ ] Reranking con cross-encoder (mencionado en roadmap futuro del plan)
- [ ] Multi-tenant si se pretende dar el sistema a más clientes
- [ ] Endpoint `/api/v1/explain.php` para debugging del RAG

---

## 6. Cifras finales

| Métrica | Valor |
|---|---|
| Cobertura del plan original | **~80%** |
| Líneas de código nuevas (RAG) | ~1.500 (PHP) + ~330 (Python) + scripts shell |
| Bugs críticos detectados | 1 (BUG-1, bloqueante) |
| Bugs no críticos | 3 |
| Componentes "bonus" no planificados | 4 (UI web, web-installer, script maestro, fallback LIKE) |
| Esfuerzo restante para 100% (estimado) | 4-6 días de trabajo enfocado |

---

## 7. Recomendación inmediata

**Antes de tocar nada más, parchear BUG-1.** Es 8 líneas de Python en `worker/utils/api_client.py`. Sin ese fix, el flujo asíncrono completo (KQL → enrich.php → cola → worker → LLM → resultado) está roto en su último tramo.

Tras parchear BUG-1, el flujo síncrono ya es totalmente operativo (no depende del worker, va directo `enrich.php` → `rag.php::searchSimilarIncidents` → respuesta). Eso permite empezar a probar contra Sentinel **hoy mismo** con queries en modo `sync`, y dejar el flujo asíncrono con LLM para una segunda fase.

Después: backfill, KQL queries de ejemplo, y la pestaña admin. En ese orden de impacto.

---

**Conclusión honesta:** este proyecto está **muchísimo más cerca de funcionar** de lo que mi análisis previo daba a entender. El equipo (sea humano o IA codificadora) hizo un trabajo sólido implementando la mayor parte del plan, con varias mejoras pragmáticas sobre el diseño original. Lo que falta es perfectamente abordable en 4-6 días, con un único parche crítico antes de cualquier despliegue.
