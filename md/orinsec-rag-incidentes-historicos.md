# OrinSec — RAG de Incidentes Históricos + Integración KQL Bidireccional

**Versión del documento:** 1.0
**Fecha:** 2026-05-03
**Proyecto base:** [alex-milla/orin-cyber](https://github.com/alex-milla)
**Autor del diseño:** Alex Milla (sesión de diseño con Claude)

---

## 0. Resumen ejecutivo

Este documento especifica la implementación de un sistema RAG (Retrieval-Augmented Generation) sobre los incidentes históricos de OrinSec, expuesto como API consumible desde Microsoft Sentinel/Defender XDR mediante el plugin KQL `evaluate http_request`. El objetivo es que cada incidente cerrado alimente un índice vectorial local que se consulta en tiempo real al llegar nuevos eventos, dando al LLM del Orin Nano contexto histórico del entorno real.

**Componentes clave a implementar:**

1. Tabla de embeddings de incidentes en SQLite (con extensión `sqlite-vec`).
2. Servicio paralelo a `llama-server` ejecutando un modelo de embeddings GGUF.
3. Dos endpoints REST nuevos: `/api/v1/enrich.php` y `/api/v1/feedback.php`.
4. Una tarea nueva en el worker: `rag_enrich`.
5. Sistema de cola con prioridades reaprovechando la infraestructura existente.
6. KQL queries de ejemplo para Sentinel.

**Compatible con la arquitectura actual:** sí. No requiere hardware adicional. Reutiliza el patrón pull worker→hosting existente, el sistema de tareas con `assignment`, el cifrado de credenciales (`crypto.php`) y el túnel Cloudflare con Zero Trust.

---

## 1. Arquitectura objetivo

```
┌──────────────────┐
│ Microsoft Sentinel│
│   / Defender XDR  │
└────────┬─────────┘
         │ KQL: evaluate http_request
         │ POST /api/v1/enrich
         │ Header: CF-Access-Client-Id/Secret + X-API-Key
         ▼
┌──────────────────────────────────────────────┐
│ Hosting PHP 8 + SQLite (compartido)          │
│                                              │
│  /api/v1/enrich.php  ─┐                      │
│  /api/v1/feedback.php │                      │
│                       ▼                      │
│  ┌───────────────────────────────────┐       │
│  │ Tabla: tasks (cola existente)     │       │
│  │   + priority (nuevo)              │       │
│  │   + assignment='worker'           │       │
│  │   + type='rag_enrich'             │       │
│  └───────────────────────────────────┘       │
│  ┌───────────────────────────────────┐       │
│  │ Tabla: incident_embeddings (nueva)│       │
│  │ Tabla: incident_embeddings_vec    │       │
│  │       (sqlite-vec virtual table)  │       │
│  └───────────────────────────────────┘       │
└────────┬─────────────────────────────────────┘
         │ pull tasks (HTTP saliente)
         ▼
┌──────────────────────────────────────────────┐
│ Jetson Orin Nano 8GB                         │
│                                              │
│  ┌────────────────┐    ┌──────────────────┐  │
│  │ llama-server   │    │ embed-server     │  │
│  │ (LLM principal)│    │ (modelo embed.   │  │
│  │  :8080         │    │  GGUF, :8081)    │  │
│  └────────────────┘    └──────────────────┘  │
│           ▲                     ▲            │
│           └─────────┬───────────┘            │
│                     │                        │
│              worker.py (Python)              │
│              + tasks/rag_enrich.py           │
│              + utils/embeddings.py           │
└──────────────────────────────────────────────┘
```

---

## 2. Modelo de datos

### 2.1 Nueva tabla: `incident_embeddings`

Almacena los embeddings y metadatos de incidentes cerrados. Es la fuente de verdad textual; los vectores se replican en una tabla virtual de `sqlite-vec` para búsqueda eficiente.

```sql
CREATE TABLE IF NOT EXISTS incident_embeddings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     INTEGER NOT NULL,           -- FK a incidents.id
    summary         TEXT NOT NULL,              -- texto que se embebió
    verdict         TEXT,                       -- TP / FP / inconclusive
    severity        TEXT,                       -- critical/high/medium/low
    mitre_tactic    TEXT,
    mitre_technique TEXT,
    classification  TEXT,                       -- GENERICO / DIRIGIDO
    entities_json   TEXT,                       -- JSON: lista de IOCs y entidades
    closed_at       TEXT NOT NULL,              -- ISO 8601
    closed_by       TEXT,                       -- usuario que cerró
    embedding_model TEXT NOT NULL,              -- ej: bge-small-en-v1.5
    embedding_dim   INTEGER NOT NULL,           -- ej: 384
    created_at      TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at      TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_incident_embeddings_incident
    ON incident_embeddings(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_embeddings_closed
    ON incident_embeddings(closed_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_embeddings_verdict
    ON incident_embeddings(verdict);
```

### 2.2 Tabla virtual `sqlite-vec`

Requiere cargar la extensión `sqlite-vec` en cada conexión PHP que vaya a hacer búsqueda. La instalación es un único `.so`/`.dll`/`.dylib` que se descarga del repo oficial.

```sql
-- Tabla virtual con índice vectorial
CREATE VIRTUAL TABLE IF NOT EXISTS incident_embeddings_vec
USING vec0(
    id INTEGER PRIMARY KEY,
    embedding FLOAT[384]   -- ajustar según el modelo elegido
);
```

**Decisión sobre la dimensión del embedding:** se recomienda `bge-small-en-v1.5` (384 dimensiones, ~130 MB) o `all-MiniLM-L6-v2` (384 dim, ~80 MB). Si se quiere multilingüe nativo, `paraphrase-multilingual-MiniLM-L12-v2` (384 dim, ~120 MB) o `bge-m3` (1024 dim, ~600 MB — más calidad pero más RAM).

### 2.3 Nuevas columnas en `tasks`

```sql
ALTER TABLE tasks ADD COLUMN priority INTEGER DEFAULT 5;
-- 1 = más alta (enrich síncrono espera respuesta)
-- 5 = normal (default actual)
-- 9 = más baja (alertas, batch, digests)

ALTER TABLE tasks ADD COLUMN parent_task_id INTEGER NULL;
-- Para agrupar batches: si llegan 50 entidades en un POST,
-- se crea una task "padre" y N tasks hijas con el mismo parent_task_id

CREATE INDEX IF NOT EXISTS idx_tasks_pending_priority
    ON tasks(status, priority, created_at)
    WHERE status = 'pending';
```

### 2.4 Tabla de caché de respuestas `enrich`

Para no consultar al LLM dos veces lo mismo en la misma franja temporal.

```sql
CREATE TABLE IF NOT EXISTS enrich_cache (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cache_key       TEXT NOT NULL UNIQUE,   -- SHA256 de subject+entities normalizadas
    response_json   TEXT NOT NULL,
    created_at      TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_enrich_cache_key ON enrich_cache(cache_key);
CREATE INDEX IF NOT EXISTS idx_enrich_cache_expires ON enrich_cache(expires_at);
```

TTL recomendado: 30 minutos para enriquecimientos (suficiente para que un analista que repita la query reciba respuesta instantánea, pero no tan largo como para no reflejar nuevos incidentes).

---

## 3. Servicio de embeddings en el Orin Nano

### 3.1 Modelo recomendado

| Modelo | Dim | Tamaño | RAM aprox. | Multilingüe | Velocidad |
|---|---|---|---|---|---|
| `bge-small-en-v1.5` | 384 | 130 MB | ~250 MB | No | Muy rápida |
| `all-MiniLM-L6-v2` | 384 | 80 MB | ~200 MB | Limitado | La más rápida |
| `paraphrase-multilingual-MiniLM-L12` | 384 | 120 MB | ~280 MB | Sí | Rápida |
| `bge-m3` | 1024 | 600 MB | ~900 MB | Sí (excelente) | Media |

**Recomendación inicial:** `bge-small-en-v1.5` por velocidad y peso. Si los incidentes de OrinSec son mayoritariamente en español, cambiar a `paraphrase-multilingual-MiniLM-L12-v2`.

Convertir a GGUF si no existe versión oficial:

```bash
# En el Orin Nano, dentro de un venv con llama.cpp clonado
python convert-hf-to-gguf.py /path/to/bge-small-en-v1.5 \
    --outfile bge-small-en-v1.5-q8_0.gguf \
    --outtype q8_0
```

### 3.2 Levantamiento del embed-server

Ejecutar `llama-server` en modo embeddings en un puerto distinto del LLM principal. **Punto crítico**: el binario de `llama.cpp` ya soporta `--embedding`, no se necesita otro servicio.

```bash
# Servicio systemd separado para no interferir con el LLM principal
# /etc/systemd/system/orinsec-embeddings.service

[Unit]
Description=OrinSec Embeddings Server (llama.cpp)
After=network.target

[Service]
Type=simple
User=orinsec
WorkingDirectory=/home/orinsec/llama.cpp
ExecStart=/home/orinsec/llama.cpp/build/bin/llama-server \
    --model /home/orinsec/models/bge-small-en-v1.5-q8_0.gguf \
    --embedding \
    --port 8081 \
    --host 127.0.0.1 \
    --ctx-size 512 \
    --batch-size 32 \
    -ngl 99 \
    --pooling mean
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Notas:**
- `--ctx-size 512` es suficiente para resúmenes de incidentes. No subir innecesariamente.
- `--pooling mean` es el modo estándar para embeddings de frase.
- `-ngl 99` carga todas las capas en GPU. En Orin 8GB con un modelo de 130 MB no hay problema.
- Coexiste con `llama-server` principal en `:8080`.

### 3.3 Cliente de embeddings en Python (worker)

Nuevo archivo: `worker/utils/embeddings.py`

```python
"""
Cliente para el servicio de embeddings local (llama-server --embedding).
Compatible con OpenAI Embeddings API (mismo formato).
"""
import requests
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


class EmbeddingClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8081", timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._dim_cache: Optional[int] = None

    def embed(self, texts: List[str]) -> List[List[float]]:
        """
        Devuelve la lista de embeddings para los textos dados.
        El servicio llama-server expone /v1/embeddings (OpenAI-compatible).
        """
        if not texts:
            return []

        payload = {"input": texts, "model": "local"}
        try:
            r = requests.post(
                f"{self.base_url}/v1/embeddings",
                json=payload,
                timeout=self.timeout,
            )
            r.raise_for_status()
            data = r.json()
            embeddings = [item["embedding"] for item in data["data"]]
            if embeddings and self._dim_cache is None:
                self._dim_cache = len(embeddings[0])
                logger.info(f"Embedding dimension detected: {self._dim_cache}")
            return embeddings
        except requests.exceptions.RequestException as e:
            logger.error(f"Embedding service error: {e}")
            raise

    def embed_one(self, text: str) -> List[float]:
        result = self.embed([text])
        return result[0] if result else []

    @property
    def dimension(self) -> int:
        if self._dim_cache is None:
            self.embed_one("warmup")
        return self._dim_cache or 0

    def health(self) -> bool:
        try:
            r = requests.get(f"{self.base_url}/health", timeout=5)
            return r.status_code == 200
        except Exception:
            return False
```

### 3.4 Cliente de embeddings en PHP (hosting)

Nuevo archivo: `hosting/includes/embedding_client.php`

```php
<?php
/**
 * Cliente PHP para el servicio de embeddings local.
 * Solo se usa desde el endpoint enrich.php (síncrono, no desde el worker).
 */

class EmbeddingClient {
    private string $baseUrl;
    private int $timeout;

    public function __construct(?string $baseUrl = null, int $timeout = 10) {
        // Reutiliza el túnel Cloudflare si está configurado, igual que LOCAL_LLM_URL
        $this->baseUrl = $baseUrl ?? (defined('LOCAL_EMBED_URL') ? LOCAL_EMBED_URL : 'http://127.0.0.1:8081');
        $this->timeout = $timeout;
    }

    /**
     * @param array $texts
     * @return array<array<float>>
     */
    public function embed(array $texts): array {
        if (empty($texts)) return [];

        $ch = curl_init($this->baseUrl . '/v1/embeddings');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                // Si embed-server está detrás de Cloudflare Access:
                'CF-Access-Client-Id: ' . (config('cf_access_client_id') ?? ''),
                'CF-Access-Client-Secret: ' . (config('cf_access_client_secret') ?? ''),
            ],
            CURLOPT_POSTFIELDS => json_encode([
                'input' => $texts,
                'model' => 'local',
            ]),
        ]);

        $resp = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);

        if ($resp === false || $httpCode !== 200) {
            throw new RuntimeException("Embedding service failed (HTTP $httpCode): $err");
        }

        $data = json_decode($resp, true);
        if (!isset($data['data'])) {
            throw new RuntimeException("Invalid embedding response");
        }

        return array_map(fn($item) => $item['embedding'], $data['data']);
    }

    public function embedOne(string $text): array {
        $result = $this->embed([$text]);
        return $result[0] ?? [];
    }
}
```

---

## 4. Endpoints REST nuevos

### 4.1 `POST /api/v1/enrich.php`

**Propósito:** punto de entrada para Sentinel/KQL. Recibe entidades o incidentes a enriquecer, decide si responde con caché, crea tareas en cola, o ambos.

**Auth:** `X-API-Key` (existente) + headers de Cloudflare Access.

**Request body:**

```json
{
  "mode": "sync" | "async" | "hybrid",
  "entities": [
    {
      "type": "incident" | "ip" | "hash" | "domain" | "user",
      "subject": "Multiple failed login attempts",
      "value": "10.0.0.45",
      "context": {
        "rule_name": "Brute force detection",
        "host": "SRV-DB-01",
        "user": "admin",
        "timestamp": "2026-05-03T10:23:00Z",
        "severity": "high"
      }
    }
  ],
  "options": {
    "k": 5,
    "include_kql_hunting": true,
    "language": "es"
  }
}
```

**Response (modo `sync` / `hybrid`):**

```json
{
  "request_id": "req_a3f9c2",
  "results": [
    {
      "entity_index": 0,
      "status": "completed" | "queued",
      "task_id": null | 12345,
      "verdict": "likely_false_positive",
      "score": 0.87,
      "confidence": "high",
      "similar_cases": [
        {
          "incident_id": 234,
          "similarity": 0.91,
          "summary": "Backup nocturno de Veeam, FP confirmado",
          "verdict": "FP",
          "closed_at": "2026-04-12T03:14:00Z"
        }
      ],
      "recommendation": "Patrón consistente con job de backup. 14 casos previos cerrados como FP.",
      "mitre_tactic": null,
      "kql_hunting": "..."
    }
  ],
  "from_cache": [0, 2],
  "queued": [1],
  "rate_limit": {
    "remaining": 45,
    "reset_at": "2026-05-03T11:00:00Z"
  }
}
```

**Modos de operación:**

- **`sync`**: solo busca en caché y BD, no encola nada al LLM. Latencia <200ms. Para queries KQL en vivo.
- **`async`**: encola todo, devuelve `task_id` inmediato. Para análisis profundos donde la respuesta llegará por otro canal.
- **`hybrid`** (recomendado por defecto): cacheadas/triviales devuelve sync, las pesadas las encola.

**Esqueleto del archivo:**

```php
<?php
// hosting/api/v1/enrich.php
require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/embedding_client.php';
require_once __DIR__ . '/../../includes/functions.php';

header('Content-Type: application/json');

// 1. Autenticación
$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
$keyRow = validateApiKey($apiKey); // ya existe en includes/auth.php
if (!$keyRow) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid API key']);
    exit;
}

// 2. Rate limiting (reutilizar la función existente)
if (!checkRateLimit("enrich_{$apiKey}", limit: 60, windowSec: 60)) {
    http_response_code(429);
    echo json_encode(['error' => 'Rate limit exceeded']);
    exit;
}

// 3. Parseo del body
$input = json_decode(file_get_contents('php://input'), true);
if (!$input || !isset($input['entities']) || !is_array($input['entities'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid request body']);
    exit;
}

$mode = $input['mode'] ?? 'hybrid';
$entities = $input['entities'];
$options = $input['options'] ?? [];
$k = min((int)($options['k'] ?? 5), 10);

if (count($entities) > 100) {
    http_response_code(400);
    echo json_encode(['error' => 'Too many entities (max 100)']);
    exit;
}

$results = [];
$queued = [];
$fromCache = [];

foreach ($entities as $idx => $entity) {
    $cacheKey = computeEnrichCacheKey($entity);

    // Intento de caché
    $cached = getEnrichCache($cacheKey);
    if ($cached) {
        $results[] = array_merge(['entity_index' => $idx, 'status' => 'completed'], $cached);
        $fromCache[] = $idx;
        continue;
    }

    if ($mode === 'sync') {
        // Solo búsqueda vectorial sin LLM
        $similar = searchSimilarIncidents($entity, $k);
        $response = buildSyncResponse($entity, $similar);
        setEnrichCache($cacheKey, $response, ttlSeconds: 1800);
        $results[] = array_merge(['entity_index' => $idx, 'status' => 'completed'], $response);
    } else {
        // Encolar para análisis con LLM
        $taskId = createTask([
            'type' => 'rag_enrich',
            'priority' => 1, // alta prioridad: viene de KQL en vivo
            'input_data' => json_encode([
                'entity' => $entity,
                'options' => $options,
                'cache_key' => $cacheKey,
            ]),
            'assignment' => 'worker',
            'created_by' => $keyRow['user_id'],
        ]);
        $results[] = [
            'entity_index' => $idx,
            'status' => 'queued',
            'task_id' => $taskId,
        ];
        $queued[] = $idx;
    }
}

echo json_encode([
    'request_id' => generateRequestId(),
    'results' => $results,
    'from_cache' => $fromCache,
    'queued' => $queued,
    'rate_limit' => getRateLimitInfo("enrich_{$apiKey}"),
], JSON_UNESCAPED_UNICODE);
```

**Función auxiliar de búsqueda vectorial** (en `functions.php` o `includes/rag.php`):

```php
function searchSimilarIncidents(array $entity, int $k = 5): array {
    $client = new EmbeddingClient();
    $query = buildEntityText($entity); // concatena subject + context relevante
    $embedding = $client->embedOne($query);

    if (empty($embedding)) return [];

    $db = db(); // tu helper de PDO existente

    // sqlite-vec: KNN sobre la tabla virtual
    $sql = "
        SELECT
            ie.incident_id,
            ie.summary,
            ie.verdict,
            ie.severity,
            ie.mitre_tactic,
            ie.classification,
            ie.closed_at,
            v.distance
        FROM incident_embeddings_vec v
        JOIN incident_embeddings ie ON ie.id = v.id
        WHERE v.embedding MATCH ?
          AND k = ?
        ORDER BY v.distance ASC
    ";

    $stmt = $db->prepare($sql);
    $stmt->execute([
        json_encode($embedding),
        $k,
    ]);

    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    return array_map(function($r) {
        $r['similarity'] = 1 - (float)$r['distance']; // convertir distancia coseno a similitud
        return $r;
    }, $rows);
}

function buildEntityText(array $entity): string {
    $parts = [
        $entity['subject'] ?? '',
        $entity['value'] ?? '',
    ];
    $ctx = $entity['context'] ?? [];
    foreach (['rule_name', 'host', 'user', 'severity'] as $field) {
        if (!empty($ctx[$field])) {
            $parts[] = "{$field}: {$ctx[$field]}";
        }
    }
    return trim(implode(' | ', array_filter($parts)));
}

function computeEnrichCacheKey(array $entity): string {
    $normalized = [
        'subject' => strtolower(trim($entity['subject'] ?? '')),
        'value' => strtolower(trim($entity['value'] ?? '')),
        'type' => $entity['type'] ?? '',
    ];
    return hash('sha256', json_encode($normalized));
}
```

### 4.2 `POST /api/v1/feedback.php`

**Propósito:** recibir el cierre de incidentes para alimentar el RAG. Llamado tanto desde el propio OrinSec (al cerrar un incidente en `blue_team.php`) como desde Sentinel cuando un analista cierra un incidente allí (vía Logic App o automation rule).

**Request body:**

```json
{
  "incident_id": 1234,
  "external_ref": "sentinel:abc-123-def",
  "summary": "Phishing dirigido al CFO. Usuario reportó. Bloqueado en EOP. Sin compromiso.",
  "verdict": "TP",
  "severity": "high",
  "mitre_tactic": "Initial Access",
  "mitre_technique": "T1566.001",
  "classification": "DIRIGIDO",
  "entities": [
    {"type": "email", "value": "attacker@evil.com"},
    {"type": "url", "value": "http://malicious.example/login"},
    {"type": "user", "value": "cfo@empresa.com"}
  ],
  "closed_by": "analyst1",
  "closed_at": "2026-05-03T11:42:00Z",
  "notes": "Coincide con campaña BEC observada en sector financiero"
}
```

**Response:**

```json
{
  "success": true,
  "embedding_id": 567,
  "incident_id": 1234,
  "embedding_model": "bge-small-en-v1.5",
  "embedding_dim": 384
}
```

**Esqueleto:**

```php
<?php
// hosting/api/v1/feedback.php
require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/embedding_client.php';

header('Content-Type: application/json');

$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
$keyRow = validateApiKey($apiKey);
if (!$keyRow) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid API key']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
if (!$input || !isset($input['summary'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid request body: summary required']);
    exit;
}

try {
    $client = new EmbeddingClient();
    $textToEmbed = buildIncidentText($input);
    $embedding = $client->embedOne($textToEmbed);

    if (empty($embedding)) {
        throw new RuntimeException("Empty embedding returned");
    }

    $db = db();
    $db->beginTransaction();

    // 1. Insertar metadatos
    $stmt = $db->prepare("
        INSERT INTO incident_embeddings
            (incident_id, summary, verdict, severity, mitre_tactic,
             mitre_technique, classification, entities_json, closed_at,
             closed_by, embedding_model, embedding_dim)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ");
    $stmt->execute([
        $input['incident_id'] ?? null,
        $input['summary'],
        $input['verdict'] ?? null,
        $input['severity'] ?? null,
        $input['mitre_tactic'] ?? null,
        $input['mitre_technique'] ?? null,
        $input['classification'] ?? null,
        json_encode($input['entities'] ?? []),
        $input['closed_at'] ?? date('c'),
        $input['closed_by'] ?? null,
        'bge-small-en-v1.5', // o leer de config
        count($embedding),
    ]);
    $embeddingId = (int)$db->lastInsertId();

    // 2. Insertar vector en la tabla virtual
    $stmt = $db->prepare("
        INSERT INTO incident_embeddings_vec (id, embedding)
        VALUES (?, ?)
    ");
    $stmt->execute([$embeddingId, json_encode($embedding)]);

    $db->commit();

    // 3. Invalidar caché de enriquecimientos relacionados (opcional)
    invalidateEnrichCacheForEntities($input['entities'] ?? []);

    echo json_encode([
        'success' => true,
        'embedding_id' => $embeddingId,
        'incident_id' => $input['incident_id'] ?? null,
        'embedding_model' => 'bge-small-en-v1.5',
        'embedding_dim' => count($embedding),
    ]);

} catch (Exception $e) {
    if ($db->inTransaction()) $db->rollBack();
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}

function buildIncidentText(array $input): string {
    $parts = [
        "[{$input['verdict']}] " . ($input['summary'] ?? ''),
    ];
    if (!empty($input['mitre_tactic'])) {
        $parts[] = "MITRE: {$input['mitre_tactic']} / " . ($input['mitre_technique'] ?? '');
    }
    if (!empty($input['classification'])) {
        $parts[] = "Tipo: {$input['classification']}";
    }
    foreach ($input['entities'] ?? [] as $ent) {
        $parts[] = "[{$ent['type']}] {$ent['value']}";
    }
    if (!empty($input['notes'])) {
        $parts[] = "Notas: {$input['notes']}";
    }
    return implode("\n", $parts);
}
```

### 4.3 Whitelist de `.htaccess`

`hosting/api/v1/.htaccess` debe permitir los nuevos endpoints (recordatorio del incident v0.10.2 de tu CHANGELOG):

```apache
<FilesMatch "^(tasks|heartbeat|commands|admin_providers|chat_external|enrich|feedback|alerts|blue_team|ioc_tracker|azure_sync|worker_config)\.php$">
    Require all granted
</FilesMatch>
```

---

## 5. Tarea nueva en el worker: `rag_enrich`

### 5.1 Estructura

Nuevo archivo: `worker/tasks/rag_enrich.py`

```python
"""
Tarea rag_enrich: dado un objeto entity (IP, hash, subject, descripción incidente),
busca casos similares vía embeddings + sqlite-vec, llama al LLM con esos casos
como contexto, y devuelve un JSON con veredicto, score, recomendación y KQL.
"""
import json
import logging
from typing import Dict, Any, List
from utils.embeddings import EmbeddingClient
from utils.llm_client import LlmClient
from utils.api_client import ApiClient

logger = logging.getLogger(__name__)


class RagEnrichTask:
    TYPE = "rag_enrich"

    def __init__(self, config_path: str):
        self.config_path = config_path
        self.embed_client = EmbeddingClient()
        self.llm = LlmClient()
        self.api = ApiClient(config_path)

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        input_data = json.loads(task["input_data"])
        entity = input_data["entity"]
        options = input_data.get("options", {})
        k = min(int(options.get("k", 5)), 10)
        language = options.get("language", "es")

        # 1. Buscar casos similares via API del hosting
        # (porque sqlite-vec vive en el hosting; el worker pide búsqueda)
        similar = self.api.search_similar_incidents(
            entity=entity, k=k
        )

        # 2. Construir prompt para el LLM con los casos similares
        prompt = self._build_prompt(entity, similar, language)

        # 3. Llamar al LLM con respuesta JSON estructurada
        llm_response = self.llm.chat_json(
            system_prompt=self._system_prompt(language),
            user_prompt=prompt,
            max_tokens=800,
        )

        if not llm_response:
            logger.warning("LLM returned empty/invalid JSON, falling back")
            llm_response = self._fallback_response(entity, similar)

        # 4. Construir respuesta enriquecida
        result = {
            "verdict": llm_response.get("verdict", "inconclusive"),
            "score": float(llm_response.get("score", 0.5)),
            "confidence": llm_response.get("confidence", "medium"),
            "similar_cases": [
                {
                    "incident_id": c["incident_id"],
                    "similarity": round(c["similarity"], 3),
                    "summary": c["summary"][:200],
                    "verdict": c["verdict"],
                    "closed_at": c["closed_at"],
                }
                for c in similar[:k]
            ],
            "recommendation": llm_response.get("recommendation", ""),
            "mitre_tactic": llm_response.get("mitre_tactic"),
            "mitre_technique": llm_response.get("mitre_technique"),
            "kql_hunting": self._generate_kql(entity, llm_response)
            if options.get("include_kql_hunting")
            else None,
        }

        return {
            "status": "completed",
            "result_json": json.dumps(result, ensure_ascii=False),
        }

    def _system_prompt(self, lang: str) -> str:
        if lang == "es":
            return (
                "Eres un analista SOC senior. Recibirás una entidad sospechosa "
                "y casos similares previos del entorno. Devuelve SOLO JSON válido "
                "con: verdict (likely_true_positive|likely_false_positive|inconclusive), "
                "score (0-1), confidence (low|medium|high), recommendation (texto breve), "
                "mitre_tactic, mitre_technique. Basa tu juicio en los casos previos."
            )
        return (
            "You are a senior SOC analyst. You'll receive a suspicious entity "
            "and similar prior cases from the environment. Return ONLY valid JSON "
            "with: verdict, score (0-1), confidence, recommendation, mitre_tactic, "
            "mitre_technique. Base your judgment on prior cases."
        )

    def _build_prompt(self, entity: Dict, similar: List[Dict], lang: str) -> str:
        ent_text = json.dumps(entity, ensure_ascii=False, indent=2)
        if not similar:
            cases_text = "(sin casos similares en el histórico)"
        else:
            cases_text = "\n\n".join([
                f"Caso #{i+1} (similitud {c['similarity']:.2f}, veredicto {c['verdict']}, "
                f"cerrado {c['closed_at']}):\n{c['summary']}"
                for i, c in enumerate(similar)
            ])

        return f"""ENTIDAD A ANALIZAR:
{ent_text}

CASOS SIMILARES PREVIOS DEL ENTORNO:
{cases_text}

Analiza la entidad considerando el patrón histórico. Responde JSON."""

    def _fallback_response(self, entity, similar):
        """Si el LLM falla, devolver algo razonable basado solo en similitud."""
        if not similar:
            return {
                "verdict": "inconclusive",
                "score": 0.5,
                "confidence": "low",
                "recommendation": "Sin histórico previo. Investigar manualmente.",
            }
        # Voto por mayoría de los casos similares
        verdicts = [c["verdict"] for c in similar if c.get("verdict")]
        tp = verdicts.count("TP")
        fp = verdicts.count("FP")
        if fp > tp * 2:
            v = "likely_false_positive"
        elif tp > fp:
            v = "likely_true_positive"
        else:
            v = "inconclusive"
        return {
            "verdict": v,
            "score": 0.6,
            "confidence": "medium",
            "recommendation": f"{len(similar)} casos similares: {tp} TP / {fp} FP",
        }

    def _generate_kql(self, entity, llm_response):
        """Genera una query KQL básica para hunting de la entidad."""
        ent_type = entity.get("type", "")
        ent_value = entity.get("value", "")
        if ent_type == "ip":
            return f"""SecurityEvent
| where TimeGenerated > ago(7d)
| where IpAddress == "{ent_value}"
| project TimeGenerated, EventID, Computer, Account, IpAddress"""
        if ent_type == "hash":
            return f"""DeviceFileEvents
| where TimeGenerated > ago(30d)
| where SHA256 == "{ent_value}"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName"""
        if ent_type == "domain":
            return f"""DnsEvents
| where TimeGenerated > ago(7d)
| where Name contains "{ent_value}"
| summarize count() by Computer, Name"""
        return None
```

### 5.2 Registro en `TASK_REGISTRY`

En `worker/worker.py`:

```python
from tasks.rag_enrich import RagEnrichTask

TASK_REGISTRY = {
    "cve_search": CveSearchTask,
    "incident_analysis": IncidentAnalysisTask,
    "azure_sync": AzureSyncTask,
    "alert_scan": AlertScanTask,
    "rag_enrich": RagEnrichTask,   # ← NUEVO
}
```

### 5.3 Endpoint auxiliar para que el worker busque vectores

El worker no tiene acceso directo a la BD del hosting. Necesita un endpoint para pedir búsqueda vectorial:

`hosting/api/v1/rag_search.php`

```php
<?php
// Endpoint interno para que el worker pida búsqueda vectorial
// Auth: API key del worker (no del usuario final)
require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/rag.php'; // donde vive searchSimilarIncidents

header('Content-Type: application/json');

$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
$keyRow = validateWorkerApiKey($apiKey); // solo workers
if (!$keyRow) {
    http_response_code(401);
    echo json_encode(['error' => 'Worker API key required']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
$entity = $input['entity'] ?? null;
$k = min((int)($input['k'] ?? 5), 10);

if (!$entity) {
    http_response_code(400);
    echo json_encode(['error' => 'entity required']);
    exit;
}

// Aquí el hosting hace embedding del query (no el worker)
// porque sqlite-vec vive aquí
$similar = searchSimilarIncidents($entity, $k);

echo json_encode(['similar' => $similar]);
```

Y en `worker/utils/api_client.py`, añadir:

```python
def search_similar_incidents(self, entity: Dict, k: int = 5) -> List[Dict]:
    r = requests.post(
        f"{self.base_url}/api/v1/rag_search.php",
        json={"entity": entity, "k": k},
        headers={"X-API-Key": self.api_key},
        timeout=15,
    )
    r.raise_for_status()
    return r.json().get("similar", [])
```

---

## 6. Cola con prioridades

### 6.1 Reclamación atómica con prioridad

Modificar `hosting/api/v1/tasks.php` action `claim`:

```sql
-- Antes:
SELECT * FROM tasks
WHERE status = 'pending' AND assignment = 'worker'
ORDER BY created_at ASC
LIMIT 1;

-- Después:
SELECT * FROM tasks
WHERE status = 'pending' AND assignment = 'worker'
ORDER BY priority ASC, created_at ASC
LIMIT 1;
```

### 6.2 Política de prioridades

| Prioridad | Tipo de tarea | Espera tolerable |
|---|---|---|
| 1 | `rag_enrich` desde KQL hybrid (analista esperando) | <30s |
| 2 | `chat` interactivo, `incident_analysis` con flag urgente | <60s |
| 5 | `cve_search` manual, `incident_analysis` batch | <5min |
| 7 | `azure_sync` programado | <10min |
| 9 | `alert_scan`, `period_analysis` (digest), batch nocturno | sin límite |

### 6.3 Cap de cola y fallback

Antes de encolar nueva tarea de prioridad 1 en `enrich.php`:

```php
$pendingHighPriority = $db->query("
    SELECT COUNT(*) FROM tasks
    WHERE status = 'pending' AND priority <= 2
")->fetchColumn();

if ($pendingHighPriority > 50) {
    // Saturado: 3 opciones
    // a) 429 al cliente
    // b) Fallback a Virtual Worker (cloud)
    // c) Caer a sync-only (solo búsqueda vectorial sin LLM)

    if (config('rag_overflow_policy') === 'cloud_fallback') {
        $task['assignment'] = 'provider:1:deepseek/deepseek-chat:free';
    } else {
        http_response_code(429);
        echo json_encode([
            'error' => 'Queue saturated',
            'retry_after_seconds' => 30,
        ]);
        exit;
    }
}
```

---

## 7. Batching en el worker

Cuando hay varias tareas `rag_enrich` pendientes con baja prioridad relativa entre ellas, agruparlas en una sola llamada al LLM ahorra mucho tiempo. Cambio en `worker.py`:

```python
def claim_batch(self, max_tasks: int = 5) -> List[Dict]:
    """
    Reclama hasta N tareas del mismo tipo y prioridad similar.
    Útil para rag_enrich: una sola llamada LLM analiza 5 entidades.
    """
    # Reclamar primera tarea normalmente
    first = self.api.claim_task()
    if not first:
        return []

    if first["type"] != "rag_enrich":
        return [first]

    # Solo agrupar enrich. Reclamar más con misma prioridad.
    batch = [first]
    for _ in range(max_tasks - 1):
        extra = self.api.claim_task(
            type_filter="rag_enrich",
            max_priority=first["priority"]
        )
        if not extra:
            break
        batch.append(extra)

    return batch
```

Y en `RagEnrichTask`:

```python
def run_batch(self, tasks: List[Dict]) -> List[Dict]:
    """Procesa varias entidades en una sola llamada al LLM."""
    entities = [json.loads(t["input_data"])["entity"] for t in tasks]

    # Buscar similares para cada uno (paralelizable)
    similar_map = {
        i: self.api.search_similar_incidents(ent, k=3)
        for i, ent in enumerate(entities)
    }

    # Un solo prompt con las N entidades
    prompt = self._build_batch_prompt(entities, similar_map)
    llm_response = self.llm.chat_json(
        system_prompt=self._system_prompt_batch(),
        user_prompt=prompt,
        max_tokens=2000,
    )

    # llm_response esperado: {"results": [{...}, {...}, ...]}
    results = llm_response.get("results", [])
    return [
        {"task_id": t["id"], "result_json": json.dumps(r, ensure_ascii=False)}
        for t, r in zip(tasks, results)
    ]
```

---

## 8. Integración con KQL (Sentinel / Defender XDR)

### 8.1 Configuración previa en Sentinel

El plugin `evaluate http_request` requiere habilitarlo a nivel de workspace o usar la versión "preview". Documentación de Microsoft: buscar "KQL http_request plugin".

Las **API keys nunca van en texto plano en la query**. Usar **Azure Key Vault** y referenciar el secreto desde la query, o usar `_GetWatchlist()` con credenciales cifradas.

### 8.2 Query KQL básica — enriquecer alertas en vivo

```kql
// === OrinSec Enrichment - Suspicious Logins ===
let OrinSecUrl = "https://hosting.orinsec.example.com/api/v1/enrich.php";
let OrinSecKey = _GetWatchlist("OrinSecCredentials")
    | where Name == "api_key"
    | project Value
    | take 1;
let CFAccessId = _GetWatchlist("OrinSecCredentials")
    | where Name == "cf_access_id"
    | project Value
    | take 1;
let CFAccessSecret = _GetWatchlist("OrinSecCredentials")
    | where Name == "cf_access_secret"
    | project Value
    | take 1;
//
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0  // login fallido
| summarize FailCount = count() by IPAddress, UserPrincipalName, AppDisplayName
| where FailCount >= 5
| project IPAddress, UserPrincipalName, AppDisplayName, FailCount
| extend EnrichBody = bag_pack(
    "mode", "sync",
    "entities", pack_array(bag_pack(
        "type", "ip",
        "subject", strcat("Multiple failed logins to ", AppDisplayName),
        "value", IPAddress,
        "context", bag_pack(
            "user", UserPrincipalName,
            "fail_count", FailCount,
            "severity", "medium"
        )
    )),
    "options", bag_pack("k", 5, "language", "es")
)
| extend RequestUrl = OrinSecUrl
| evaluate http_request(
    RequestUrl,
    dynamic({
        "Content-Type": "application/json",
        "X-API-Key": tostring(toscalar(OrinSecKey)),
        "CF-Access-Client-Id": tostring(toscalar(CFAccessId)),
        "CF-Access-Client-Secret": tostring(toscalar(CFAccessSecret))
    }),
    EnrichBody
)
| mv-expand answer = ResponseBody.results
| project
    IPAddress,
    UserPrincipalName,
    FailCount,
    OrinSecVerdict = tostring(answer.verdict),
    OrinSecScore = todouble(answer.score),
    OrinSecRecommendation = tostring(answer.recommendation),
    SimilarCases = answer.similar_cases
```

### 8.3 Query KQL — enriquecer hashes en bloque

```kql
// === OrinSec - Hash enrichment (batched) ===
let OrinSecUrl = "https://hosting.orinsec.example.com/api/v1/enrich.php";
let OrinSecKey = toscalar(_GetWatchlist("OrinSecCredentials") | where Name == "api_key" | project Value);
//
DeviceFileEvents
| where TimeGenerated > ago(24h)
| where ActionType in ("FileCreated", "FileModified")
| where isnotempty(SHA256)
| summarize Hosts = make_set(DeviceName), FirstSeen = min(TimeGenerated) by SHA256
| where array_length(Hosts) >= 2  // hashes que aparecen en >=2 hosts
| take 20  // CRÍTICO: limitar para no saturar OrinSec
| summarize Entities = make_list(bag_pack(
    "type", "hash",
    "subject", "SHA256 seen on multiple hosts",
    "value", SHA256,
    "context", bag_pack(
        "host_count", array_length(Hosts),
        "first_seen", tostring(FirstSeen)
    )
))
| extend Body = bag_pack(
    "mode", "hybrid",
    "entities", Entities,
    "options", bag_pack("k", 3, "language", "es")
)
| evaluate http_request(
    OrinSecUrl,
    dynamic({
        "Content-Type": "application/json",
        "X-API-Key": OrinSecKey
    }),
    Body
)
| mv-expand result = ResponseBody.results
| project
    Hash = tostring(result.entity_index),
    Status = tostring(result.status),
    TaskId = tolong(result.task_id),
    Verdict = tostring(result.verdict),
    Recommendation = tostring(result.recommendation)
```

### 8.4 Query KQL — feedback al cerrar incidente

```kql
// === OrinSec - Feedback al cerrar incidente ===
// Programar como Automation Rule en Sentinel: trigger = "When incident is closed"
//
let OrinSecUrl = "https://hosting.orinsec.example.com/api/v1/feedback.php";
let OrinSecKey = toscalar(_GetWatchlist("OrinSecCredentials") | where Name == "api_key" | project Value);
//
SecurityIncident
| where TimeGenerated > ago(15m)
| where Status == "Closed"
| extend EntityList = (
    AlertIds
    | mv-expand AlertId
    | join SecurityAlert on AlertId == SystemAlertId
    | summarize make_list(Entities)
)
| project
    IncidentNumber,
    Title,
    Severity,
    Classification,
    ClassificationReason,
    ClassificationComment,
    Owner = tostring(Owner.userPrincipalName),
    ClosedTime,
    EntityList
| extend Body = bag_pack(
    "incident_id", IncidentNumber,
    "external_ref", strcat("sentinel:", tostring(IncidentNumber)),
    "summary", strcat(Title, ". ", ClassificationComment),
    "verdict", iff(Classification in ("TruePositive", "BenignPositive"), "TP", "FP"),
    "severity", tolower(Severity),
    "classification", iff(Classification == "TruePositive", "DIRIGIDO", "GENERICO"),
    "entities", EntityList,
    "closed_by", Owner,
    "closed_at", tostring(ClosedTime),
    "notes", ClassificationReason
)
| evaluate http_request(
    OrinSecUrl,
    dynamic({"Content-Type": "application/json", "X-API-Key": OrinSecKey}),
    Body
)
| project IncidentNumber, OrinSecResponse = ResponseBody
```

### 8.5 Query KQL — modo asíncrono con polling

Cuando el análisis es pesado y no se quiere bloquear KQL:

```kql
// Paso 1: encolar análisis profundo
let OrinSecUrl = "https://hosting.orinsec.example.com/api/v1/enrich.php";
let OrinSecKey = toscalar(_GetWatchlist("OrinSecCredentials") | where Name == "api_key" | project Value);
//
let TaskIds = (
    SecurityIncident
    | where TimeGenerated > ago(30m)
    | where Status == "New"
    | take 10
    | extend Body = bag_pack(
        "mode", "async",
        "entities", pack_array(bag_pack(
            "type", "incident",
            "subject", Title,
            "value", tostring(IncidentNumber),
            "context", bag_pack("severity", Severity)
        )),
        "options", bag_pack("k", 5, "include_kql_hunting", true, "language", "es")
    )
    | evaluate http_request(
        OrinSecUrl,
        dynamic({"Content-Type": "application/json", "X-API-Key": OrinSecKey}),
        Body
    )
    | mv-expand result = ResponseBody.results
    | project IncidentNumber, TaskId = tolong(result.task_id)
);
TaskIds

// Paso 2 (en una segunda query, 30s-2min después):
// Consultar /api/v1/tasks.php?action=result&task_id=XXX
// y actualizar el incidente con los resultados.
```

### 8.6 Watchlist de credenciales

Crear en Sentinel un watchlist `OrinSecCredentials` con dos columnas (`Name`, `Value`) y filas:
- `api_key` → la key generada por `install.php` de OrinSec
- `cf_access_id` → Cloudflare Service Token Client ID
- `cf_access_secret` → Cloudflare Service Token Client Secret

Restringir RBAC del watchlist solo a los analistas SOC autorizados.

---

## 9. Flujo end-to-end paso a paso

### 9.1 Caso 1: Analista ejecuta hunt en Sentinel

1. Analista ejecuta query KQL del § 8.2 en Sentinel.
2. KQL agrupa los resultados (5 IPs sospechosas).
3. KQL hace **1 sola llamada** POST a `/api/v1/enrich.php` con `mode=sync` y las 5 entidades.
4. `enrich.php` valida API key + Cloudflare Access + rate limit.
5. Para cada entidad:
   - Calcula `cache_key` = SHA256(subject+value normalizados).
   - Busca en `enrich_cache`. Si hit y no expirado → respuesta inmediata.
   - Si miss → llama a `EmbeddingClient::embedOne()` → consulta `incident_embeddings_vec` con KNN.
   - Construye respuesta sin LLM (en modo `sync`).
   - Guarda en `enrich_cache` con TTL 30 min.
6. KQL recibe respuesta en <500ms y la muestra en columnas adicionales.

### 9.2 Caso 2: Sentinel envía incidente nuevo (modo hybrid)

1. Analytic rule de Sentinel dispara incidente.
2. Automation rule lanza query KQL `mode=hybrid`.
3. `enrich.php` recibe; cache miss → encola tarea `rag_enrich` priority=1.
4. Devuelve `{"status":"queued","task_id":12345}` a Sentinel.
5. Sentinel registra `task_id` como comentario al incidente.
6. Worker del Orin reclama tarea (loop principal cada 2s).
7. `RagEnrichTask` llama a `/api/v1/rag_search.php` para obtener similares.
8. LLM local recibe entidad + 5 casos similares + prompt.
9. LLM devuelve JSON con verdict, score, recommendation, MITRE.
10. Worker llama a `/api/v1/tasks.php?action=result` con el resultado.
11. Logic App (o cron) en Sentinel detecta tarea completada → actualiza incidente con comentario enriquecido.

### 9.3 Caso 3: Analista cierra incidente en Sentinel

1. Analista marca incidente como "Closed - True Positive".
2. Automation rule (§ 8.4) ejecuta query KQL.
3. KQL llama POST `/api/v1/feedback.php` con summary, verdict, entities, etc.
4. `feedback.php` llama al embed-server local del Orin (vía túnel CF si está fuera).
5. Inserta fila en `incident_embeddings` y vector en `incident_embeddings_vec`.
6. Invalida caché de enrich relacionados.
7. **Próxima vez** que llegue una alerta similar, el RAG ya conoce este caso.

---

## 10. Configuración nueva

### 10.1 En `hosting/includes/config.php`

```php
// URL del servicio de embeddings (mismo Orin, distinto puerto)
define('LOCAL_EMBED_URL', 'https://embed-orin.cyberintelligence.dev');

// O directo si está en la misma red:
// define('LOCAL_EMBED_URL', 'http://192.168.1.50:8081');

// Política de overflow de cola RAG
// Options: 'reject_429' | 'cloud_fallback' | 'sync_only_degraded'
define('RAG_OVERFLOW_POLICY', 'reject_429');

// TTL de caché de enriquecimientos en segundos
define('ENRICH_CACHE_TTL', 1800);

// Límite de entidades por petición a /enrich
define('ENRICH_MAX_ENTITIES_PER_REQUEST', 100);

// Tamaño máximo de cola high-priority antes de saturar
define('RAG_QUEUE_HIGH_THRESHOLD', 50);
```

### 10.2 En `worker/config.ini`

```ini
[embeddings]
url = http://127.0.0.1:8081
model = bge-small-en-v1.5
dim = 384
timeout = 30

[rag_enrich]
batch_size = 5
default_k = 5
max_k = 10
include_kql_hunting = true
```

---

## 11. Migración paso a paso (orden de despliegue)

1. **Hosting** — añadir migraciones SQL (tablas `incident_embeddings`, `enrich_cache`, columnas en `tasks`). Auto-aplicar en `db.php` como ya hace OrinSec.
2. **Hosting** — instalar extensión `sqlite-vec` en el servidor PHP. Es un único `.so` que carga con `PDO::sqliteCreateFunction` o `loadExtension()`. Probar con `SELECT vec_version()`.
3. **Orin** — descargar modelo de embeddings GGUF, crear servicio `orinsec-embeddings.service`, comprobar `curl http://localhost:8081/health`.
4. **Orin** — exponer puerto 8081 vía Cloudflare Tunnel adicional (subdomain `embed-orin.cyberintelligence.dev`) protegido con Cloudflare Access (mismo Service Token o uno nuevo).
5. **Hosting** — desplegar `embedding_client.php`, `rag.php`, `enrich.php`, `feedback.php`, `rag_search.php`. Añadir whitelist en `.htaccess`.
6. **Hosting** — backfill: script CLI que recorre `incidents` cerrados existentes y crea embeddings para ellos. Opcional pero muy recomendable para arrancar con histórico.
7. **Worker** — desplegar `tasks/rag_enrich.py`, `utils/embeddings.py` (en realidad solo se usa para el embed-server health, el embedding del query lo hace el hosting), registrar en `TASK_REGISTRY`.
8. **Sentinel** — crear watchlist `OrinSecCredentials`, crear automation rules con las KQL del § 8.
9. **Validación** — disparar incidente de prueba en Sentinel, verificar que `enrich.php` lo recibe, que llega al worker, que vuelve enriquecido.
10. **Monitorización** — añadir métricas a `admin.php` → Workers: tareas `rag_enrich` por estado, latencia media, tamaño de `incident_embeddings`, hit rate de caché.

---

## 12. Backfill — script CLI

Nuevo: `hosting/dev/backfill_embeddings.php` (protegido por `.htaccess` `Require all denied`)

```php
<?php
/**
 * Script CLI para generar embeddings de todos los incidentes cerrados existentes.
 * Ejecutar 1 sola vez tras el despliegue inicial.
 *
 * Uso: php hosting/dev/backfill_embeddings.php [--limit=100] [--dry-run]
 */

if (php_sapi_name() !== 'cli') {
    die("CLI only\n");
}

require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/embedding_client.php';

$opts = getopt('', ['limit::', 'dry-run']);
$limit = isset($opts['limit']) ? (int)$opts['limit'] : 1000;
$dryRun = isset($opts['dry-run']);

$db = db();
$client = new EmbeddingClient();

$stmt = $db->prepare("
    SELECT i.* FROM incidents i
    LEFT JOIN incident_embeddings e ON e.incident_id = i.id
    WHERE i.status IN ('closed', 'resolved')
      AND e.id IS NULL
    ORDER BY i.closed_at DESC
    LIMIT ?
");
$stmt->execute([$limit]);
$incidents = $stmt->fetchAll(PDO::FETCH_ASSOC);

echo "Found " . count($incidents) . " incidents to backfill.\n";

$batchSize = 16;
$processed = 0;

foreach (array_chunk($incidents, $batchSize) as $batch) {
    $texts = array_map(function($inc) {
        return buildIncidentText([
            'summary' => $inc['summary'] ?? $inc['title'] ?? '',
            'verdict' => $inc['llm_verdict'] ?? null,
            'mitre_tactic' => $inc['mitre_tactic'] ?? null,
            'classification' => $inc['blue_team_classification'] ?? null,
            'entities' => json_decode($inc['entities_json'] ?? '[]', true),
        ]);
    }, $batch);

    if ($dryRun) {
        echo "Would embed batch of " . count($texts) . "\n";
        continue;
    }

    $embeddings = $client->embed($texts);

    $db->beginTransaction();
    foreach ($batch as $i => $inc) {
        $stmt = $db->prepare("
            INSERT INTO incident_embeddings
                (incident_id, summary, verdict, severity, mitre_tactic,
                 classification, entities_json, closed_at, embedding_model, embedding_dim)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $inc['id'],
            $texts[$i],
            $inc['llm_verdict'] ?? null,
            $inc['severity'] ?? null,
            $inc['mitre_tactic'] ?? null,
            $inc['blue_team_classification'] ?? null,
            $inc['entities_json'] ?? '[]',
            $inc['closed_at'] ?? $inc['created_at'],
            'bge-small-en-v1.5',
            count($embeddings[$i]),
        ]);
        $embeddingId = (int)$db->lastInsertId();

        $stmt2 = $db->prepare("INSERT INTO incident_embeddings_vec (id, embedding) VALUES (?, ?)");
        $stmt2->execute([$embeddingId, json_encode($embeddings[$i])]);
    }
    $db->commit();

    $processed += count($batch);
    echo "Processed $processed / " . count($incidents) . "\n";
    usleep(500000); // 500ms entre lotes para no saturar el embed-server
}

echo "Done.\n";
```

---

## 13. Métricas y observabilidad

Añadir en `admin.php` → Workers una nueva sección "🧠 RAG":

- Total embeddings indexados
- Tareas `rag_enrich` por estado (last 24h / 7d / 30d)
- Latencia media de búsqueda vectorial
- Hit rate de caché de enrich
- Tareas en cola priority=1 ahora mismo
- Tamaño en disco de `incident_embeddings_vec`
- Top 10 entidades más consultadas vía `enrich`
- Veredictos del LLM: distribución TP/FP/inconclusive del último mes
- Errores recientes del embed-server

Usar el patrón visual del Dashboard v2 (KPI cards + mini charts CSS) para consistencia.

---

## 14. Seguridad y privacidad

- **API keys** en `X-API-Key` header igual que el resto de endpoints. No exponer en query string.
- **Cloudflare Access** con Service Token para `enrich.php`, `feedback.php`, `rag_search.php` y el embed-server (nuevo subdominio).
- **Rate limiting** estricto: 60 req/min por API key en `enrich`, 20 req/min en `feedback` (los cierres no son tan frecuentes).
- **Validación de input**: tamaño máximo del body 256 KB, número máximo de entidades por petición 100, longitud máxima de cada campo (subject ≤ 500 chars, summary ≤ 4000 chars).
- **Sanitización del output del LLM** antes de almacenar: el LLM puede devolver HTML/JS si se le pide MITRE en formato libre. Usar `htmlspecialchars` o `sanitizeReportHtml()` ya existente.
- **Aislamiento del embed-server**: solo escucha en `127.0.0.1` localmente; el túnel Cloudflare es el único acceso externo, protegido por Zero Trust.
- **Logs**: incluir `request_id` en cada respuesta para trazabilidad. Registrar entidades enriquecidas en `enrich_log` (nueva tabla opcional) con TTL 90 días para auditoría.
- **No persistir contenido sensible**: si un campo `notes` del feedback contiene PII (nombres de empleados, números de cuenta), considerar campo opcional `redact=true` que aplique reglas de redacción antes del embedding.

---

## 15. Testing recomendado

1. **Unit tests del cliente de embeddings** (Python y PHP): mock del endpoint, verificar parseo de respuestas OpenAI-format.
2. **Integration test**: levantar embed-server local, llamar `embed("test")`, verificar dim correcta.
3. **Test de búsqueda vectorial**: insertar 100 incidentes ficticios, hacer queries con variantes lingüísticas, verificar que los relevantes salen en top-5.
4. **Test de cola con prioridades**: encolar 10 tareas mezcladas (priority 1, 5, 9), verificar que el worker reclama priority 1 primero.
5. **Test de KQL**: en Sentinel, crear una hunting query de prueba contra `enrich.php` con datos sintéticos, verificar latencia <2s y respuesta correcta.
6. **Test de feedback loop**: cerrar un incidente sintético, verificar que aparece en `incident_embeddings`, lanzar inmediatamente un enrich con entidad similar, verificar que aparece como "similar case".
7. **Test de saturación**: 200 peticiones simultáneas a `enrich`, verificar que devuelve 429 cuando corresponde y que las legítimas siguen funcionando.

---

## 16. Roadmap futuro (post-implementación inicial)

Fuera del alcance de esta primera fase, pero conviene tenerlo en mente para no cerrar puertas:

- **Reranking** con un cross-encoder pequeño tras el KNN inicial (mejora calidad de top-3 a costa de ~50ms más).
- **Embeddings híbridos** (denso + BM25) para queries con términos muy específicos (CVE IDs, hashes exactos).
- **Multi-tenant**: si se quisiera dar OrinSec a varios clientes, segmentar `incident_embeddings` por `tenant_id`.
- **Re-embedding programado**: si se cambia el modelo de embeddings, script para re-generar todos los vectores.
- **API pública para integraciones distintas a Sentinel**: Splunk, Elastic, Wazuh, Crowdstrike pueden todos llamar a `enrich.php` igual que KQL.
- **Endpoint `/api/v1/explain.php`**: dado un `task_id` completado, devolver explicación detallada de por qué los casos similares se eligieron (similitud por entidad, por subject, por contexto…). Útil para debugging y trust del analista.

---

## Apéndice A — Ejemplo completo de respuesta de `/enrich`

```json
{
  "request_id": "req_a3f9c2e1",
  "results": [
    {
      "entity_index": 0,
      "status": "completed",
      "task_id": null,
      "verdict": "likely_false_positive",
      "score": 0.87,
      "confidence": "high",
      "similar_cases": [
        {
          "incident_id": 234,
          "similarity": 0.91,
          "summary": "[FP] Backup nocturno Veeam en SRV-BACKUP-01, falso positivo recurrente",
          "verdict": "FP",
          "closed_at": "2026-04-12T03:14:00Z"
        },
        {
          "incident_id": 198,
          "similarity": 0.88,
          "summary": "[FP] PowerShell ejecutado por SYSTEM durante ventana de mantenimiento",
          "verdict": "FP",
          "closed_at": "2026-03-28T02:45:00Z"
        },
        {
          "incident_id": 156,
          "similarity": 0.84,
          "summary": "[FP] Job de Veeam con script remoto, autorizado por infra",
          "verdict": "FP",
          "closed_at": "2026-03-15T03:02:00Z"
        }
      ],
      "recommendation": "Patrón consistente con job de backup nocturno de Veeam. 14 casos previos cerrados como FP en los últimos 6 meses, siempre en franja 02:00-04:00. Confirmar con equipo de infraestructura antes de escalar.",
      "mitre_tactic": null,
      "mitre_technique": null,
      "kql_hunting": null
    }
  ],
  "from_cache": [],
  "queued": [],
  "rate_limit": {
    "remaining": 59,
    "reset_at": "2026-05-03T11:00:00Z"
  }
}
```

---

## Apéndice B — Checklist de implementación

- [ ] Migración SQL: tabla `incident_embeddings`
- [ ] Migración SQL: tabla virtual `incident_embeddings_vec`
- [ ] Migración SQL: columnas `priority` y `parent_task_id` en `tasks`
- [ ] Migración SQL: tabla `enrich_cache`
- [ ] Instalación de `sqlite-vec` en hosting
- [ ] Descarga y conversión de modelo embeddings GGUF
- [ ] Servicio systemd `orinsec-embeddings.service`
- [ ] Cloudflare Tunnel para `embed-orin.cyberintelligence.dev`
- [ ] Cloudflare Access policy en el nuevo subdominio
- [ ] `hosting/includes/embedding_client.php`
- [ ] `hosting/includes/rag.php` con `searchSimilarIncidents()`, `buildEntityText()`, `computeEnrichCacheKey()`
- [ ] `hosting/api/v1/enrich.php`
- [ ] `hosting/api/v1/feedback.php`
- [ ] `hosting/api/v1/rag_search.php`
- [ ] Whitelist en `hosting/api/v1/.htaccess`
- [ ] `worker/utils/embeddings.py`
- [ ] `worker/tasks/rag_enrich.py`
- [ ] Registro en `TASK_REGISTRY` de `worker.py`
- [ ] Lógica de prioridades en `claim` de `tasks.php`
- [ ] Lógica de batching en `worker.py`
- [ ] Script de backfill `hosting/dev/backfill_embeddings.php`
- [ ] Watchlist `OrinSecCredentials` en Sentinel
- [ ] Automation rules con queries KQL del § 8
- [ ] Sección "🧠 RAG" en admin.php
- [ ] Tests unitarios e integración
- [ ] Documentación de operación (cómo añadir más fuentes que llamen a `/enrich`)

---

**Fin del documento.**
