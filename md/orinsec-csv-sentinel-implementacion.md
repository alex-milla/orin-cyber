# OrinSec — Implementación: Flujo CSV Sentinel → Blue Team (usuarios ofuscados)

**Versión:** 1.0
**Fecha:** 2026-05-03
**Contexto:** El plugin `evaluate http_request` de KQL está desactivado en el tenant de Sentinel.
Esta implementación cubre el flujo alternativo: exportar datos desde Sentinel como CSV
y subirlos manualmente a OrinSec para análisis con el RAG y el LLM local.

---

## 0. Por qué este flujo y qué resuelve

### El problema
`evaluate http_request` (el mecanismo nativo de KQL para llamar APIs externas) está
**desactivado** en el workspace de Log Analytics del cliente. Sin él, KQL no puede
enviar datos directamente a la API de OrinSec en tiempo real.

### La solución adoptada
Flujo manual de tres pasos:

```
Sentinel (KQL) → Exportar CSV → Subir a OrinSec (blue_team.php)
                                        ↓
                                  Worker Orin Nano
                                  (incident_analysis)
                                        ↓
                                  RAG + LLM local
                                        ↓
                                  Resultado enriquecido
```

### Detección validada
Se ha validado en producción la detección de **"Login desde fuera de España"** sobre
`SigninLogs`. El tenant tiene todos los usuarios en `["ES"]`, por lo que el impossible
travel no aplica. Cualquier login con `Country != "ES"` es relevante.

Casos reales detectados: `IT/Milano`, `GB/London`, `GB/Dundee`, `AD/Andorra La Vella`.

### Privacidad — usuarios ofuscados
Los UPNs (correos corporativos) se ofuscan con `hash_sha256()` de KQL antes de exportar.
El CSV **nunca contiene nombres de usuario en claro**. Solo contiene:
- `UserHash`: hash numérico SHA256 del UPN (permite correlación sin exponer el dato)
- `UserDomain`: dominio del UPN (ej: `empresa.com`) sin el usuario

---

## 1. La KQL — estado final validado

Esta es la query que funciona en el tenant del cliente. Está validada y ejecuta sin errores.

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City    = tostring(LocationDetails.city)
| where Country != "ES" and isnotempty(Country)
| summarize
    Countries  = tostring(make_set(Country, 10)),
    Cities     = tostring(make_set(City, 10)),
    IPs        = tostring(make_set(IPAddress, 10)),
    Apps       = tostring(make_set(AppDisplayName, 10)),
    FirstSeen  = min(TimeGenerated),
    LastSeen   = max(TimeGenerated),
    LoginCount = count()
    by UserPrincipalName
| extend
    Subject    = "Login desde país no habitual (fuera de ES)",
    EntityType = "user",
    Severity   = "high",
    UserHash   = tostring(hash_sha256(UserPrincipalName)),
    UserDomain = tostring(split(UserPrincipalName, "@")[1])
| project
    UserHash,
    UserDomain,
    Subject,
    EntityType,
    Severity,
    Countries,
    Cities,
    IPs,
    Apps,
    FirstSeen,
    LastSeen,
    LoginCount
| order by LoginCount desc
```

### Notas críticas sobre esta KQL

**Por qué no usar `let` para variables:** el workspace rechaza variables `let` de tipo
`timespan` usadas dentro de `ago()`. Error: *"Failed to resolve scalar expression"*.
Los valores se ponen directamente en la query.

**Por qué no usar `tohex(hash_sha256(...))`:** KQL en este workspace lanza error
*"tohex(): argument #1 expected to be an integer expression"* porque `hash_sha256()`
devuelve `long`, no bytes. Se usa `tostring(hash_sha256(...))` que devuelve un entero
largo (positivo o negativo) como string. Es único y consistente para correlación.

**Ejemplo de `UserHash` resultante:**
```
ana.garcia@empresa.com → "-4521034789234567890"
```

**Cómo desofuscar si se necesita investigar:** ejecutar en Sentinel:
```kql
SigninLogs
| where UserPrincipalName == "usuario.sospechoso@empresa.com"
| extend UserHash = tostring(hash_sha256(UserPrincipalName))
| project UserHash, UserPrincipalName
| take 1
```

### Columnas del CSV exportado

| Columna | Tipo | Ejemplo | Descripción |
|---|---|---|---|
| `UserHash` | string | `-4521034789234567890` | SHA256 del UPN como long |
| `UserDomain` | string | `empresa.com` | Dominio del UPN |
| `Subject` | string | `Login desde país no habitual (fuera de ES)` | Descripción del patrón |
| `EntityType` | string | `user` | Tipo de entidad OrinSec |
| `Severity` | string | `high` | Severidad |
| `Countries` | string | `["IT","GB"]` | JSON array como string |
| `Cities` | string | `["Milano","London"]` | JSON array como string |
| `IPs` | string | `["216.128.11.80","78.32.250.115"]` | JSON array como string |
| `Apps` | string | `["Windows Sign In","One Outlook Web"]` | JSON array como string |
| `FirstSeen` | datetime | `2026-04-15T08:23:11Z` | Primer login detectado |
| `LastSeen` | datetime | `2026-05-01T14:45:22Z` | Último login detectado |
| `LoginCount` | int | `4` | Total de logins fuera de ES |

---

## 2. Qué hay que cambiar en OrinSec

El flujo de subida de CSV existe (`blue_team.php`) y el worker ya procesa CSV
(`incident_analysis.py`). Sin embargo, **el CSV de Sentinel tiene una estructura
diferente** a lo que el sistema espera actualmente.

### 2.1 El problema actual

El sistema actual hace esto con el CSV subido:

1. **`blue_team.php`** → `_extractAndStoreEntities()`: extrae entidades por **regex**
   sobre todo el texto del CSV (IPs, emails, hashes, dominios).
2. **`incident_analysis.py`** → `_extract_entities()`: misma lógica de regex sobre
   todas las filas.

El CSV de Sentinel con usuarios ofuscados **no tiene emails** (el UPN ya no aparece
en claro), así que:
- El regex de email no extrae nada útil (el UserHash no es un email).
- El campo `UserHash` no se reconoce como entidad de tipo `user`.
- El campo `Countries`/`IPs` son JSON arrays como string — el regex de IPs puede
  extraerlas del string, pero sin contexto de qué usuario las generó.
- El LLM recibe el CSV como texto plano sin saber que `UserHash` representa un usuario.

### 2.2 Lo que hay que implementar

Tres cambios concretos y bien delimitados:

---

### Cambio 1 — `blue_team.php`: detectar y manejar CSV de Sentinel ofuscado

**Archivo:** `hosting/blue_team.php`
**Función a modificar:** `_extractAndStoreEntities()`
**Función nueva a añadir:** `_isSentinelObfuscatedCsv()`

#### Lógica

Antes de hacer la extracción por regex, detectar si el CSV viene del flujo Sentinel
ofuscado (tiene columnas `UserHash`, `UserDomain`, `EntityType`). Si es así, procesar
columna a columna en lugar de por regex.

```php
/**
 * Detecta si un CSV tiene la estructura del export Sentinel ofuscado.
 * Criterio: tiene cabeceras UserHash, UserDomain, EntityType.
 */
function _isSentinelObfuscatedCsv(array $headers): bool {
    $required = ['UserHash', 'UserDomain', 'EntityType'];
    $headersLower = array_map('strtolower', $headers);
    foreach ($required as $col) {
        if (!in_array(strtolower($col), $headersLower, true)) {
            return false;
        }
    }
    return true;
}

/**
 * Procesa CSV de Sentinel ofuscado extrayendo entidades por columna,
 * no por regex sobre texto plano.
 */
function _extractSentinelObfuscatedEntities(string $incidentId, array $rows, array $headers): void {
    // Normalizar nombres de cabecera a lowercase para búsqueda insensible
    $headerMap = [];
    foreach ($headers as $i => $h) {
        $headerMap[strtolower(trim($h))] = $i;
    }

    foreach ($rows as $row) {
        // Mapear columnas
        $userHash   = trim($row[($headerMap['userhash']   ?? -1)] ?? '');
        $userDomain = trim($row[($headerMap['userdomain'] ?? -1)] ?? '');
        $ipsRaw     = trim($row[($headerMap['ips']        ?? -1)] ?? '');
        $countries  = trim($row[($headerMap['countries']  ?? -1)] ?? '');
        $cities     = trim($row[($headerMap['cities']     ?? -1)] ?? '');
        $apps       = trim($row[($headerMap['apps']       ?? -1)] ?? '');
        $severity   = trim($row[($headerMap['severity']   ?? -1)] ?? 'high');
        $subject    = trim($row[($headerMap['subject']    ?? -1)] ?? '');

        // 1. Entidad usuario ofuscado (UserHash como identificador)
        if ($userHash) {
            $entityValue = $userDomain
                ? "hash:{$userHash}@{$userDomain}"
                : "hash:{$userHash}";

            try {
                Database::query(
                    "INSERT OR IGNORE INTO entities (entity_type, entity_value, notes) VALUES (?, ?, ?)",
                    ['user_obfuscated', $entityValue, "Ofuscado desde Sentinel. Dominio: {$userDomain}"]
                );
                Database::query(
                    "INSERT OR IGNORE INTO incident_entities (incident_id, entity_value, role) VALUES (?, ?, ?)",
                    [$incidentId, $entityValue, 'subject']
                );
            } catch (Exception $e) { /* ignorar duplicados */ }
        }

        // 2. IPs — extraer del JSON array string: ["1.2.3.4","5.6.7.8"]
        $ips = _parseJsonArrayString($ipsRaw);
        foreach ($ips as $ip) {
            $ip = trim($ip, '"\'');
            if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;
            try {
                Database::query(
                    "INSERT OR IGNORE INTO entities (entity_type, entity_value) VALUES (?, ?)",
                    ['ip', $ip]
                );
                Database::query(
                    "INSERT OR IGNORE INTO incident_entities (incident_id, entity_value, role) VALUES (?, ?, ?)",
                    [$incidentId, $ip, 'related']
                );
            } catch (Exception $e) { /* ignorar duplicados */ }
        }
    }
}

/**
 * Parsea un JSON array en formato string de KQL: ["ES","IT"] o ["1.2.3.4"]
 * Devuelve array de strings limpios.
 */
function _parseJsonArrayString(string $raw): array {
    if (empty($raw)) return [];
    // Intentar JSON decode
    $decoded = json_decode($raw, true);
    if (is_array($decoded)) {
        return array_filter(array_map('trim', $decoded));
    }
    // Fallback: limpiar brackets y dividir por coma
    $raw = trim($raw, '[]"\'');
    return array_filter(array_map('trim', explode(',', $raw)));
}
```

#### Modificación en `_extractAndStoreEntities()`

```php
function _extractAndStoreEntities(string $incidentId, string $csvData): void {
    $lines = explode("\n", $csvData);
    if (count($lines) < 2) return;

    $headers = str_getcsv($lines[0]);

    // ── NUEVO: detectar CSV de Sentinel ofuscado ──────────────────
    if (_isSentinelObfuscatedCsv($headers)) {
        $rows = [];
        for ($i = 1; $i < count($lines); $i++) {
            $line = trim($lines[$i]);
            if (empty($line)) continue;
            $rows[] = str_getcsv($line);
        }
        _extractSentinelObfuscatedEntities($incidentId, $rows, $headers);
        return; // no continuar con la lógica de regex
    }
    // ── FIN NUEVO ─────────────────────────────────────────────────

    // Lógica original de regex (para otros tipos de CSV)
    $allText = implode(' ', $lines);
    // ... (código existente sin cambios)
}
```

---

### Cambio 2 — `incident_analysis.py`: reconocer columnas del CSV ofuscado

**Archivo:** `worker/tasks/incident_analysis.py`
**Función a modificar:** `execute()`
**Función nueva a añadir:** `_is_sentinel_obfuscated_csv()`, `_parse_sentinel_obfuscated_rows()`

#### Lógica

El worker recibe `csv_data` como string. Si detecta que es el CSV ofuscado de Sentinel,
construye el contexto para el LLM de forma estructurada (no por regex), incluyendo la
información de países, IPs y dominio de usuario de forma legible.

```python
def _is_sentinel_obfuscated_csv(rows: list[dict]) -> bool:
    """Detecta si el CSV tiene la estructura del export Sentinel ofuscado."""
    if not rows:
        return False
    required = {'userhash', 'userdomain', 'entitytype'}
    headers_lower = {k.lower() for k in rows[0].keys()}
    return required.issubset(headers_lower)


def _parse_sentinel_obfuscated_rows(rows: list[dict]) -> list[dict]:
    """
    Normaliza las filas del CSV ofuscado de Sentinel.
    Devuelve lista de dicts con claves normalizadas.
    """
    import json

    normalized = []
    for row in rows:
        # Normalizar claves a lowercase
        r = {k.lower(): v for k, v in row.items()}

        def parse_json_array(val: str) -> list:
            val = val.strip()
            if not val:
                return []
            try:
                result = json.loads(val)
                return result if isinstance(result, list) else [val]
            except Exception:
                return [x.strip().strip('"\'') for x in val.strip('[]').split(',') if x.strip()]

        normalized.append({
            'user_hash':    r.get('userhash', ''),
            'user_domain':  r.get('userdomain', ''),
            'subject':      r.get('subject', ''),
            'entity_type':  r.get('entitytype', 'user'),
            'severity':     r.get('severity', 'high'),
            'countries':    parse_json_array(r.get('countries', '')),
            'cities':       parse_json_array(r.get('cities', '')),
            'ips':          parse_json_array(r.get('ips', '')),
            'apps':         parse_json_array(r.get('apps', '')),
            'first_seen':   r.get('firstseen', ''),
            'last_seen':    r.get('lastseen', ''),
            'login_count':  r.get('logincount', '0'),
        })
    return normalized


def _build_sentinel_obfuscated_context(
    incident_id: str,
    title: str,
    severity: str,
    normalized_rows: list[dict],
) -> str:
    """
    Construye el prompt para el LLM con datos del CSV Sentinel ofuscado.
    Los usuarios están identificados por hash, no por nombre.
    """
    lines = [
        f"Incidente: {incident_id}",
        f"Título: {title}",
        f"Severidad: {severity}",
        f"Tipo de análisis: Logins desde países no habituales (fuera de ES)",
        f"Registros analizados: {len(normalized_rows)}",
        "",
        "NOTA IMPORTANTE: Los usuarios están ofuscados por privacidad.",
        "El campo UserHash es el identificador único del usuario (SHA256 del UPN).",
        "No intentes deducir el nombre del usuario.",
        "",
        "=== REGISTROS ===",
    ]

    for i, row in enumerate(normalized_rows):
        lines.append(f"\nUsuario {i+1}:")
        lines.append(f"  Hash:          {row['user_hash']}")
        lines.append(f"  Dominio:       {row['user_domain']}")
        lines.append(f"  Países:        {', '.join(row['countries'])}")
        lines.append(f"  Ciudades:      {', '.join(row['cities'])}")
        lines.append(f"  IPs:           {', '.join(row['ips'])}")
        lines.append(f"  Apps usadas:   {', '.join(row['apps'])}")
        lines.append(f"  Primer login:  {row['first_seen']}")
        lines.append(f"  Último login:  {row['last_seen']}")
        lines.append(f"  Total logins:  {row['login_count']}")

    lines.append("")
    lines.append("=== ANÁLISIS SOLICITADO ===")
    lines.append(
        "Para cada usuario, evalúa si el login desde un país no habitual es sospechoso "
        "o puede ser legítimo (viaje de trabajo, VPN, Andorra como país fronterizo, etc.). "
        "Considera el país, las IPs, las apps usadas y la frecuencia."
    )

    return "\n".join(lines)
```

#### Modificación en `execute()`

Añadir detección al inicio del método, antes de la extracción de entidades por regex:

```python
def execute(self, input_data: dict[str, Any]) -> dict[str, str]:
    incident_id = input_data.get("incident_id", "UNKNOWN")
    title       = input_data.get("title", "Sin título")
    severity    = input_data.get("severity", "Medium")
    csv_data    = input_data.get("csv_data", "")

    if not csv_data:
        return {"result_html": "<p>Error: No CSV.</p>", "result_text": "Error: No CSV."}

    rows = _parse_csv(csv_data)
    if not rows:
        return {"result_html": "<p>Error: CSV vacío.</p>", "result_text": "Error: CSV vacío."}

    # ── NUEVO: detectar CSV de Sentinel ofuscado ──────────────────────
    if _is_sentinel_obfuscated_csv(rows):
        logger.info("CSV detectado como Sentinel ofuscado para incidente %s", incident_id)
        normalized = _parse_sentinel_obfuscated_rows(rows)
        context = _build_sentinel_obfuscated_context(incident_id, title, severity, normalized)

        # Extraer IPs para OSINT (las IPs sí están en claro)
        all_ips = []
        for r in normalized:
            all_ips.extend(r['ips'])
        all_ips = list(set(all_ips))[:10]

        osint_data = {}
        for ip in all_ips:
            osint_data[f"ip:{ip}"] = enrich_ioc(ip, "ip", self.config_path)

        if osint_data:
            context += "\n\n=== OSINT IPs ===\n"
            for key, data in osint_data.items():
                context += f"{key}: {json.dumps(data, ensure_ascii=False)}\n"

        # Llamar al LLM con el contexto estructurado
        llm_analysis = None
        try:
            llm_analysis = self.llm.chat_json(
                system_prompt=self.prompt_template,
                user_prompt=context,
            )
        except Exception as exc:
            logger.warning("LLM call failed for %s: %s", incident_id, exc)

        # Generar KQL de hunting para cada IP detectada
        hunting_queries = []
        for ip in all_ips[:5]:
            kql = generate_hunting_kql(ip, "ip")
            hunting_queries.append({"target": ip, "type": "ip", "kql": kql})

        # Generar informe con los datos normalizados
        return self._build_sentinel_report(
            incident_id, title, severity,
            normalized, llm_analysis, hunting_queries, osint_data
        )
    # ── FIN NUEVO ────────────────────────────────────────────────────

    # Flujo original para otros tipos de CSV (sin cambios)
    # ...
```

#### Nuevo método `_build_sentinel_report()`

Método de instancia en `IncidentAnalysisTask` para generar el HTML del informe
con la estructura del CSV ofuscado:

```python
def _build_sentinel_report(
    self,
    incident_id: str,
    title: str,
    severity: str,
    normalized_rows: list[dict],
    llm_analysis: dict | None,
    hunting_queries: list[dict],
    osint_data: dict,
) -> dict[str, str]:
    """Genera el informe HTML para CSV de Sentinel ofuscado."""

    verdict      = llm_analysis.get("veredicto", "NEEDS REVIEW") if llm_analysis else "NEEDS REVIEW"
    summary      = llm_analysis.get("resumen", "")               if llm_analysis else ""
    mitre        = llm_analysis.get("mitre_tecnicas", [])         if llm_analysis else []
    recomendaciones = llm_analysis.get("recomendaciones", [])     if llm_analysis else []

    # Construir tabla de usuarios
    users_rows_html = ""
    for row in normalized_rows:
        countries_str = ", ".join(row['countries'])
        ips_str       = ", ".join(row['ips'][:3])
        users_rows_html += f"""
        <tr>
            <td><code style="font-size:.75rem;">{row['user_hash'][:20]}…</code><br>
                <small style="color:var(--text-muted);">{row['user_domain']}</small></td>
            <td>{countries_str}</td>
            <td style="font-size:.8rem;">{ips_str}</td>
            <td>{row['login_count']}</td>
            <td><small>{row['first_seen'][:10] if row['first_seen'] else '—'}</small></td>
        </tr>"""

    # KQL de hunting
    kql_sections = ""
    for q in hunting_queries:
        kql_sections += f"""
        <div style="margin-bottom:1rem;">
            <strong>IP: {q['target']}</strong>
            <pre style="background:var(--surface-2);padding:.75rem;border-radius:var(--radius-sm);
                        font-size:.8rem;overflow-x:auto;margin:.5rem 0;">{q['kql']}</pre>
        </div>"""

    mitre_html = ""
    for t in (mitre if isinstance(mitre, list) else [mitre]):
        mitre_html += f'<span class="badge" style="margin:.2rem;">{t}</span>'

    rec_html = ""
    for r in (recomendaciones if isinstance(recomendaciones, list) else [recomendaciones]):
        rec_html += f"<li>{r}</li>"

    verdict_color = {
        "MALICIOSO": "severity-critical",
        "SOSPECHOSO": "severity-high",
        "NEEDS REVIEW": "severity-medium",
        "BENIGNO": "severity-low",
    }.get(verdict.upper(), "severity-medium")

    html = f"""
    <div style="font-family:var(--font-mono,monospace);">

    <!-- KPIs -->
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.5rem;">
        <div style="background:var(--surface-2);padding:1rem;border-radius:var(--radius);">
            <div style="font-size:.75rem;color:var(--text-muted);">USUARIOS AFECTADOS</div>
            <div style="font-size:2rem;font-weight:700;">{len(normalized_rows)}</div>
        </div>
        <div style="background:var(--surface-2);padding:1rem;border-radius:var(--radius);">
            <div style="font-size:.75rem;color:var(--text-muted);">PAÍSES DETECTADOS</div>
            <div style="font-size:2rem;font-weight:700;">
                {len(set(c for r in normalized_rows for c in r['countries']))}
            </div>
        </div>
        <div style="background:var(--surface-2);padding:1rem;border-radius:var(--radius);">
            <div style="font-size:.75rem;color:var(--text-muted);">VEREDICTO</div>
            <div><span class="badge {verdict_color}" style="font-size:1rem;">{verdict}</span></div>
        </div>
    </div>

    <!-- Aviso privacidad -->
    <div style="background:var(--surface-2);border-left:3px solid var(--accent);
                padding:.75rem 1rem;border-radius:var(--radius-sm);margin-bottom:1.5rem;
                font-size:.85rem;">
        🔒 <strong>Datos ofuscados:</strong> Los usuarios están identificados por hash SHA256.
        Para desofuscar un caso específico, ejecuta la query de desofuscación en Sentinel.
    </div>

    <!-- Resumen LLM -->
    <h3 style="margin:0 0 .5rem;">Análisis del LLM</h3>
    <p style="margin-bottom:1rem;">{summary or 'Sin análisis disponible.'}</p>

    <!-- MITRE -->
    {f'<div style="margin-bottom:1rem;"><strong>MITRE ATT&amp;CK:</strong><br>{mitre_html}</div>' if mitre_html else ''}

    <!-- Recomendaciones -->
    {f'<h3>Recomendaciones</h3><ul>{rec_html}</ul>' if rec_html else ''}

    <!-- Tabla de usuarios -->
    <h3 style="margin:1.5rem 0 .5rem;">Detalle por usuario</h3>
    <div style="overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;font-size:.85rem;">
            <thead>
                <tr style="background:var(--surface-2);">
                    <th style="padding:.5rem;text-align:left;">Usuario (hash)</th>
                    <th style="padding:.5rem;text-align:left;">Países</th>
                    <th style="padding:.5rem;text-align:left;">IPs</th>
                    <th style="padding:.5rem;text-align:left;">Logins</th>
                    <th style="padding:.5rem;text-align:left;">Primer login</th>
                </tr>
            </thead>
            <tbody>{users_rows_html}</tbody>
        </table>
    </div>

    <!-- KQL Hunting -->
    {f'<h3 style="margin:1.5rem 0 .5rem;">KQL Hunting (por IP)</h3>{kql_sections}' if kql_sections else ''}

    </div>"""

    # Texto plano para result_text
    text_lines = [
        f"Incidente: {incident_id} — {title}",
        f"Veredicto: {verdict}",
        f"Usuarios afectados: {len(normalized_rows)}",
        f"Resumen: {summary}",
        "",
    ]
    for row in normalized_rows:
        text_lines.append(
            f"- hash:{row['user_hash'][:16]}… ({row['user_domain']}) "
            f"→ {', '.join(row['countries'])} | IPs: {', '.join(row['ips'][:3])}"
        )

    return {
        "result_html": html,
        "result_text": "\n".join(text_lines),
    }
```

---

### Cambio 3 — `blue_team.php`: añadir aviso en el formulario de subida

**Archivo:** `hosting/blue_team.php`
**Sección:** el `<form>` de subida de CSV (línea ~201)

Añadir un bloque informativo debajo del `<input type="file">` que explique
al usuario cómo exportar el CSV desde Sentinel y qué KQL usar.

```html
<!-- Añadir DESPUÉS del input de file (línea ~230) -->
<div style="margin-top:.75rem;padding:.75rem 1rem;background:var(--surface-2);
            border-radius:var(--radius-sm);font-size:.83rem;border-left:3px solid var(--accent);">
    <strong>📥 ¿Cómo exportar desde Sentinel?</strong>
    <ol style="margin:.5rem 0 0 1.2rem;padding:0;">
        <li>Ejecuta la KQL de detección en Log Analytics / Sentinel.</li>
        <li>Haz clic en <strong>Export → CSV (all columns)</strong>.</li>
        <li>Sube el archivo aquí.</li>
    </ol>
    <details style="margin-top:.5rem;">
        <summary style="cursor:pointer;color:var(--accent);">Ver KQL de ejemplo (login fuera de ES)</summary>
        <pre style="background:var(--surface);padding:.75rem;border-radius:var(--radius-sm);
                    font-size:.75rem;overflow-x:auto;margin:.5rem 0;">SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City    = tostring(LocationDetails.city)
| where Country != "ES" and isnotempty(Country)
| summarize
    Countries  = tostring(make_set(Country, 10)),
    Cities     = tostring(make_set(City, 10)),
    IPs        = tostring(make_set(IPAddress, 10)),
    Apps       = tostring(make_set(AppDisplayName, 10)),
    FirstSeen  = min(TimeGenerated),
    LastSeen   = max(TimeGenerated),
    LoginCount = count()
    by UserPrincipalName
| extend
    Subject    = "Login desde país no habitual (fuera de ES)",
    EntityType = "user",
    Severity   = "high",
    UserHash   = tostring(hash_sha256(UserPrincipalName)),
    UserDomain = tostring(split(UserPrincipalName, "@")[1])
| project UserHash, UserDomain, Subject, EntityType, Severity,
          Countries, Cities, IPs, Apps, FirstSeen, LastSeen, LoginCount
| order by LoginCount desc</pre>
        <p style="margin:.25rem 0 0;color:var(--text-muted);">
            ⚠️ Los usuarios se exportan <strong>ofuscados</strong> (hash SHA256).
            Para investigar un usuario concreto, usa la query de desofuscación en Sentinel.
        </p>
    </details>
</div>
```

---

## 3. Flujo completo paso a paso (para el usuario final)

```
1. Sentinel → Log Analytics → pegar la KQL → Run
2. Resultados aparecen con UserHash (usuarios ofuscados)
3. Export → CSV (all columns) → descargar fichero
4. OrinSec → Blue Team → formulario de subida
5. Rellenar: ID incidente, título, severidad = High, fuente = Sentinel
6. Seleccionar el CSV descargado
7. Submit → el sistema detecta automáticamente que es CSV Sentinel ofuscado
8. Worker procesa:
   a. Detecta columnas UserHash/UserDomain/EntityType
   b. Extrae IPs en claro → OSINT (VirusTotal, AbuseIPDB)
   c. Construye contexto estructurado para el LLM
   d. LLM analiza: ¿los países/IPs/apps son sospechosos?
   e. Genera KQL de hunting para las IPs detectadas
9. Resultado en pantalla:
   - KPIs: usuarios afectados, países, veredicto
   - Aviso de datos ofuscados
   - Análisis narrativo del LLM
   - Tabla por usuario (hash + dominio + países + IPs + logins)
   - KQL de hunting por IP
10. Si el caso es relevante → cerrar como TP en blue_team → feedback.php → RAG aprende
```

---

## 4. Tabla de archivos a modificar

| Archivo | Tipo de cambio | Funciones afectadas |
|---|---|---|
| `hosting/blue_team.php` | Modificar + Añadir | `_extractAndStoreEntities()`, `_isSentinelObfuscatedCsv()` (nueva), `_extractSentinelObfuscatedEntities()` (nueva), `_parseJsonArrayString()` (nueva), bloque HTML del formulario |
| `worker/tasks/incident_analysis.py` | Modificar + Añadir | `execute()`, `_is_sentinel_obfuscated_csv()` (nueva), `_parse_sentinel_obfuscated_rows()` (nueva), `_build_sentinel_obfuscated_context()` (nueva), `_build_sentinel_report()` (nuevo método de instancia) |

**No se toca:**
- `hosting/api/v1/enrich.php` — no interviene en este flujo
- `hosting/includes/rag.php` — el feedback al RAG ocurre igual que antes al cerrar el incidente
- `worker/tasks/rag_enrich.py` — no interviene
- El resto del worker y del hosting — sin cambios

---

## 5. Consideraciones importantes para el modelo codificador

### 5.1 El campo `entity_type` nuevo: `user_obfuscated`

La tabla `entities` tiene un campo `entity_type` con valores conocidos (`ip`, `domain`,
`user`, `hash`). Se añade `user_obfuscated` para distinguir estos casos.
**Verificar que no hay restricciones CHECK en la tabla** antes de insertar.
Si las hay, añadir `user_obfuscated` a la lista permitida en la migración de `db.php`.

### 5.2 El `UserHash` de KQL es un número, no un hash hexadecimal

`tostring(hash_sha256(upn))` en KQL devuelve un `long` como string tipo `"-4521034789234567890"`.
**No es un SHA256 hexadecimal de 64 chars.** El código PHP e Python no debe intentar
validarlo como hash hex — solo tratarlo como string opaco de identificación.

### 5.3 Los JSON arrays vienen como string de KQL

`Countries`, `Cities`, `IPs`, `Apps` en el CSV son strings con formato `["ES","IT"]`
(el resultado de `tostring(make_set(...))` en KQL). Hay que parsearlos como JSON
antes de usarlos. Ambas funciones (`_parseJsonArrayString` en PHP y
`parse_json_array` en Python) ya lo manejan con fallback a split por coma.

### 5.4 Compatibilidad con CSV existentes (no romper nada)

El cambio en `_extractAndStoreEntities()` y en `execute()` debe ser aditivo:
si el CSV **no** tiene las cabeceras `UserHash/UserDomain/EntityType`, el flujo
original de regex no se toca. La detección actúa solo si las tres cabeceras están
presentes.

### 5.5 El `prompt_template` del LLM es el mismo

Se reutiliza `prompts/incident_analysis.txt` existente. No hace falta un prompt
nuevo — el contexto construido por `_build_sentinel_obfuscated_context()` ya
incluye la instrucción de no intentar desofuscar usuarios y de analizar por
comportamiento (países + IPs + apps).

### 5.6 Sin cambios en la tabla `incidents`

El incidente se crea exactamente igual que antes en `blue_team.php`. Solo cambia
cómo se procesan las entidades internas. El `incident_id`, `title`, `severity`,
`source` y `raw_data` se guardan igual.

---

## 6. Test manual para validar la implementación

Después de aplicar los cambios, verificar con este CSV de prueba
(guardarlo como `test_sentinel_ofuscado.csv`):

```csv
UserHash,UserDomain,Subject,EntityType,Severity,Countries,Cities,IPs,Apps,FirstSeen,LastSeen,LoginCount
-4521034789234567890,empresa.com,Login desde país no habitual (fuera de ES),user,high,["IT"],["Milano"],["216.128.11.80"],["Windows Sign In"],2026-04-15T08:23:11Z,2026-05-01T14:45:22Z,3
-7893421056789012345,empresa.com,Login desde país no habitual (fuera de ES),user,high,["GB","AD"],["London","Andorra La Vella"],["78.32.250.115","85.94.178.3"],["One Outlook Web","Apple Internet Accounts"],2026-04-20T10:11:00Z,2026-05-02T09:30:00Z,4
```

**Resultado esperado:**
1. El sistema detecta automáticamente el CSV como Sentinel ofuscado (sin mensaje de error).
2. Se crean 2 entidades tipo `user_obfuscated` en la tabla `entities`.
3. Se crean entradas en `incident_entities` para las IPs `216.128.11.80`, `78.32.250.115`, `85.94.178.3`.
4. El informe HTML muestra:
   - KPI: 2 usuarios, 3 países (IT, GB, AD), veredicto del LLM.
   - Aviso de datos ofuscados con borde azul.
   - Tabla con los dos usuarios (hash truncado + dominio + países + IPs + logins).
   - KQL de hunting para las IPs.
5. El resultado **no contiene** ningún UPN en claro.
