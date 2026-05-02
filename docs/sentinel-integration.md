# OrinSec — Integración con Microsoft Sentinel / Defender XDR

Este documento describe cómo conectar OrinSec RAG con Microsoft Sentinel mediante KQL `evaluate http_request`.

---

## 1. Prerrequisitos

- OrinSec v0.13.0+ con RAG Fase 2 operativo
- Túnel Cloudflare configurado (`embed-orin.cyberintelligence.dev`)
- API key válida de OrinSec
- Sentinel con acceso a `evaluate http_request` (preview en algunas regiones)

---

## 2. Watchlist de credenciales

Crea un watchlist en Sentinel llamado `OrinSecCredentials` con columnas `Name` y `Value`:

| Name | Value |
|---|---|
| `api_key` | `c4d50777...` (tu API key de OrinSec) |
| `cf_access_id` | `...` (Cloudflare Service Token Client ID) |
| `cf_access_secret` | `...` (Cloudflare Service Token Client Secret) |

Restringe el RBAC del watchlist solo a analistas SOC autorizados.

---

## 3. Query KQL — Enriquecer IPs sospechosas (modo sync)

```kql
// === OrinSec Enrichment - Suspicious Logins ===
let OrinSecUrl = "https://orin.cyberintelligence.dev/api/v1/enrich.php";
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
| where ResultType != 0
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

---

## 4. Query KQL — Enriquecer hashes en bloque (modo hybrid)

```kql
let OrinSecUrl = "https://orin.cyberintelligence.dev/api/v1/enrich.php";
let OrinSecKey = toscalar(_GetWatchlist("OrinSecCredentials") | where Name == "api_key" | project Value);
//
DeviceFileEvents
| where TimeGenerated > ago(24h)
| where ActionType in ("FileCreated", "FileModified")
| where isnotempty(SHA256)
| summarize Hosts = make_set(DeviceName), FirstSeen = min(TimeGenerated) by SHA256
| where array_length(Hosts) >= 2
| take 20
| summarize Entities = make_list(bag_pack(
    "type", "hash",
    "subject", "SHA256 seen on multiple hosts",
    "value", SHA256,
    "context", bag_pack("host_count", array_length(Hosts), "first_seen", tostring(FirstSeen))
))
| extend Body = bag_pack("mode", "hybrid", "entities", Entities, "options", bag_pack("k", 3, "language", "es"))
| evaluate http_request(OrinSecUrl, dynamic({"Content-Type": "application/json", "X-API-Key": OrinSecKey}), Body)
| mv-expand result = ResponseBody.results
| project Hash = tostring(result.entity_index), Status = tostring(result.status), TaskId = tolong(result.task_id), Verdict = tostring(result.verdict), Recommendation = tostring(result.recommendation)
```

---

## 5. Automation Rule — Feedback al cerrar incidente

Crea una Automation Rule en Sentinel:
- **Trigger**: When incident is created or updated → Status = Closed
- **Action**: Run playbook (Logic App)

El Logic App debe hacer un POST a `https://orin.cyberintelligence.dev/api/v1/rag_feedback.php` con el body del incidente cerrado.

---

## 6. Notas de seguridad

- Nunca incluyas API keys en texto plano en queries KQL compartidas.
- Usa `_GetWatchlist()` con RBAC restringido.
- El header `X-API-Key` se valida en cada request contra la tabla `api_keys`.
- Cloudflare Access headers (`CF-Access-Client-Id/Secret`) se validan en el túnel antes de llegar al hosting.
