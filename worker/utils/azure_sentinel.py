"""Cliente para Microsoft Sentinel / Log Analytics vía Azure CLI device code flow.

No requiere App Registration en Entra ID. Usa el client_id público de Azure CLI
con device code flow delegado. El usuario debe haber ejecutado `az login` en la
Orin previamente (o el script lo solicita).

Limitaciones:
- Token válido ~1h, puede requerir renovación manual con `az login`
- Requiere que el usuario tenga permisos de lectura en el workspace de Sentinel
"""

import json
import logging
import subprocess
from datetime import datetime
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

AZURE_RESOURCE = "https://api.loganalytics.io"


def _run_az(args: list[str]) -> tuple[str, str, int]:
    """Ejecuta un comando de Azure CLI y devuelve (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            ["az"] + args,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except FileNotFoundError:
        logger.error("Azure CLI (az) no está instalado o no está en PATH")
        return "", "Azure CLI no encontrado", 1
    except subprocess.TimeoutExpired:
        return "", "Timeout ejecutando az", 1


def get_access_token() -> Optional[str]:
    """Obtiene un token de acceso para Log Analytics usando Azure CLI."""
    stdout, stderr, rc = _run_az([
        "account", "get-access-token",
        "--resource", AZURE_RESOURCE,
        "--query", "accessToken",
        "-o", "tsv",
    ])
    if rc != 0 or not stdout:
        logger.warning("No se pudo obtener token Azure: %s", stderr or stdout)
        return None
    return stdout


def check_login_status() -> dict[str, Any]:
    """Verifica si hay una sesión activa de Azure CLI."""
    stdout, stderr, rc = _run_az(["account", "show", "-o", "json"])
    if rc != 0:
        return {"logged_in": False, "error": stderr or "No hay sesión activa"}
    try:
        data = json.loads(stdout)
        return {
            "logged_in": True,
            "tenant_id": data.get("tenantId"),
            "subscription_id": data.get("id"),
            "subscription_name": data.get("name"),
            "user": data.get("user", {}).get("name"),
        }
    except json.JSONDecodeError:
        return {"logged_in": False, "error": "Respuesta inválida de az"}


def query_sentinel(workspace_id: str, kql_query: str, token: Optional[str] = None) -> dict[str, Any]:
    """Ejecuta una query KQL contra un workspace de Log Analytics.

    Args:
        workspace_id: GUID del workspace de Sentinel/Log Analytics
        kql_query: Query en lenguaje KQL
        token: Token de acceso (si es None, se intenta obtener automáticamente)

    Returns:
        Dict con 'success', 'tables', 'rows', 'error'
    """
    if token is None:
        token = get_access_token()
    if not token:
        return {
            "success": False,
            "error": "No hay token válido. Ejecuta 'az login' en la Orin y vuelve a intentarlo.",
        }

    url = f"{AZURE_RESOURCE}/v1/workspaces/{workspace_id}/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {"query": kql_query}

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=60)
        if resp.status_code == 401:
            return {
                "success": False,
                "error": "Token expirado o inválido. Ejecuta 'az login' en la Orin.",
            }
        if resp.status_code == 403:
            return {
                "success": False,
                "error": "Sin permisos para consultar este workspace. Verifica que tu usuario tenga acceso de lectura.",
            }
        if resp.status_code == 404:
            return {
                "success": False,
                "error": f"Workspace {workspace_id} no encontrado.",
            }
        resp.raise_for_status()
        data = resp.json()

        tables = data.get("tables", [])
        rows: list[dict] = []
        for table in tables:
            cols = [c.get("name") for c in table.get("columns", [])]
            for raw_row in table.get("rows", []):
                row = {cols[i]: raw_row[i] for i in range(len(cols)) if i < len(raw_row)}
                rows.append(row)

        return {
            "success": True,
            "tables": tables,
            "rows": rows,
            "row_count": len(rows),
        }

    except requests.exceptions.Timeout:
        return {"success": False, "error": "Timeout consultando Sentinel (>60s)"}
    except requests.exceptions.RequestException as exc:
        logger.error("Error consultando Sentinel: %s", exc)
        return {"success": False, "error": f"Error de red: {exc}"}


def fetch_recent_incidents(workspace_id: str, days: int = 7, token: Optional[str] = None) -> dict[str, Any]:
    """Obtiene incidentes recientes de Sentinel con la query KQL estándar."""
    kql = f"""SecurityIncident
| where CreatedTime > ago({days}d)
| project IncidentNumber, Title, Description, Severity, Status, CreatedTime, AlertIds, Entities
| extend Entities = parse_json(Entities)
| order by CreatedTime desc"""
    return query_sentinel(workspace_id, kql, token)


def generate_hunting_kql(ioc_value: str, ioc_type: str) -> str:
    """Genera una query KQL de hunting para un IOC específico."""
    if ioc_type == "ip":
        return f"""let malicious_ip = "{ioc_value}";
DeviceNetworkEvents
| where RemoteIP == malicious_ip or LocalIP == malicious_ip
| union (SigninLogs | where IPAddress == malicious_ip)
| union (OfficeActivity | where ClientIP == malicious_ip)
| summarize count() by SourceTable=Type, Account, DeviceName, TimeGenerated
| order by TimeGenerated desc"""
    elif ioc_type == "domain":
        return f"""let malicious_domain = "{ioc_value}";
DeviceNetworkEvents
| where RemoteUrl contains malicious_domain
| union (EmailEvents | where SenderFromDomain == malicious_domain or RecipientDomain contains malicious_domain)
| union (DnsEvents | where DomainName contains malicious_domain)
| summarize count() by SourceTable=Type, Account, DeviceName, TimeGenerated
| order by TimeGenerated desc"""
    elif ioc_type == "hash":
        return f"""let malicious_hash = "{ioc_value}";
DeviceFileEvents
| where MD5 == malicious_hash or SHA1 == malicious_hash or SHA256 == malicious_hash
| union (EmailAttachmentInfo | where FileHash == malicious_hash)
| summarize count() by SourceTable=Type, Account, DeviceName, TimeGenerated
| order by TimeGenerated desc"""
    elif ioc_type == "url":
        return f"""let malicious_url = "{ioc_value}";
DeviceNetworkEvents
| where RemoteUrl == malicious_url
| union (EmailEvents | where UrlLocation == malicious_url)
| summarize count() by SourceTable=Type, Account, DeviceName, TimeGenerated
| order by TimeGenerated desc"""
    else:
        return f"""let ioc = "{ioc_value}";
search ioc
| summarize count() by Type, TimeGenerated
| order by TimeGenerated desc"""


def generate_entity_hunting_kql(entity_value: str, entity_type: str) -> str:
    """Genera KQL para investigar una entidad (usuario, device, etc.)."""
    if entity_type == "user":
        return f"""let target_user = "{entity_value}";
SigninLogs
| where UserPrincipalName == target_user
| union (AuditLogs | where InitiatedBy.user.userPrincipalName == target_user or TargetResources contains target_user)
| union (OfficeActivity | where UserId == target_user)
| summarize count() by SourceTable=Type, OperationName, Result, TimeGenerated
| order by TimeGenerated desc"""
    elif entity_type == "device":
        return f"""let target_device = "{entity_value}";
DeviceInfo
| where DeviceName == target_device
| union (DeviceNetworkEvents | where DeviceName == target_device)
| union (DeviceProcessEvents | where DeviceName == target_device)
| summarize count() by SourceTable=Type, ActionType, TimeGenerated
| order by TimeGenerated desc"""
    elif entity_type == "ip":
        return generate_hunting_kql(entity_value, "ip")
    else:
        return f"""search "{entity_value}"
| summarize count() by Type, TimeGenerated
| order by TimeGenerated desc"""
