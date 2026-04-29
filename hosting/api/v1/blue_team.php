<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/config.php';
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/functions.php';

session_start();
if (!isLoggedIn()) {
    jsonResponse(['error' => 'No autorizado'], 401);
}

$action = $_GET['action'] ?? '';

switch ($action) {
    case 'list_incidents':
        $limit = min((int)($_GET['limit'] ?? 50), 100);
        $offset = (int)($_GET['offset'] ?? 0);
        $status = $_GET['status'] ?? '';

        $where = [];
        $params = [];
        if ($status !== '' && in_array($status, ['open', 'closed', 'investigating'], true)) {
            $where[] = "status = ?";
            $params[] = $status;
        }

        $sqlWhere = $where ? 'WHERE ' . implode(' AND ', $where) : '';

        $incidents = Database::fetchAll(
            "SELECT * FROM incidents {$sqlWhere} ORDER BY created_time DESC LIMIT ? OFFSET ?",
            array_merge($params, [$limit, $offset])
        );

        $total = Database::fetchOne(
            "SELECT COUNT(*) as total FROM incidents {$sqlWhere}",
            $params
        )['total'] ?? 0;

        jsonResponse(['success' => true, 'incidents' => $incidents, 'total' => (int)$total]);
        break;

    case 'get_incident':
        $id = $_GET['id'] ?? '';
        if (!$id) {
            jsonResponse(['error' => 'id requerido'], 400);
        }
        $incident = Database::fetchOne("SELECT * FROM incidents WHERE incident_id = ?", [$id]);
        if (!$incident) {
            jsonResponse(['error' => 'Incidente no encontrado'], 404);
        }
        $entities = Database::fetchAll(
            "SELECT e.*, ie.role, ie.risk_contribution 
             FROM entities e 
             JOIN incident_entities ie ON e.entity_value = ie.entity_value 
             WHERE ie.incident_id = ?",
            [$id]
        );
        $iocs = Database::fetchAll(
            "SELECT i.*, ii.context 
             FROM iocs i 
             JOIN ioc_incidents ii ON i.ioc_value = ii.ioc_value 
             WHERE ii.incident_id = ?",
            [$id]
        );
        jsonResponse(['success' => true, 'incident' => $incident, 'entities' => $entities, 'iocs' => $iocs]);
        break;

    case 'list_entities':
        $type = $_GET['type'] ?? '';
        $where = [];
        $params = [];
        if ($type !== '' && in_array($type, ['user','device','ip','application','domain','url','hash'], true)) {
            $where[] = "entity_type = ?";
            $params[] = $type;
        }
        $sqlWhere = $where ? 'WHERE ' . implode(' AND ', $where) : '';
        $entities = Database::fetchAll(
            "SELECT * FROM entities {$sqlWhere} ORDER BY current_risk_score DESC, total_incidents DESC LIMIT 100",
            $params
        );
        jsonResponse(['success' => true, 'entities' => $entities]);
        break;

    case 'update_incident_status':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            jsonResponse(['error' => 'Método no permitido'], 405);
        }
        $data = getJsonInput();
        $id = $data['incident_id'] ?? '';
        $status = $data['status'] ?? '';
        if (!$id || !in_array($status, ['open', 'closed', 'investigating'], true)) {
            jsonResponse(['error' => 'Datos inválidos'], 400);
        }
        Database::update('incidents', ['status' => $status], 'incident_id = ?', [$id]);
        jsonResponse(['success' => true]);
        break;

    default:
        jsonResponse(['error' => 'Acción no válida'], 400);
}
