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
    case 'list':
        $type = $_GET['type'] ?? '';
        $status = $_GET['status'] ?? '';
        $search = $_GET['search'] ?? '';
        $limit = min((int)($_GET['limit'] ?? 50), 100);
        $offset = (int)($_GET['offset'] ?? 0);

        $where = [];
        $params = [];
        if ($type !== '' && in_array($type, ['ip','domain','hash','url'], true)) {
            $where[] = "ioc_type = ?";
            $params[] = $type;
        }
        if ($status !== '' && in_array($status, ['sospechosa','confirmada_maliciosa','falsa_alarma','whitelist'], true)) {
            $where[] = "status = ?";
            $params[] = $status;
        }
        if ($search !== '') {
            $where[] = "ioc_value LIKE ?";
            $params[] = '%' . $search . '%';
        }

        $sqlWhere = $where ? 'WHERE ' . implode(' AND ', $where) : '';

        $iocs = Database::fetchAll(
            "SELECT * FROM iocs {$sqlWhere} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            array_merge($params, [$limit, $offset])
        );

        $total = Database::fetchOne(
            "SELECT COUNT(*) as total FROM iocs {$sqlWhere}",
            $params
        )['total'] ?? 0;

        jsonResponse(['success' => true, 'iocs' => $iocs, 'total' => (int)$total]);
        break;

    case 'get':
        $id = (int)($_GET['id'] ?? 0);
        if (!$id) {
            jsonResponse(['error' => 'id requerido'], 400);
        }
        $ioc = Database::fetchOne("SELECT * FROM iocs WHERE ioc_id = ?", [$id]);
        if (!$ioc) {
            jsonResponse(['error' => 'IOC no encontrado'], 404);
        }
        $incidents = Database::fetchAll(
            "SELECT i.*, ii.context FROM incidents i JOIN ioc_incidents ii ON i.incident_id = ii.incident_id WHERE ii.ioc_value = ? ORDER BY i.created_time DESC",
            [$ioc['ioc_value']]
        );
        jsonResponse(['success' => true, 'ioc' => $ioc, 'incidents' => $incidents]);
        break;

    case 'add':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            jsonResponse(['error' => 'Método no permitido'], 405);
        }
        verifyCsrf();
        $data = getJsonInput();
        $value = trim($data['ioc_value'] ?? '');
        $type = $data['ioc_type'] ?? '';
        $notes = trim($data['notes'] ?? '');

        if (!$value || !in_array($type, ['ip','domain','hash','url'], true)) {
            jsonResponse(['error' => 'Valor y tipo válidos requeridos'], 400);
        }

        try {
            $id = Database::insert('iocs', [
                'ioc_value' => $value,
                'ioc_type' => $type,
                'notes' => $notes,
                'status' => 'sospechosa',
                'declared_by' => $_SESSION['username'] ?? 'system',
            ]);
            jsonResponse(['success' => true, 'ioc_id' => $id]);
        } catch (Exception $e) {
            jsonResponse(['error' => 'Error al insertar: ' . $e->getMessage()], 500);
        }
        break;

    case 'update_status':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            jsonResponse(['error' => 'Método no permitido'], 405);
        }
        verifyCsrf();
        $data = getJsonInput();
        $id = (int)($data['ioc_id'] ?? 0);
        $status = $data['status'] ?? '';
        $notes = trim($data['notes'] ?? '');

        if (!$id || !in_array($status, ['sospechosa','confirmada_maliciosa','falsa_alarma','whitelist'], true)) {
            jsonResponse(['error' => 'Datos inválidos'], 400);
        }

        $update = ['status' => $status, 'declared_at' => date('Y-m-d H:i:s'), 'declared_by' => $_SESSION['username'] ?? 'system'];
        if ($notes !== '') {
            $update['notes'] = $notes;
        }
        Database::update('iocs', $update, 'ioc_id = ?', [$id]);
        jsonResponse(['success' => true]);
        break;

    case 'delete':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            jsonResponse(['error' => 'Método no permitido'], 405);
        }
        verifyCsrf();
        $data = getJsonInput();
        $id = (int)($data['ioc_id'] ?? 0);
        if (!$id) {
            jsonResponse(['error' => 'ioc_id requerido'], 400);
        }
        Database::query("DELETE FROM iocs WHERE ioc_id = ?", [$id]);
        jsonResponse(['success' => true]);
        break;

    case 'stats':
        $stats = Database::fetchAll(
            "SELECT ioc_type, status, COUNT(*) as count FROM iocs GROUP BY ioc_type, status"
        );
        $total = Database::fetchOne("SELECT COUNT(*) as c FROM iocs")['c'] ?? 0;
        jsonResponse(['success' => true, 'stats' => $stats, 'total' => (int)$total]);
        break;

    default:
        jsonResponse(['error' => 'Acción no válida'], 400);
}
