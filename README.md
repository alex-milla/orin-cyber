# OrinSec 🔒

Plataforma de ciberseguridad con worker de IA local (Jetson Orin Nano) + hosting compartido.

## Arquitectura

- **Hosting** (`hosting/`): PHP 8 + SQLite. Recibe tareas del usuario y expone API REST.
- **Worker** (`worker/`): Python 3. Consulta tareas, ejecuta búsquedas (NVD), genera informes con LLM local (llama.cpp).
- **Conectividad**: Solo saliente desde el Orin. Sin túneles ni puertos abiertos.

## Instalación rápida

### Hosting (PHP)

1. Subir el contenido de `hosting/` al servidor.
2. Acceder a `https://tu-dominio/install.php`.
3. Crear usuario admin y guardar la **API key** generada.
4. `install.php` se auto-bloquea tras la instalación (renombra a `.bak` + crea lock file).

### Worker (Orin Nano)

1. Clonar repo en `~/orinsec`.
2. Crear entorno virtual e instalar dependencias:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. Copiar `config.ini` y rellenar `api_key` con la clave de install.php:
   ```bash
   nano worker/config.ini
   ```
4. Asegurar que `llama-server` está corriendo en `localhost:8080`.
5. Ejecutar:
   ```bash
   python worker/worker.py
   ```

### Servicio systemd (opcional)

```bash
sudo cp worker/orinsec-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now orinsec-worker
```

## API del Worker

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/api/v1/tasks.php?action=pending` | Tareas pendientes |
| POST | `/api/v1/tasks.php?action=claim` | Reclamar tarea |
| POST | `/api/v1/tasks.php?action=result` | Enviar resultado |

Auth: Header `X-API-Key`.

## Medidas de seguridad implementadas

| Capa | Medida | Descripción |
|------|--------|-------------|
| Transporte | HTTPS obligatorio | Todo el tráfico hosting ↔ Orin por HTTPS |
| Headers | CSP, HSTS-ready, X-Frame, XSS, nosniff | `.htaccess` configura headers de seguridad |
| Sesiones | Cookies HttpOnly + Secure + SameSite=Strict | Previene robo de sesión y CSRF básico |
| Sesiones | Regeneración de ID tras login | Previene fijación de sesión |
| Autenticación | Bcrypt + brute-force protection | 5 intentos máximo en 5 minutos |
| Autenticación | CSRF tokens en todos los formularios | Protección contra ataques CSRF |
| API | API key en header | Worker autenticado con token generado en instalación |
| API | Rate limiting | 1 req/seg para worker, 1 req/seg para frontend |
| Datos | Prepared statements (PDO) | Protección contra SQL Injection |
| Datos | `data/.htaccess` | Bloquea acceso directo a SQLite |
| Datos | `includes/.htaccess` | Bloquea acceso directo a archivos PHP internos |
| Datos | `templates/.htaccess` | Bloquea acceso directo a templates |
| Datos | `install.php` auto-lock | Se renombra a `.bak` tras instalación |
| Output | `htmlspecialchars` + `strip_tags` | Protección XSS en salidas |
| Output | Validación de inputs | Regex whitelist en formularios |
| Admin | Panel admin solo para `is_admin=1` | Separación de privilegios |
| Updater | Backup automático + rollback | Si falla la actualización, restaura automáticamente |
| Updater | Validación estricta de nombres de archivo | Previene path traversal en backups |

## Primera tarea: CVE Search

El usuario rellena el formulario en `task_cve.php`:
- Producto / Software
- Versión (opcional)
- Año mínimo (opcional)
- Severidad mínima (opcional)
- Máximo resultados

El worker busca en NVD, pasa los datos al LLM y genera un informe estructurado en español.

## Estructura del repo

```
.
├── hosting/          # Código PHP (subir al hosting)
│   ├── api/v1/       # API REST para el worker
│   ├── assets/       # CSS, JS
│   ├── data/         # SQLite + .htaccess de protección
│   ├── includes/     # Config, DB, auth, funciones, updater
│   ├── templates/    # Header, footer
│   └── *.php         # Páginas principales
├── worker/           # Código Python (ejecutar en Orin)
│   ├── tasks/        # Lógica de cada tarea
│   ├── scrapers/     # Fuentes de datos externas
│   ├── utils/        # Clientes API y LLM
│   ├── prompts/      # Plantillas de prompts
│   └── worker.py     # Loop principal
└── README.md
```

## Licencia

Proyecto privado — Alex Milla.
