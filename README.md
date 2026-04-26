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
4. Eliminar o renombrar `install.php` tras la instalación.

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
   cp config.ini config.ini
   nano config.ini
   ```
4. Asegurar que `llama-server` está corriendo en `localhost:8080`.
5. Ejecutar:
   ```bash
   python worker.py
   ```

### Servicio systemd (opcional)

```bash
sudo cp orinsec-worker.service /etc/systemd/system/
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
│   ├── includes/     # Config, DB, auth, funciones
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
