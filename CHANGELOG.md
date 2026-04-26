# Changelog

## [v0.5.2] — 2026-04-27

### Fixed
- **Worker widget "Offline"**: comparación de timestamps ahora fuerza UTC (evita desfase de timezone entre hosting y Orin).
- **llama-server no responde**: worker ahora hace polling durante 60s (cada 2s) en lugar de esperar 10s fijos. Los modelos de 2.7GB+ necesitan ~20-30s para cargar en Jetson Orin Nano.
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
