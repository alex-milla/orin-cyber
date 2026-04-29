/**
 * Pulse de Virtual Worker — se ejecuta en cualquier página autenticada
 * para procesar tareas cloud pendientes sin depender de cron.
 */
(function() {
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    if (!csrfMeta) return;
    const csrf = csrfMeta.getAttribute('content');
    if (!csrf) return;

    const PULSE_INTERVAL = 15000; // 15s

    async function pulse() {
        try {
            const res = await fetch('ajax_virtual_worker.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-CSRF-Token': csrf,
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: 'csrf_token=' + encodeURIComponent(csrf)
            });
            const data = await res.json();
            if (data.processed) {
                console.log('[virtual-worker-pulse] procesada tarea #' + data.task_id);
                window.dispatchEvent(new CustomEvent('virtual-task-processed', { detail: data }));
            }
        } catch (e) {
            // silencioso
        }
    }

    pulse();
    setInterval(pulse, PULSE_INTERVAL);
})();
