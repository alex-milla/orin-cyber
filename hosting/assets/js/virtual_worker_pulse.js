/**
 * Pulse de Virtual Worker — se ejecuta en cualquier página autenticada
 * para procesar tareas cloud pendientes sin depender de cron.
 */
(function() {
    let csrf = '';
    const PULSE_INTERVAL = 15000; // 15s

    function init() {
        const csrfMeta = document.querySelector('meta[name="csrf-token"]');
        if (!csrfMeta) return;
        csrf = csrfMeta.getAttribute('content') || '';
        if (!csrf) return;
        pulse();
        setInterval(pulse, PULSE_INTERVAL);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

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

})();
