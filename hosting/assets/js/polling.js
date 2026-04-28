/**
 * Polling del frontend para consultar estado de tareas
 */
(function() {
    const area = document.getElementById('polling-area');
    if (!area) return;

    const taskId = area.dataset.taskId;
    const statusEl = document.getElementById('status-message');
    const resultArea = document.getElementById('result-area');
    const resultContent = document.getElementById('result-content');

    const POLL_INTERVAL = 5000;   // 5 segundos
    const VIRTUAL_POLL_INTERVAL = 10000; // 10 segundos para virtual worker
    const MAX_WAIT = 180000;      // 3 minutos timeout
    const startTime = Date.now();

    let timer = null;
    let virtualTimer = null;

    async function pollVirtualWorker() {
        try {
            const csrfInput = document.querySelector('input[name="csrf_token"]');
            const csrf = csrfInput ? csrfInput.value : '';
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
                console.log('Virtual Worker procesó tarea #' + data.task_id);
            }
        } catch (e) {
            // Silencioso: no interrumpe el polling principal
        }
    }

    async function checkStatus() {
        try {
            const res = await fetch('ajax_check_status.php?task_id=' + encodeURIComponent(taskId), {
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            const data = await res.json();

            if (data.error) {
                statusEl.innerHTML = '<span style="color:#c62828;">Error: ' + escapeHtml(data.error) + '</span>';
                stopPolling();
                return;
            }

            const statusSpan = statusEl.querySelector('span') || statusEl;
            statusSpan.textContent = data.status;
            statusSpan.className = 'status-' + data.status;

            if (data.status === 'completed') {
                showResult(data.result_html, data.result_text);
                stopPolling();
                return;
            }

            if (data.status === 'error') {
                showResult('<p style="color:#c62828;"><strong>Error:</strong> ' + escapeHtml(data.error_message || 'Error desconocido') + '</p>', data.error_message || '');
                stopPolling();
                return;
            }

            if (Date.now() - startTime > MAX_WAIT) {
                statusEl.innerHTML = '<span style="color:#c62828;">Timeout: el worker no respondió en 3 minutos.</span>';
                stopPolling();
                return;
            }

        } catch (e) {
            console.error('Polling error:', e);
        }
    }

    function showResult(html, text) {
        resultContent.innerHTML = html || '<p class="small">Sin contenido HTML.</p>';
        // Añadir textarea oculto para copiar
        let ta = document.getElementById('plain-text');
        if (!ta) {
            ta = document.createElement('textarea');
            ta.id = 'plain-text';
            ta.style.position = 'absolute';
            ta.style.left = '-9999px';
            document.body.appendChild(ta);
        }
        ta.value = text || '';
        resultArea.style.display = 'block';
        // Ocultar spinner
        const spinner = area.querySelector('.spinner');
        if (spinner) spinner.style.display = 'none';
    }

    function stopPolling() {
        if (timer) {
            clearInterval(timer);
            timer = null;
        }
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // Primera consulta inmediata, luego cada 5s
    checkStatus();
    timer = setInterval(checkStatus, POLL_INTERVAL);

    // Polling de Virtual Worker en segundo plano (cada 10s)
    pollVirtualWorker();
    virtualTimer = setInterval(pollVirtualWorker, VIRTUAL_POLL_INTERVAL);
})();
