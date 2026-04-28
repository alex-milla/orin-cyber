<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

// Obtener el modelo más reciente cargado por cualquier worker
$latestModel = Database::fetchOne(
    "SELECT model_loaded FROM worker_heartbeats WHERE model_loaded IS NOT NULL AND model_loaded != '' ORDER BY created_at DESC LIMIT 1"
);
$currentModel = $latestModel['model_loaded'] ?? 'Ninguno';

$pageTitle = 'Chat — OrinSec';
require_once __DIR__ . '/templates/header.php';
?>

<style>
.chat-wrap { display: flex; flex-direction: column; gap: .75rem; max-width: 900px; margin: 0 auto; height: calc(100vh - 220px); min-height: 400px; }
.chat-messages { flex: 1 1 auto; overflow-y: auto; border: 1px solid var(--border); border-radius: .5rem; padding: 1rem; background: var(--bg-secondary); }
.chat-message { margin-bottom: .75rem; }
.chat-message.user { text-align: right; }
.chat-message .bubble { display: inline-block; padding: .5rem .9rem; border-radius: 1rem; max-width: 80%; word-break: break-word; line-height: 1.4; }
.chat-message.user .bubble { background: var(--primary); color: #fff; }
.chat-message.assistant .bubble { background: var(--bg-tertiary); color: var(--text); }
.chat-message .meta { font-size: .7rem; color: var(--text-muted); margin-top: .15rem; }
.chat-input-area { display: flex; gap: .5rem; }
.chat-input-area textarea { flex: 1; min-height: 56px; resize: none; }
.chat-status { font-size: .85rem; color: var(--text-muted); min-height: 1.2rem; }
</style>

<h2>💬 Chat con el modelo</h2>
<p class="text-muted">Los mensajes se procesan a través del worker. Puede tardar unos segundos.</p>
<p class="text-muted">Modelo activo: <code><?php echo htmlspecialchars($currentModel); ?></code></p>

<div class="chat-wrap">
    <div class="chat-messages" id="chat-messages"></div>

    <div class="chat-input-area">
        <textarea id="chat-input" placeholder="Escribe tu mensaje..." rows="3"></textarea>
        <button id="chat-send" class="btn btn-primary">Enviar</button>
    </div>
    <div class="chat-status" id="chat-status"></div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    'use strict';

    const messagesEl = document.getElementById('chat-messages');
    const inputEl = document.getElementById('chat-input');
    const sendBtn = document.getElementById('chat-send');
    const statusEl = document.getElementById('chat-status');

    if (!messagesEl || !inputEl || !sendBtn || !statusEl) {
        console.error('Chat: no se encontraron elementos del DOM');
        return;
    }
    console.log('Chat: inicializado correctamente');

function addMessage(role, text) {
    const div = document.createElement('div');
    div.className = 'chat-message ' + role;
    const time = new Date().toLocaleTimeString();
    div.innerHTML = '<div class="bubble">' + escapeHtml(text) + '</div><div class="meta">' + time + '</div>';
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function setStatus(text) {
    statusEl.textContent = text;
}

async function pollTask(taskId) {
    let attempts = 0;
    const maxAttempts = 120; // ~6 minutos a 3s

    return new Promise((resolve, reject) => {
        const interval = setInterval(async () => {
            attempts++;
            if (attempts > maxAttempts) {
                clearInterval(interval);
                reject(new Error('Timeout esperando respuesta'));
                return;
            }

            try {
                const pollUrl = 'api/v1/chat.php?task_id=' + taskId;
                const resp = await fetch(pollUrl, { credentials: 'same-origin' });
                const pollRaw = await resp.text();
                if (resp.status !== 200) {
                    console.log('Poll URL:', pollUrl, 'Status:', resp.status, 'Raw:', pollRaw.substring(0, 300));
                }
                let data;
                try {
                    data = JSON.parse(pollRaw);
                } catch (e) {
                    continue;
                }
                if (!data.success) {
                    clearInterval(interval);
                    reject(new Error(data.error || 'Error desconocido'));
                    return;
                }

                if (data.status === 'completed') {
                    clearInterval(interval);
                    resolve(data.response);
                } else if (data.status === 'error') {
                    clearInterval(interval);
                    reject(new Error(data.error || 'Error en el worker'));
                } else {
                    setStatus('Esperando respuesta del worker... (' + attempts + '/' + maxAttempts + ')');
                }
            } catch (e) {
                // seguir intentando
            }
        }, 3000);
    });
}

async function sendMessage() {
    const text = inputEl.value.trim();
    if (!text) return;

    inputEl.value = '';
    addMessage('user', text);
    sendBtn.disabled = true;
    setStatus('Enviando mensaje...');

    const url = 'api/v1/chat.php';
    try {
        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ message: text })
        });

        const rawText = await resp.text();
        console.log('URL:', url, 'Status:', resp.status, 'Raw:', rawText.substring(0, 500));

        let data;
        try {
            data = JSON.parse(rawText);
        } catch (e) {
            throw new Error('HTTP ' + resp.status + ' — respuesta no es JSON. Primeros 200 chars: ' + rawText.substring(0, 200));
        }

        if (!data.success) {
            throw new Error(data.error || 'Error al crear la tarea');
        }

        setStatus('Mensaje enviado. Esperando respuesta del worker...');
        const response = await pollTask(data.task_id);
        addMessage('assistant', response);
        setStatus('');
    } catch (err) {
        addMessage('assistant', '❌ ' + err.message);
        setStatus('');
    } finally {
        sendBtn.disabled = false;
        inputEl.focus();
    }
}

sendBtn.addEventListener('click', sendMessage);
inputEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});
});
</script>

<?php require_once __DIR__ . '/templates/footer.php'; ?>
