<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

$pageTitle = 'Chat — OrinSec';
require_once __DIR__ . '/templates/header.php';
?>

<style>
.chat-container { max-width: 800px; margin: 0 auto; display: flex; flex-direction: column; height: calc(100vh - 180px); }
.chat-messages { flex: 1; overflow-y: auto; border: 1px solid var(--border); border-radius: .5rem; padding: 1rem; background: var(--bg-secondary); margin-bottom: 1rem; }
.chat-message { margin-bottom: 1rem; }
.chat-message.user { text-align: right; }
.chat-message .bubble { display: inline-block; padding: .6rem 1rem; border-radius: 1rem; max-width: 80%; word-break: break-word; }
.chat-message.user .bubble { background: var(--primary); color: #fff; }
.chat-message.assistant .bubble { background: var(--bg-tertiary); color: var(--text); }
.chat-message .meta { font-size: .7rem; color: var(--text-muted); margin-top: .2rem; }
.chat-input-area { display: flex; gap: .5rem; }
.chat-input-area textarea { flex: 1; min-height: 60px; resize: vertical; }
.chat-status { font-size: .85rem; color: var(--text-muted); margin-top: .5rem; min-height: 1.2rem; }
</style>

<h2>💬 Chat con el modelo</h2>
<p class="text-muted">Los mensajes se procesan a través del worker. Puede tardar unos segundos.</p>

<div class="chat-container">
    <div class="chat-messages" id="chat-messages"></div>

    <div class="chat-input-area">
        <textarea id="chat-input" placeholder="Escribe tu mensaje..." rows="3"></textarea>
        <button id="chat-send" class="btn btn-primary">Enviar</button>
    </div>
    <div class="chat-status" id="chat-status"></div>
</div>

<script>
const messagesEl = document.getElementById('chat-messages');
const inputEl = document.getElementById('chat-input');
const sendBtn = document.getElementById('chat-send');
const statusEl = document.getElementById('chat-status');

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
                const resp = await fetch('api/v1/chat.php?task_id=' + taskId);
                const data = await resp.json();
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

    try {
        const resp = await fetch('api/v1/chat.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: text })
        });
        const data = await resp.json();

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
</script>

<?php require_once __DIR__ . '/templates/footer.php'; ?>
