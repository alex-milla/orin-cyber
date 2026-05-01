<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

$pageTitle = 'Chat — OrinSec';
require_once __DIR__ . '/templates/header.php';
?>

<h2>💬 Chat con el modelo</h2>

<div class="chat-controls" style="margin-bottom: 1rem;">
    <label for="provider-select">Modelo:</label>
    <select id="provider-select" style="min-width: 280px;"></select>
</div>

<div id="chat-panel">
    <div class="chat-wrap" style="display: flex; flex-direction: column; gap: .75rem; width: 100%; min-height: 60vh; max-height: calc(100vh - 280px); margin-top: .5rem;">
        <div class="chat-messages" id="chat-messages" style="flex: 1 1 auto; min-height: 300px; overflow-y: auto; border: 1px solid var(--border); border-radius: .5rem; padding: 1rem; background: var(--bg-secondary);"></div>
        <div class="chat-input-area" style="display: flex; gap: .5rem; align-items: flex-end;">
            <textarea id="chat-input" placeholder="Escribe tu mensaje..." rows="3" style="flex: 1; min-height: 56px; resize: vertical; padding: .6rem .8rem; border: 1px solid var(--border); border-radius: .5rem; background: var(--surface); color: var(--text); font: inherit;"></textarea>
            <button id="chat-send" class="btn btn-primary" style="align-self: stretch;">Enviar</button>
        </div>
        <div class="chat-status" id="chat-status" style="font-size: .85rem; color: var(--text-muted); min-height: 1.2rem;"></div>
    </div>
</div>

<style>
.chat-message { margin-bottom: .75rem; }
.chat-message.user { text-align: right; }
.chat-message .bubble {
    display: inline-block;
    padding: .5rem .9rem;
    border-radius: 1rem;
    max-width: 80%;
    word-break: break-word;
    line-height: 1.4;
}
.chat-message.user .bubble { background: var(--primary); color: #fff; }
.chat-message.assistant .bubble { background: var(--bg-tertiary); color: var(--text); }
.chat-message .meta { font-size: .7rem; color: var(--text-muted); margin-top: .15rem; }
</style>

<script>
(function () {
    'use strict';

    const providerSelect = document.getElementById('provider-select');
    const messagesEl = document.getElementById('chat-messages');
    const inputEl = document.getElementById('chat-input');
    const sendBtn = document.getElementById('chat-send');
    const statusEl = document.getElementById('chat-status');

    let currentConversationId = 0;
    let availableProviders = [];
    let availableModels = [];

    function escapeHtml(text) {
        const d = document.createElement('div');
        d.textContent = text;
        return d.innerHTML;
    }

    function addMessage(role, text) {
        const div = document.createElement('div');
        div.className = 'chat-message ' + role;
        const time = new Date().toLocaleTimeString();
        div.innerHTML =
            '<div class="bubble">' + escapeHtml(text) + '</div>' +
            '<div class="meta">' + time + '</div>';
        messagesEl.appendChild(div);
        messagesEl.scrollTop = messagesEl.scrollHeight;
        return div.querySelector('.bubble');
    }

    function setStatus(text) { statusEl.textContent = text; }

    async function loadProviders() {
        let hasOptions = false;
        try {
            const resp = await fetch('api/v1/chat_external.php', { credentials: 'same-origin' });
            const data = await resp.json();
            if (data.success) {
                availableProviders = data.providers;
                availableModels = data.models;
                const providersById = {};
                data.providers.forEach(p => providersById[p.id] = p);

                const byProvider = {};
                data.models.forEach(m => {
                    if (!byProvider[m.provider_id]) byProvider[m.provider_id] = [];
                    byProvider[m.provider_id].push(m);
                });
                Object.keys(byProvider).forEach(pid => {
                    const provider = providersById[pid];
                    if (!provider) return;
                    const group = document.createElement('optgroup');
                    const prefix = parseInt(pid) === 0 ? '🏠 ' : '☁️ ';
                    group.label = prefix + provider.label;
                    byProvider[pid].forEach(m => {
                        const opt = document.createElement('option');
                        opt.value = JSON.stringify({
                            provider_id: parseInt(pid),
                            model_id: m.model_id
                        });
                        opt.textContent = m.label;
                        group.appendChild(opt);
                        hasOptions = true;
                    });
                    providerSelect.appendChild(group);
                });

                if (data.providers.length && !hasOptions) {
                    const hint = document.createElement('option');
                    hint.disabled = true;
                    hint.textContent = '⚠️ Hay proveedores pero sin modelos (configúralos en Admin → Proveedores)';
                    providerSelect.appendChild(hint);
                }
            }
        } catch (e) {
            console.warn('No se pudieron cargar proveedores:', e);
            const errOpt = document.createElement('option');
            errOpt.disabled = true;
            errOpt.textContent = '❌ Error cargando proveedores';
            providerSelect.appendChild(errOpt);
        }

        const saved = localStorage.getItem('orinsec_provider');
        if (saved) {
            try {
                providerSelect.value = saved;
            } catch(e) {}
        }
        providerSelect.addEventListener('change', () => {
            localStorage.setItem('orinsec_provider', providerSelect.value);
        });
    }

    async function sendMessage() {
        const text = inputEl.value.trim();
        if (!text) return;

        const selection = JSON.parse(providerSelect.value || '{}');
        if (!selection.provider_id && selection.provider_id !== 0) {
            setStatus('Selecciona un modelo primero.');
            return;
        }

        // Detectar URLs en el mensaje y avisar
        const urlPattern = /https?:\/\/\S+/g;
        const detectedUrls = text.match(urlPattern) || [];
        if (detectedUrls.length > 0) {
            setStatus('Leyendo ' + detectedUrls.length + ' URL(s)...');
        }

        inputEl.value = '';
        addMessage('user', text);
        sendBtn.disabled = true;
        if (detectedUrls.length === 0) {
            setStatus('Enviando...');
        }
        const assistantBubble = addMessage('assistant', '...');

        try {
            const resp = await fetch('api/v1/chat_external.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({
                    provider_id: selection.provider_id,
                    model_id: selection.model_id,
                    message: text,
                    conversation_id: currentConversationId || 0,
                    stream: false,
                })
            });

            const rawText = await resp.text();
            let data;
            try { data = JSON.parse(rawText); } catch(e) {
                throw new Error('HTTP ' + resp.status + ' — respuesta no es JSON');
            }

            if (!data.success) {
                throw new Error(data.error || 'Error del servidor');
            }

            assistantBubble.textContent = data.response;
            if (data.conversation_id) currentConversationId = data.conversation_id;
            setStatus('Listo (' + (data.duration_ms || 0) + ' ms)');
        } catch (err) {
            assistantBubble.textContent = '❌ ' + err.message;
            setStatus('');
        } finally {
            sendBtn.disabled = false;
            inputEl.focus();
            messagesEl.scrollTop = messagesEl.scrollHeight;
        }
    }

    sendBtn.addEventListener('click', sendMessage);
    inputEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    loadProviders();
})();
</script>

<?php require_once __DIR__ . '/templates/footer.php'; ?>
