<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

requireAuth();

// Obtener modelo local actual
$localModel = Database::fetchOne(
    "SELECT model_loaded FROM worker_heartbeats ORDER BY created_at DESC LIMIT 1"
);
$localModelId = ($localModel['model_loaded'] ?? null) ?: 'local-model';

// Obtener conversaciones previas del usuario
$conversations = [];
try {
    $conversations = Database::fetchAll(
        "SELECT id, title, updated_at FROM chat_conversations
         WHERE user_id = ?
         ORDER BY updated_at DESC LIMIT 20",
        [$_SESSION['user_id']]
    );
} catch (Throwable $e) {
    // Tabla podría no existir en versiones antiguas
}

// Conversación activa (si viene por URL)
$activeConvId = filter_input(INPUT_GET, 'conv', FILTER_VALIDATE_INT) ?: 0;
$activeMessages = [];
if ($activeConvId > 0) {
    $own = Database::fetchOne(
        "SELECT id FROM chat_conversations WHERE id = ? AND user_id = ?",
        [$activeConvId, $_SESSION['user_id']]
    );
    if ($own) {
        $activeMessages = Database::fetchAll(
            "SELECT role, content, created_at FROM chat_messages
             WHERE conversation_id = ?
             ORDER BY created_at ASC",
            [$activeConvId]
        );
    } else {
        $activeConvId = 0;
    }
}

$pageTitle = 'Chat — OrinSec';
require_once __DIR__ . '/templates/header.php';
?>

<div style="display: grid; grid-template-columns: 260px 1fr; gap: 1.5rem; align-items: start;">

    <!-- Sidebar: Conversaciones -->
    <aside class="card" style="padding: 1rem; max-height: calc(100vh - 140px); overflow-y: auto;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: .75rem;">
            <h3 style="margin: 0; font-size: 1rem;">💬 Historial</h3>
            <a href="chat.php" class="btn small" style="padding: .25rem .6rem; font-size: .8rem;">+ Nuevo</a>
        </div>

        <div style="font-size: .85rem; color: var(--text-muted); margin-bottom: .5rem;">
            🏠 Modelo: <?= htmlspecialchars($localModelId) ?>
        </div>

        <?php if (empty($conversations)): ?>
            <p class="small" style="color: var(--text-muted);">No hay conversaciones previas.</p>
        <?php else: ?>
            <ul style="list-style: none; padding: 0; margin: 0;">
                <?php foreach ($conversations as $conv): ?>
                    <li style="margin-bottom: .25rem;">
                        <a href="chat.php?conv=<?= (int)$conv['id'] ?>"
                           class="small"
                           style="display: block; padding: .4rem .5rem; border-radius: var(--radius-sm); text-decoration: none; color: var(--text); <?= ($activeConvId == $conv['id']) ? 'background: var(--primary-bg); font-weight: 600;' : '' ?>">
                            <?= htmlspecialchars(mb_substr($conv['title'] ?: 'Sin título', 0, 30)) ?>
                            <span style="display: block; font-size: .7rem; color: var(--text-muted); margin-top: .1rem;">
                                <?= htmlspecialchars(substr($conv['updated_at'], 0, 16)) ?>
                            </span>
                        </a>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
    </aside>

    <!-- Panel de chat -->
    <div>
        <div class="chat-wrap" style="display: flex; flex-direction: column; gap: .75rem; width: 100%; min-height: 60vh; max-height: calc(100vh - 140px); margin-top: 0;">
            <div class="chat-messages" id="chat-messages" style="flex: 1 1 auto; min-height: 300px; overflow-y: auto; border: 1px solid var(--border); border-radius: .5rem; padding: 1rem; background: var(--bg-secondary);">
                <?php if ($activeConvId > 0 && empty($activeMessages)): ?>
                    <p class="small" style="color: var(--text-muted); text-align: center; margin-top: 2rem;">Esta conversación está vacía.</p>
                <?php elseif ($activeConvId === 0): ?>
                    <p class="small" style="color: var(--text-muted); text-align: center; margin-top: 2rem;">💡 Escribe un mensaje para iniciar una nueva conversación con el modelo local.</p>
                <?php endif; ?>

                <?php foreach ($activeMessages as $msg): ?>
                    <div class="chat-message <?= htmlspecialchars($msg['role']) ?>">
                        <div class="bubble"><?= nl2br(htmlspecialchars($msg['content'])) ?></div>
                        <div class="meta"><?= htmlspecialchars(substr($msg['created_at'], 11, 5)) ?></div>
                    </div>
                <?php endforeach; ?>
            </div>

            <div class="chat-input-area" style="display: flex; gap: .5rem; align-items: flex-end;">
                <textarea id="chat-input" placeholder="Escribe tu mensaje..." rows="3" style="flex: 1; min-height: 56px; resize: vertical; padding: .6rem .8rem; border: 1px solid var(--border); border-radius: .5rem; background: var(--surface); color: var(--text); font: inherit;"></textarea>
                <button id="chat-send" class="btn btn-primary" style="align-self: stretch;">Enviar</button>
            </div>
            <div class="chat-status" id="chat-status" style="font-size: .85rem; color: var(--text-muted); min-height: 1.2rem;"></div>
        </div>
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
.chat-message.assistant .bubble { background: var(--surface); color: var(--text); border: 1px solid var(--border); }
.chat-message .meta { font-size: .7rem; color: var(--text-muted); margin-top: .15rem; }
@media (max-width: 640px) {
    .chat-wrap { max-height: calc(100vh - 200px) !important; }
}
</style>

<script>
(function () {
    'use strict';

    const messagesEl = document.getElementById('chat-messages');
    const inputEl = document.getElementById('chat-input');
    const sendBtn = document.getElementById('chat-send');
    const statusEl = document.getElementById('chat-status');

    let currentConversationId = <?= (int)$activeConvId ?>;
    const localModelId = <?= json_encode($localModelId) ?>;

    function escapeHtml(text) {
        const d = document.createElement('div');
        d.textContent = text;
        return d.innerHTML;
    }

    function addMessage(role, text) {
        const div = document.createElement('div');
        div.className = 'chat-message ' + role;
        const time = new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        div.innerHTML =
            '<div class="bubble">' + escapeHtml(text).replace(/\n/g, '<br>') + '</div>' +
            '<div class="meta">' + time + '</div>';
        messagesEl.appendChild(div);
        messagesEl.scrollTop = messagesEl.scrollHeight;
        return div.querySelector('.bubble');
    }

    function setStatus(text) { statusEl.textContent = text; }

    async function sendMessage() {
        const text = inputEl.value.trim();
        if (!text) return;

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
                    provider_id: 0,
                    model_id: localModelId,
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

            assistantBubble.innerHTML = escapeHtml(data.response).replace(/\n/g, '<br>');
            if (data.conversation_id) {
                currentConversationId = data.conversation_id;
                // Actualizar URL sin recargar para que F5 mantenga la conversación
                if (!window.location.search.includes('conv=' + data.conversation_id)) {
                    history.replaceState(null, '', 'chat.php?conv=' + data.conversation_id);
                }
            }
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

    // Auto-scroll al final si hay mensajes previos cargados
    if (messagesEl.children.length > 0) {
        messagesEl.scrollTop = messagesEl.scrollHeight;
    }
})();
</script>

<?php require_once __DIR__ . '/templates/footer.php'; ?>
