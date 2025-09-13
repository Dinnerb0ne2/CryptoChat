
document.addEventListener('DOMContentLoaded', () => {
    const messageInput = document.getElementById('messageInput');
    const sendButton = document.getElementById('sendButton');
    const messagesContainer = document.getElementById('messages');
    let lastMessageId = 0;

    const sendMessage = async (content) => {
        try {
            const response = await fetch('/api/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    type: 'message',
                    content: content
                })
            });

            const result = await response.json();
            if (!result.success) {
                showSystemMessage(`发送失败: ${result.error || '未知错误'}`);
            }
        } catch (error) {
            showSystemMessage(`发送失败: ${error.message}`);
        }
    };

    // 轮询获取新消息
    const fetchNewMessages = async () => {
        try {
            const response = await fetch(`/api/messages?last_id=${lastMessageId}`);
            const data = await response.json();
            
            if (data.messages.length > 0) {
                data.messages.forEach(msg => {
                    displayMessage(msg);
                    lastMessageId = Math.max(lastMessageId, msg.id);
                });
            }
        } catch (error) {
            console.error('获取消息失败:', error);
        } finally {
            // 继续轮询
            setTimeout(fetchNewMessages, 1000);
        }
    };

    // 显示消息到页面
    const displayMessage = (msg) => {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${msg.type}`;
        
        if (msg.type === 'message') {
            messageDiv.innerHTML = `
                <span class="time">${new Date(msg.timestamp * 1000).toLocaleTimeString()}</span>
                <span class="user">${msg.nickname}:</span>
                <span class="content">${msg.message}</span>
            `;
        } else if (msg.type === 'system') {
            messageDiv.innerHTML = `<span class="system">[系统] ${msg.message}</span>`;
        }
        
        messagesContainer.appendChild(messageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    };

    // 显示系统消息
    const showSystemMessage = (text) => {
        const systemDiv = document.createElement('div');
        systemDiv.className = 'message system';
        systemDiv.innerHTML = `<span>${text}</span>`;
        messagesContainer.appendChild(systemDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    };

    // 绑定发送按钮事件
    sendButton.addEventListener('click', () => {
        const content = messageInput.value.trim();
        if (content) {
            sendMessage(content);
            messageInput.value = '';
        }
    });

    // 绑定回车键发送
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            sendButton.click();
        }
    });

    // 初始化：开始获取消息
    fetchNewMessages();
    showSystemMessage('');
});