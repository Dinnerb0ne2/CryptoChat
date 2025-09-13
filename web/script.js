// 配置
const webuiPort = 25567;
let lastMessageId = 0;
let isPolling = false;

// DOM元素
const chatHistory = document.getElementById('chat-history');
const messageInput = document.getElementById('message-input');

// 初始化
document.addEventListener('DOMContentLoaded', () => {
    // 开始轮询消息
    startPolling();
    
    // 绑定发送按钮事件
    document.querySelector('button').addEventListener('click', sendMessage);
    
    // 绑定回车键发送
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });
});

// 发送消息
function sendMessage() {
    const text = messageInput.value.trim();
    if (!text) return;
    
    const type = text.startsWith('/') ? 'command' : 'message';
    
    // 发送POST请求
    fetch(`/api/send`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ type, content: text })
    })
    .then(response => response.json())
    .then(data => {
        if (!data.success) {
            addSystemMessage(`错误: ${data.error || '发送失败'}`);
        } else if (data.command_result) {
            addSystemMessage(data.command_result);
        }
    })
    .catch(error => {
        addSystemMessage(`发送失败: ${error.message}`);
    });
    
    // 清空输入框
    messageInput.value = '';
}

// 开始轮询消息
function startPolling() {
    if (isPolling) return;
    isPolling = true;
    pollMessages();
}

// 轮询消息
function pollMessages() {
    if (!isPolling) return;
    
    // 发送GET请求获取新消息
    fetch(`/api/messages?last_id=${lastMessageId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            // 处理新消息
            if (data.messages && data.messages.length > 0) {
                data.messages.forEach(msg => {
                    addMessageToHistory(msg);
                });
                lastMessageId = data.last_id;
            }
            
            // 继续轮询
            setTimeout(pollMessages, 100);
        })
        .catch(error => {
            console.error('轮询错误:', error);
            addSystemMessage('连接已断开，正在尝试重连...');
            // 出错后延迟重连
            setTimeout(pollMessages, 3000);
        });
}

// 添加消息到历史记录
function addMessageToHistory(msg) {
    const div = document.createElement('div');
    
    switch (msg.type) {
        case 'message':
            div.className = 'user-message';
            div.textContent = `[${new Date(msg.timestamp * 1000).toLocaleTimeString()}] ${msg.nickname}: ${msg.message}`;
            break;
        case 'system':
            div.className = 'system-message';
            div.textContent = `[系统] ${msg.message}`;
            break;
        case 'online':
            div.className = 'system-message';
            div.textContent = `在线用户: ${msg.nicknames.join(', ')} (共${msg.count}人)`;
            break;
        case 'pong':
            div.className = 'system-message';
            div.textContent = `延迟: ${msg.latency}ms`;
            break;
    }
    
    chatHistory.appendChild(div);
    chatHistory.scrollTop = chatHistory.scrollHeight;
}

// 添加系统消息
function addSystemMessage(text) {
    const div = document.createElement('div');
    div.className = 'system-message';
    div.textContent = `[系统] ${text}`;
    chatHistory.appendChild(div);
    chatHistory.scrollTop = chatHistory.scrollHeight;
}

// 页面关闭时停止轮询
window.addEventListener('beforeunload', () => {
    isPolling = false;
});
