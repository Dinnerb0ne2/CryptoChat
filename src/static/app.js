const messages = document.getElementById("messages");
const messageInput = document.getElementById("message");
const nicknameInput = document.getElementById("nickname");
const roomInput = document.getElementById("room");
const roomPasswordInput = document.getElementById("roomPassword");

function appendLine(text) {
  messages.textContent += `${text}\n`;
  messages.scrollTop = messages.scrollHeight;
}

function fmt(item) {
  return `[${item.timestamp}][${item.room}][${item.nickname} ${item.ip}:${item.port}] ${item.content}`;
}

async function postSend(content) {
  const res = await fetch("/api/send", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      nickname: nicknameInput.value.trim() || "web-user",
      room: roomInput.value.trim(),
      room_password: roomPasswordInput.value,
      content,
    }),
  });
  const data = await res.json();
  if (!data.ok) appendLine(`[ERROR] ${data.error || data.message || "unknown error"}`);
  else if (data.message) appendLine(fmt(data.message));
  else appendLine(`[OK] ${JSON.stringify(data)}`);
}

document.getElementById("sendBtn").addEventListener("click", async () => {
  const content = messageInput.value.trim();
  if (!content) return;
  await postSend(content);
  messageInput.value = "";
});

messageInput.addEventListener("keydown", async (ev) => {
  if (ev.key === "Enter") {
    ev.preventDefault();
    document.getElementById("sendBtn").click();
  }
});

document.getElementById("loadUsers").addEventListener("click", async () => {
  const room = roomInput.value.trim();
  const query = room ? `?room=${encodeURIComponent(room)}` : "";
  const res = await fetch(`/api/users${query}`);
  const data = await res.json();
  if (!data.ok) return appendLine("[ERROR] load users failed");
  appendLine("[USERS]");
  data.users.forEach((u) => appendLine(`  - ${u.nickname} ${u.ip}:${u.port} room=${u.room} since=${u.connected_at}`));
});

document.getElementById("loadHistory").addEventListener("click", async () => {
  const room = roomInput.value.trim();
  const query = room ? `?room=${encodeURIComponent(room)}&limit=100` : "?limit=100";
  const res = await fetch(`/api/history${query}`);
  const data = await res.json();
  if (!data.ok) return appendLine("[ERROR] load history failed");
  appendLine("[HISTORY]");
  data.history.forEach((item) => appendLine(fmt(item)));
});

document.getElementById("clearHistory").addEventListener("click", async () => {
  await postSend("/clear");
});

const eventSource = new EventSource("/events");
eventSource.onmessage = (event) => {
  const payload = JSON.parse(event.data);
  if (payload.type === "message") appendLine(fmt(payload));
  else if (payload.type === "system") appendLine(`[${payload.timestamp}][SYSTEM] ${payload.content}`);
};
