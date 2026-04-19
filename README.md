# CryptoChat

基于 **Python 3.14.3** 的加密聊天项目（仅标准库运行时依赖），提供：

- TLS 1.3 加密传输（`ssl`）
- CLI 客户端 + WebUI
- SQLite 持久化（`sqlite3`）
- 命令系统（`/help` `/users` `/history` `/clear` `/rooms` `/join` `/quit`）
- 可选房间与密码（默认关闭）
- GitHub Actions CI/CD + Nuitka 打包

---

## 1. 目录结构

```text
.
├─ chat.py
├─ config/
│  └─ chat_config.json
├─ src/
│  ├─ main.py
│  ├─ client.py
│  ├─ server.py
│  ├─ webui.py
│  ├─ storage.py
│  ├─ protocol.py
│  ├─ config.py
│  ├─ utils.py
│  └─ static/
│     ├─ index.html
│     ├─ app.js
│     └─ style.css
├─ tests/
└─ .github/workflows/
```

---

## 2. 运行前准备（TLS 证书）

项目要求 TLS 1.3，需要服务端证书与私钥。示例（OpenSSL）：

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost"
```

Windows PowerShell：

```powershell
New-Item -ItemType Directory -Path certs -Force | Out-Null
openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost"
```

> 默认配置允许客户端跳过证书校验（便于自签证书本地开发）。

---

## 3. 配置说明

默认配置文件：`config/chat_config.json`

关键字段：

- `database.path`: sqlite 文件路径
- `server.host/port/certfile/keyfile`: TLS 聊天服务监听与证书
- `client.server_host/server_port/cert_verify`: CLI 客户端连接参数
- `rooms.enabled`: 房间功能开关（默认 `false`）
- `rooms.rooms.<room>.password`: 房间密码（任意字符串）
- `web.host/port/use_tls/static_dir`: WebUI 服务配置
- `history.default_limit/max_limit`: 历史消息读取策略

---

## 4. 启动方式

### 4.1 初始化数据库

```bash
python chat.py --config config/chat_config.json init-db
```

### 4.2 启动聊天服务器（TLS）

```bash
python chat.py --config config/chat_config.json server
```

### 4.3 启动 CLI 客户端

```bash
python chat.py --config config/chat_config.json client --nickname alice
```

可选：

```bash
python chat.py --config config/chat_config.json client --nickname bob --room team-a --room-password team-secret
```

### 4.4 启动 Web 模式（聊天服务 + WebUI）

```bash
python chat.py --config config/chat_config.json web
```

然后访问：

- `http://127.0.0.1:9444/`（或你配置的地址）

---

## 5. 聊天命令

CLI 输入 `/` 前缀调用命令：

1. `/help` 显示帮助
2. `/users` 显示在线用户
3. `/history [n]` 查看历史消息
4. `/clear` 清除消息记录（按配置决定是否仅当前房间）
5. `/rooms` 查看房间列表
6. `/join <room> [password]` 切换/进入房间
7. `/quit` 退出聊天

消息展示与数据库存储包含：

- 昵称
- IP
- 端口
- 房间
- 时间（`MM-DD HH:MM:SS`）
- 消息内容

---

## 6. 测试

```bash
python -m unittest discover -s tests -v
```

---

## 7. Nuitka 打包

```bash
python -m pip install nuitka
python -m nuitka --onefile --output-dir=dist chat.py
```

生成产物在 `dist/`。

---

## 8. CI/CD

- `ci.yml`：在 push / PR 时自动执行 `unittest`
- `release.yml`：在推送 `v*` tag 时
  - 运行测试
  - 使用 Nuitka 构建
  - 上传产物到 GitHub Release

