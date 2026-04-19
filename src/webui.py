from __future__ import annotations

import json
import queue
import ssl
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any
from urllib.parse import parse_qs, urlparse

from .server import ChatServer


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class ChatWebApp:
    def __init__(self, config: dict[str, Any], chat_server: ChatServer) -> None:
        self.config = config
        self.chat_server = chat_server
        self.web_cfg = config["web"]
        self.rooms_cfg = config["rooms"]
        self.static_dir = Path(self.web_cfg["static_dir"]).resolve()

    def _json_response(self, handler: BaseHTTPRequestHandler, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    def handle_api_get(self, handler: BaseHTTPRequestHandler, path: str, query: dict[str, list[str]]) -> bool:
        if path == "/api/users":
            room = query.get("room", [""])[0] or None
            users = self.chat_server.list_online_users(room=room)
            self._json_response(handler, {"ok": True, "users": users})
            return True
        if path == "/api/history":
            limit = int(query.get("limit", [str(self.config["history"]["default_limit"])])[0])
            room = query.get("room", [""])[0] or None
            history = self.chat_server.get_history(limit=limit, room=room)
            self._json_response(handler, {"ok": True, "history": history})
            return True
        if path == "/api/rooms":
            enabled = bool(self.rooms_cfg.get("enabled", False))
            rooms = sorted(self.rooms_cfg.get("rooms", {}).keys())
            self._json_response(handler, {"ok": True, "enabled": enabled, "rooms": rooms})
            return True
        return False

    def handle_api_post(self, handler: BaseHTTPRequestHandler, path: str, payload: dict[str, Any]) -> bool:
        if path == "/api/send":
            nickname = str(payload.get("nickname", "")).strip() or "web-user"
            content = str(payload.get("content", "")).strip()
            room = str(payload.get("room", "")).strip()
            room_password = str(payload.get("room_password", ""))
            if not content:
                self._json_response(handler, {"ok": False, "error": "content required"}, status=400)
                return True
            client_ip, client_port = handler.client_address[0], int(handler.client_address[1])
            if content.startswith("/"):
                parts = content[1:].split()
                if not parts:
                    self._json_response(handler, {"ok": False, "error": "empty command"}, status=400)
                    return True
                result = self.chat_server.run_web_command(nickname, parts[0], parts[1:], room, room_password)
                self._json_response(handler, result, status=200 if result.get("ok") else 400)
                return True
            try:
                msg = self.chat_server.post_web_message(
                    nickname=nickname,
                    content=content,
                    ip=client_ip,
                    port=client_port,
                    room=room,
                    password=room_password,
                )
            except ValueError as exc:
                self._json_response(handler, {"ok": False, "error": str(exc)}, status=403)
                return True
            self._json_response(handler, {"ok": True, "message": msg})
            return True
        return False

    def serve_static(self, handler: BaseHTTPRequestHandler, path: str) -> bool:
        rel = "index.html" if path == "/" else path.lstrip("/")
        file_path = (self.static_dir / rel).resolve()
        if not str(file_path).startswith(str(self.static_dir)):
            return False
        if not file_path.exists() or not file_path.is_file():
            return False
        suffix = file_path.suffix.lower()
        content_type = "text/plain; charset=utf-8"
        if suffix == ".html":
            content_type = "text/html; charset=utf-8"
        elif suffix == ".js":
            content_type = "application/javascript; charset=utf-8"
        elif suffix == ".css":
            content_type = "text/css; charset=utf-8"
        body = file_path.read_bytes()
        handler.send_response(HTTPStatus.OK)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)
        return True

    def stream_events(self, handler: BaseHTTPRequestHandler) -> None:
        subscriber = self.chat_server.register_web_subscriber()
        handler.send_response(HTTPStatus.OK)
        handler.send_header("Content-Type", "text/event-stream")
        handler.send_header("Cache-Control", "no-cache")
        handler.send_header("Connection", "keep-alive")
        handler.end_headers()
        try:
            while True:
                try:
                    event = subscriber.get(timeout=15)
                    data = json.dumps(event, ensure_ascii=False)
                    chunk = f"data: {data}\n\n".encode("utf-8")
                    handler.wfile.write(chunk)
                    handler.wfile.flush()
                except queue.Empty:
                    ping = b": ping\n\n"
                    handler.wfile.write(ping)
                    handler.wfile.flush()
        except OSError:
            pass
        finally:
            self.chat_server.unregister_web_subscriber(subscriber)


class ChatHTTPRequestHandler(BaseHTTPRequestHandler):
    server_version = "CryptoChatHTTP/1.0"

    @property
    def app(self) -> ChatWebApp:
        return self.server.app  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/events":
            self.app.stream_events(self)
            return
        if path.startswith("/api/"):
            if self.app.handle_api_get(self, path, query):
                return
            self.send_error(HTTPStatus.NOT_FOUND, "API not found")
            return
        if self.app.serve_static(self, path):
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            self.send_error(HTTPStatus.BAD_REQUEST, "invalid json")
            return
        if not isinstance(payload, dict):
            self.send_error(HTTPStatus.BAD_REQUEST, "json object required")
            return
        if path.startswith("/api/") and self.app.handle_api_post(self, path, payload):
            return
        self.send_error(HTTPStatus.NOT_FOUND, "API not found")

    def log_message(self, format: str, *args: Any) -> None:
        return


class ChatWebUIServer:
    def __init__(self, config: dict[str, Any], chat_server: ChatServer) -> None:
        self.config = config
        self.app = ChatWebApp(config, chat_server)
        self.httpd: ThreadingHTTPServer | None = None

    def start(self, background: bool = False) -> None:
        host = self.config["web"]["host"]
        port = int(self.config["web"]["port"])
        self.httpd = ThreadingHTTPServer((host, port), ChatHTTPRequestHandler)
        self.httpd.app = self.app  # type: ignore[attr-defined]
        if bool(self.config["web"].get("use_tls", False)):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.load_cert_chain(self.config["web"]["certfile"], self.config["web"]["keyfile"])
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        if background:
            threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
            return
        self.httpd.serve_forever()

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
