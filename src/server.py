from __future__ import annotations

import queue
import socket
import ssl
import threading
import uuid
from dataclasses import dataclass
from typing import Any, BinaryIO

from .protocol import recv_packet, send_packet
from .storage import ChatStorage
from .utils import now_text


@dataclass
class ClientSession:
    session_id: str
    nickname: str
    ip: str
    port: int
    room: str
    stream: BinaryIO
    conn: ssl.SSLSocket
    lock: threading.Lock


class ChatServer:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.storage = ChatStorage(config["database"]["path"])
        self.rooms_config = config["rooms"]
        self.server_config = config["server"]
        self.history_cfg = config["history"]
        self._dyn_room_passwords: dict[str, str] = {}
        self._clients: dict[str, ClientSession] = {}
        self._web_subscribers: list[queue.Queue[dict[str, Any]]] = []
        self._lock = threading.Lock()
        self._running = threading.Event()
        self._sock: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None

    def _create_server_tls_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(self.server_config["certfile"], self.server_config["keyfile"])
        ca_file = self.server_config.get("ca_file", "")
        if ca_file:
            context.load_verify_locations(cafile=ca_file)
            context.verify_mode = ssl.CERT_REQUIRED
        return context

    def start(self, background: bool = False) -> None:
        if self._running.is_set():
            return
        self._running.set()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        host = self.server_config["host"]
        port = int(self.server_config["port"])
        self._sock.bind((host, port))
        self._sock.listen(int(self.server_config.get("backlog", 128)))
        tls_context = self._create_server_tls_context()
        self._accept_thread = threading.Thread(target=self._accept_loop, args=(tls_context,), daemon=True)
        self._accept_thread.start()
        if not background:
            self._accept_thread.join()

    def stop(self) -> None:
        self._running.clear()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        with self._lock:
            clients = list(self._clients.values())
            self._clients.clear()
        for client in clients:
            try:
                client.conn.close()
            except OSError:
                pass
        self.storage.close()

    def _accept_loop(self, tls_context: ssl.SSLContext) -> None:
        assert self._sock is not None
        while self._running.is_set():
            try:
                raw_conn, _ = self._sock.accept()
            except OSError:
                break
            thread = threading.Thread(target=self._handle_client, args=(raw_conn, tls_context), daemon=True)
            thread.start()

    def _validate_room(self, room: str, password: str) -> tuple[bool, str]:
        cfg = self.rooms_config
        enabled = bool(cfg.get("enabled", False))
        default_room = str(cfg.get("default_room", "lobby"))
        if not enabled:
            return True, default_room
        room_name = room.strip() or default_room
        static_rooms = cfg.get("rooms", {})
        if room_name in static_rooms:
            expected = str(static_rooms[room_name].get("password", ""))
            return expected == password, room_name
        if bool(cfg.get("allow_dynamic", True)):
            known = self._dyn_room_passwords.get(room_name)
            if known is None:
                self._dyn_room_passwords[room_name] = password
                return True, room_name
            return known == password, room_name
        return False, default_room

    def _list_rooms(self) -> list[str]:
        rooms = set(self.rooms_config.get("rooms", {}).keys())
        rooms.update(self._dyn_room_passwords.keys())
        if not rooms:
            rooms.add(str(self.rooms_config.get("default_room", "lobby")))
        return sorted(rooms)

    def _broadcast(self, payload: dict[str, Any], room: str | None = None) -> None:
        with self._lock:
            sessions = list(self._clients.values())
            subscribers = list(self._web_subscribers)
        for session in sessions:
            if room and session.room != room:
                continue
            self._safe_send(session, payload)
        for subscriber in subscribers:
            try:
                subscriber.put_nowait(payload)
            except queue.Full:
                pass

    def _safe_send(self, session: ClientSession, payload: dict[str, Any]) -> None:
        try:
            with session.lock:
                send_packet(session.stream, payload)
        except (OSError, ValueError):
            self._disconnect_session(session.session_id)

    def _disconnect_session(self, session_id: str) -> None:
        with self._lock:
            session = self._clients.pop(session_id, None)
        if not session:
            return
        self.storage.set_client_offline(session_id)
        leave_payload = {
            "type": "system",
            "timestamp": now_text(),
            "room": session.room,
            "content": f"{session.nickname} left room {session.room}",
        }
        self._broadcast(leave_payload, room=session.room)
        self._broadcast({"type": "users_update"}, room=session.room)
        try:
            session.conn.close()
        except OSError:
            pass

    def register_web_subscriber(self) -> queue.Queue[dict[str, Any]]:
        q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=128)
        with self._lock:
            self._web_subscribers.append(q)
        return q

    def unregister_web_subscriber(self, q: queue.Queue[dict[str, Any]]) -> None:
        with self._lock:
            if q in self._web_subscribers:
                self._web_subscribers.remove(q)

    def list_online_users(self, room: str | None = None) -> list[dict[str, Any]]:
        return self.storage.list_online_users(room=room)

    def get_history(self, limit: int, room: str | None = None) -> list[dict[str, Any]]:
        max_limit = int(self.history_cfg.get("max_limit", 500))
        final_limit = max(1, min(int(limit), max_limit))
        return self.storage.get_history(final_limit, room=room)

    def clear_history(self, room: str | None = None) -> int:
        return self.storage.clear_history(room=room)

    def post_web_message(
        self,
        nickname: str,
        content: str,
        ip: str,
        port: int,
        room: str = "",
        password: str = "",
    ) -> dict[str, Any]:
        ok, room_name = self._validate_room(room, password)
        if not ok:
            raise ValueError("room password mismatch")
        msg = self.storage.add_message(nickname, ip, port, room_name, content)
        self._broadcast({"type": "message", **msg}, room=room_name)
        return msg

    def run_web_command(
        self,
        nickname: str,
        command: str,
        args: list[str],
        room: str,
        password: str,
    ) -> dict[str, Any]:
        ok, room_name = self._validate_room(room, password)
        if not ok:
            return {"ok": False, "message": "room password mismatch"}
        cmd = command.lower()
        if cmd == "users":
            return {"ok": True, "users": self.list_online_users(room=room_name)}
        if cmd == "history":
            limit = int(args[0]) if args else int(self.history_cfg.get("default_limit", 50))
            return {"ok": True, "history": self.get_history(limit, room=room_name)}
        if cmd == "clear":
            deleted = self.clear_history(room=room_name if self.rooms_config.get("room_scoped_clear", True) else None)
            self._broadcast({"type": "system", "timestamp": now_text(), "room": room_name, "content": f"{nickname} cleared history"})
            return {"ok": True, "deleted": deleted}
        if cmd == "rooms":
            return {"ok": True, "rooms": self._list_rooms()}
        return {"ok": False, "message": "unsupported web command"}

    def _handle_client(self, raw_conn: socket.socket, tls_context: ssl.SSLContext) -> None:
        try:
            conn = tls_context.wrap_socket(raw_conn, server_side=True)
        except ssl.SSLError:
            raw_conn.close()
            return
        stream = conn.makefile("rwb")
        session_id = str(uuid.uuid4())
        try:
            hello = recv_packet(stream)
            if not hello or hello.get("type") != "hello":
                send_packet(stream, {"type": "error", "error": "first packet must be hello"})
                conn.close()
                return
            nickname = str(hello.get("nickname", "")).strip()
            if not nickname:
                send_packet(stream, {"type": "error", "error": "nickname required"})
                conn.close()
                return
            room_input = str(hello.get("room", "") or "")
            room_password = str(hello.get("room_password", "") or "")
            room_ok, room_name = self._validate_room(room_input, room_password)
            if not room_ok:
                send_packet(stream, {"type": "error", "error": "room password mismatch"})
                conn.close()
                return

            ip, port = conn.getpeername()[0], int(conn.getpeername()[1])
            session = ClientSession(
                session_id=session_id,
                nickname=nickname,
                ip=ip,
                port=port,
                room=room_name,
                stream=stream,
                conn=conn,
                lock=threading.Lock(),
            )
            with self._lock:
                self._clients[session_id] = session
            self.storage.set_client_online(session_id, nickname, ip, port, room_name)
            send_packet(stream, {"type": "hello_ack", "timestamp": now_text(), "room": room_name})
            self._broadcast(
                {
                    "type": "system",
                    "timestamp": now_text(),
                    "room": room_name,
                    "content": f"{nickname} joined room {room_name}",
                },
                room=room_name,
            )
            self._broadcast({"type": "users_update"}, room=room_name)

            while self._running.is_set():
                packet = recv_packet(stream)
                if not packet:
                    break
                p_type = str(packet.get("type", ""))
                if p_type == "chat":
                    content = str(packet.get("content", "")).strip()
                    if not content:
                        continue
                    msg = self.storage.add_message(session.nickname, session.ip, session.port, session.room, content)
                    self._broadcast({"type": "message", **msg}, room=session.room)
                    continue
                if p_type == "command":
                    command = str(packet.get("command", "")).lower()
                    args = packet.get("args", [])
                    if not isinstance(args, list):
                        args = []
                    if command == "users":
                        send_packet(stream, {"type": "command_result", "command": "users", "users": self.list_online_users(room=session.room)})
                    elif command == "history":
                        raw_limit = int(args[0]) if args else int(self.history_cfg.get("default_limit", 50))
                        history_room = session.room if self.rooms_config.get("room_scoped_history", True) else None
                        send_packet(stream, {"type": "command_result", "command": "history", "history": self.get_history(raw_limit, room=history_room)})
                    elif command == "clear":
                        clear_room = session.room if self.rooms_config.get("room_scoped_clear", True) else None
                        deleted = self.clear_history(room=clear_room)
                        send_packet(stream, {"type": "command_result", "command": "clear", "deleted": deleted})
                        self._broadcast(
                            {
                                "type": "system",
                                "timestamp": now_text(),
                                "room": session.room,
                                "content": f"{session.nickname} cleared history",
                            },
                            room=session.room,
                        )
                    elif command == "rooms":
                        send_packet(stream, {"type": "command_result", "command": "rooms", "rooms": self._list_rooms()})
                    elif command == "join":
                        if not args:
                            send_packet(stream, {"type": "error", "error": "usage: /join <room> [password]"})
                            continue
                        next_room = str(args[0]).strip()
                        next_pwd = str(args[1]) if len(args) > 1 else ""
                        ok, room_name = self._validate_room(next_room, next_pwd)
                        if not ok:
                            send_packet(stream, {"type": "error", "error": "room password mismatch"})
                            continue
                        old_room = session.room
                        session.room = room_name
                        self.storage.update_client_room(session.session_id, room_name)
                        send_packet(stream, {"type": "command_result", "command": "join", "room": room_name})
                        self._broadcast({"type": "users_update"}, room=old_room)
                        self._broadcast({"type": "users_update"}, room=room_name)
                    elif command == "help":
                        send_packet(
                            stream,
                            {
                                "type": "command_result",
                                "command": "help",
                                "commands": ["/help", "/users", "/history [n]", "/clear", "/rooms", "/join <room> [password]", "/quit"],
                            },
                        )
                    elif command == "quit":
                        send_packet(stream, {"type": "bye"})
                        break
                    else:
                        send_packet(stream, {"type": "error", "error": "unsupported command"})
                    continue
                send_packet(stream, {"type": "error", "error": "unsupported packet type"})
        except (OSError, ValueError, ssl.SSLError):
            pass
        finally:
            self._disconnect_session(session_id)
