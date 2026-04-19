from __future__ import annotations

import argparse
import socket
import ssl
import threading
from typing import Any, BinaryIO

from .protocol import recv_packet, send_packet


def parse_slash_command(line: str) -> tuple[str, list[str]] | None:
    if not line.startswith("/"):
        return None
    parts = line[1:].strip().split()
    if not parts:
        return None
    return parts[0].lower(), parts[1:]


class ChatClient:
    def __init__(self, config: dict[str, Any], nickname: str, room: str = "", room_password: str = "") -> None:
        self.config = config
        self.nickname = nickname
        self.room = room
        self.room_password = room_password
        self._stop = threading.Event()
        self._stream: BinaryIO | None = None
        self._conn: ssl.SSLSocket | None = None
        self._write_lock = threading.Lock()

    def _create_client_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        client_cfg = self.config["client"]
        if not bool(client_cfg.get("cert_verify", False)):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ca_file = str(client_cfg.get("ca_file", ""))
            if ca_file:
                ctx.load_verify_locations(cafile=ca_file)
        return ctx

    def _print_message(self, payload: dict[str, Any]) -> None:
        ts = payload.get("timestamp", "")
        room = payload.get("room", "")
        nick = payload.get("nickname", "")
        ip = payload.get("ip", "")
        port = payload.get("port", "")
        content = payload.get("content", "")
        print(f"[{ts}][{room}][{nick} {ip}:{port}] {content}")

    def _print_system(self, payload: dict[str, Any]) -> None:
        print(f"[{payload.get('timestamp', '')}][SYSTEM] {payload.get('content', '')}")

    def _send(self, payload: dict[str, Any]) -> None:
        if not self._stream:
            return
        with self._write_lock:
            send_packet(self._stream, payload)

    def _recv_loop(self) -> None:
        assert self._stream is not None
        while not self._stop.is_set():
            try:
                packet = recv_packet(self._stream)
            except (OSError, ValueError):
                break
            if not packet:
                break
            p_type = str(packet.get("type", ""))
            if p_type == "message":
                self._print_message(packet)
            elif p_type == "system":
                self._print_system(packet)
            elif p_type == "hello_ack":
                print(f"Connected to room: {packet.get('room', '')}")
            elif p_type == "command_result":
                self._print_command_result(packet)
            elif p_type == "error":
                print(f"[ERROR] {packet.get('error', '')}")
            elif p_type == "bye":
                print("Disconnected by server.")
                self._stop.set()
                break
        self._stop.set()

    def _print_command_result(self, packet: dict[str, Any]) -> None:
        command = packet.get("command")
        if command == "users":
            users = packet.get("users", [])
            print("Online users:")
            for user in users:
                print(
                    f"  - {user['nickname']} {user['ip']}:{user['port']} "
                    f"room={user['room']} since={user['connected_at']}"
                )
            return
        if command == "history":
            history = packet.get("history", [])
            print("History:")
            for item in history:
                self._print_message(item)
            return
        if command == "clear":
            print(f"Deleted {packet.get('deleted', 0)} messages.")
            return
        if command == "rooms":
            print("Rooms: " + ", ".join(packet.get("rooms", [])))
            return
        if command == "join":
            self.room = str(packet.get("room", self.room))
            print(f"Switched room to: {self.room}")
            return
        if command == "help":
            print("Commands:")
            for cmd in packet.get("commands", []):
                print(f"  {cmd}")

    def run(self) -> int:
        ctx = self._create_client_context()
        host = self.config["client"]["server_host"]
        port = int(self.config["client"]["server_port"])
        with socket.create_connection((host, port)) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as conn:
                self._conn = conn
                self._stream = conn.makefile("rwb")
                self._send(
                    {
                        "type": "hello",
                        "nickname": self.nickname,
                        "room": self.room,
                        "room_password": self.room_password,
                    }
                )
                recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
                recv_thread.start()
                print("Type /help to show commands.")
                while not self._stop.is_set():
                    try:
                        line = input("> ").strip()
                    except (EOFError, KeyboardInterrupt):
                        line = "/quit"
                    if not line:
                        continue
                    command = parse_slash_command(line)
                    if command is None:
                        self._send({"type": "chat", "content": line})
                        continue
                    cmd, args = command
                    if cmd == "quit":
                        self._send({"type": "command", "command": "quit", "args": []})
                        self._stop.set()
                        break
                    if cmd == "help":
                        print("/help /users /history [n] /clear /rooms /join <room> [password] /quit")
                        self._send({"type": "command", "command": "help", "args": []})
                        continue
                    self._send({"type": "command", "command": cmd, "args": args})
                recv_thread.join(timeout=2)
        return 0


def add_client_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--nickname", required=False, help="nickname")
    parser.add_argument("--room", default="", help="room name")
    parser.add_argument("--room-password", default="", help="room password")
