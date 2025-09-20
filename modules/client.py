# client.py
import os
import sys
import json
import time
import socket
import threading
from datetime import datetime
from typing import Optional

from .crypto import CryptoManager


class ChatClient:
    def __init__(self, config: dict):
        self.config = config
        self.host = config["ip"]
        self.port = int(config["port"])
        self.nickname = config["nickname"]
        self.room: Optional[str] = None

        self._init_crypto()
        self.running = True

        self.chat_history = []

        self._init_webui()

        # Start chat!
        self.run()

    # Initialization
    def _init_crypto(self):
        # Initialize crypto manager
        self.crypto = CryptoManager(self.config)

    def run(self):
        print(f"Connecting to {self.host}:{self.port}")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((self.host, self.port))
        except ConnectionRefusedError:
            print("Server unreachable")
            sys.exit(1)

        # TCP handshake packet
        password = input("Server password (blank if none): ") if self.config.get("enable_password") == "true" else ""
        room_pwd = ""
        if self.config.get("enable_rooms") == "true" and self.room:
            room_pwd = input(f"Password for room {self.room} (blank if none): ")

        # Prepare hello message with encrypted sensitive fields
        hello_data = {
            "nickname": self.nickname,
            "public_key": self.crypto.get_public_key_pem(),
            "room": self.room,
            "password": password,
            "room_password": room_pwd,
        }
        # do not send encrypted hello_data
        self.sock.send(hello_data.encode() if isinstance(hello_data, str) else json.dumps(hello_data).encode())

        # Get server's public key from initial response
        server_response = self.sock.recv(4096)
        server_pub_key = json.loads(server_response.decode()).get("server_public_key")
        if server_pub_key:
            self.crypto.set_server_public_key(server_pub_key)
        else:
            print("Failed to get server public key")
            sys.exit(1)

        threading.Thread(target=self._recv_loop, daemon=True).start()
        self._send_loop()

    def _recv_loop(self):
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    print("\nDisconnected from server")
                    break
                # Decrypt received data
                msg = self.crypto.decrypt(data)
                self._handle_message(msg)
            except (ConnectionResetError, json.JSONDecodeError):
                print("\nConnection lost")
                break
        sys.exit(0)

    def _handle_message(self, msg: dict):
        t = msg["type"]
        if t == "message":
            time_str = datetime.fromtimestamp(msg.get("timestamp", time.time())).strftime("%Y-%m-%d %H:%M:%S")
            formatted = f"{time_str}\n    {msg.get('nickname', 'Unknown')}: {msg.get('message', '')}"
            print(formatted)
            self.chat_history.append(
                {
                    "timestamp": msg.get("timestamp", time.time()),
                    "local_time": time_str,
                    "user": msg.get("nickname", "Unknown"),
                    "message": msg.get("message", ""),
                    "room": msg.get("room", "public"),
                }
            )
        elif t == "system":
            room = msg.get("room", "public")
            print(f"[{room}] [System] {msg['message']}")
        elif t == "pong":
            print(f"Latency: {(time.time()-msg['timestamp'])*1000:.2f}ms")
        elif t == "online":
            print(f"Online: {', '.join(msg['nicknames'])}  (total {msg['count']})")
        elif t == "join":
            self.room = msg["room"]
            print(f"Joined room: {self.room}")
        elif t == "save":
            self._save_history()
            print("Chat history saved")

        if self.config.get('enable_webui'):
            self.web_server.broadcast_to_web(msg)

    def _send_loop(self):
        while self.running:
            try:
                text = input("")
            except (EOFError, KeyboardInterrupt):
                print("\nExit client")
                break
            if text.startswith("/"):
                self._handle_cmd(text[1:])
            else:
                # Encrypt message before sending
                message_data = {
                    "type": "message",
                    "message": text,
                    "timestamp": time.time(),
                    "room": self.room,
                }
                encrypted_msg = self.crypto.encrypt(message_data)
                self.sock.send(encrypted_msg)
        self.sock.close()
        sys.exit(0)

    # Command handling
    def _handle_cmd(self, cmd: str):
        parts = cmd.strip().split()
        if not parts:
            return
        c = parts[0].lower()
        if c == "ping":
            cmd_data = {"type": "ping", "timestamp": time.time()}
            self.sock.send(self.crypto.encrypt(cmd_data))
        elif c == "online":
            cmd_data = {"type": "online"}
            self.sock.send(self.crypto.encrypt(cmd_data))
        elif c == "exit":
            self.sock.close()
            sys.exit(0)
        elif c == "help":
            print("/ping /online /join <room> /rooms /save /exit /help")
        elif c == "join" and len(parts) >= 2:
            room = " ".join(parts[1:])
            pwd = input(f"Password for {room} (blank if none): ")
            cmd_data = {
                "type": "join",
                "room": room,
                "room_password": pwd,
            }
            self.sock.send(self.crypto.encrypt(cmd_data))
        elif c == "rooms":
            cmd_data = {"type": "rooms"}
            self.sock.send(self.crypto.encrypt(cmd_data))
        elif c == "save":
            cmd_data = {"type": "save"}
            self.sock.send(self.crypto.encrypt(cmd_data))
        else:
            print(f"Unknown command: {c}")

    def _save_history(self):
        if not self.chat_history:
            return
        fname = f"client_history_{int(time.time())}.txt"
        with open(fname, "w", encoding="utf-8") as f:
            for item in self.chat_history:
                f.write(f"{item['local_time']}\n    {item['user']}: {item['message']}\n")
        print(f"Saved -> {fname}")

    def _init_webui(self):
        # Check configuration validity
        if not self.config.get('enable_console') and not self.config.get('enable_webui'):
            raise ValueError("enable_console and enable_webui cannot both be false")
        
        # Start WebUI service if enabled
        if self.config.get('enable_webui'):
            from .web import ChatWebServer
            self.web_server = ChatWebServer(
                self, 
                port=int(self.config.get('webui_port', 25567))
            )