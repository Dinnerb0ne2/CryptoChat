import os
import sys
import json
import time
import socket
import threading
import hashlib
from datetime import datetime
from typing import Dict, Any

from .crypto import RSA, CryptoManager


class ChatServer:
    def __init__(self, app):  # Accept ChatApplication instance
        self.running = True

        self.app = app
        self.cfg = app.config 
        self.ip = self.cfg["ip"]
        self.port = int(self.cfg["port"])
        self.clients: Dict[Any, dict] = {}  # (ip,port)->client_info
        self.rooms = {}  # For room functionality if enabled
        self.chat_history = []

        # Initialize crypto manager for server
        self.crypto = CryptoManager(self.cfg)

        self.bans = {"ips": set(), "users": set()}
        self.bans_file = "bans.json"

        self._load_bans()
        if self.cfg.get("enable_rooms"):  # enable_rooms is boolean
            self._load_rooms()

        self.admin_cmds = {
            "kick": self._kick,
            "ban": self._ban,
            "unban": self._unban,
            "listbans": self._list_bans,
            "stop": self._stop,
            "help": self._admin_help,
            "save": self._save_history,
        }

        # Start the server
        self.run()

    # Lifecycle management
    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.ip, self.port))
        self.sock.listen(5)
        print(f"Server listening on {self.ip}:{self.port}")

        threading.Thread(target=self._admin_console, daemon=True).start()
         
        # Auto-save functionality
        if self.cfg.get("enable_autosave") == "true":
            threading.Thread(target=self._auto_save, daemon=True).start()

        while True:
            try:
                conn, addr = self.sock.accept()
            except OSError:
                break  
            if len(self.clients) >= int(self.cfg.get("max_users", 20)):
                try:
                    # Send server full message with encryption
                    response = self._encrypt_response({
                        "type": "system", 
                        "message": "Server full"
                    }, None)
                    conn.send(response)
                    conn.close()
                except:
                    pass
                continue
            threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
        print("Server thread exited")

    def _stop(self, _args=None):
        print("Shutting down...")
        self._save_history()  # Save chat history
        self._save_bans()     # Save ban list

        for addr, client in self.clients.items():
            try:
                response = self._encrypt_response({
                    "type": "system", 
                    "message": "Server is shutting down"
                }, client.get("public_key"))
                client["socket"].send(response)
                client["socket"].close()
            except:
                pass
        self.clients.clear()

        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
        except OSError:
            pass
        self.running = False

        os._exit(0)

    def _handle_client(self, sock: socket.socket, addr: Any):
        try:
            # Receive and decrypt hello message
            data = sock.recv(4096)
            hello = self._decrypt_client_data(data, None)  # No client pubkey yet
            
            # Extract client info
            nick = hello.get("nickname", "Unknown").strip() or "Unknown"
            client_pub_key = hello.get("public_key")
            room = hello.get("room") if self.cfg.get("enable_rooms") == "true" else None
            
            # Check bans
            if nick.lower() in self.bans["users"] or addr[0] in self.bans["ips"]:
                response = self._encrypt_response({
                    "type": "system", 
                    "message": "Banned"
                }, client_pub_key)
                sock.send(response)
                sock.close()
                return
            
            # Verify server password if enabled
            if self.cfg.get("enable_password") == "true":
                pwd = hello.get("password", "")
                if not self._verify_server_pwd(pwd):
                    response = self._encrypt_response({
                        "type": "system", 
                        "message": "Wrong password"
                    }, client_pub_key)
                    sock.send(response)
                    sock.close()
                    return
            
            # Send server's public key to client
            server_pub_key = self.crypto.get_public_key_pem()
            sock.send(json.dumps({"server_public_key": server_pub_key}).encode())
            
            # Register client
            self.clients[addr] = {
                "socket": sock, 
                "nickname": nick, 
                "room": room, 
                "last_active": time.time(),
                "public_key": client_pub_key
            }
            
            # Broadcast join message
            self._broadcast({
                "type": "system", 
                "message": f"{nick} joined"
            }, room=room, exclude=addr)
            
            # Send MOTD to client
            motd_msg = self._encrypt_response({
                "type": "system", 
                "message": self._motd(room)
            }, client_pub_key)
            sock.send(motd_msg)

            # Main message handling loop
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                # Decrypt client message
                msg = self._decrypt_client_data(data, client_pub_key)
                self._route_message(addr, msg)
                
        except (ConnectionResetError, json.JSONDecodeError) as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            if addr in self.clients:
                nick = self.clients[addr]["nickname"]
                room = self.clients[addr]["room"]
                del self.clients[addr]
                self._broadcast({
                    "type": "system", 
                    "message": f"{nick} left"
                }, room=room)
                print(f"{nick} disconnected")
            try:
                sock.close()
            except:
                pass

    def _decrypt_client_data(self, data: bytes, client_pub_key: str) -> dict:
        """Decrypt data received from client"""
        return self.crypto.decrypt(data)

    def _encrypt_response(self, data: dict, client_pub_key: str) -> bytes:
        """Encrypt response to send to client"""
        if client_pub_key:
            # Use client's public key if available
            temp_crypto = CryptoManager(self.cfg)
            temp_crypto.set_server_public_key(client_pub_key)
            return temp_crypto.encrypt(data)
        # Fallback to unencrypted for initial handshake
        return json.dumps(data).encode()

    def _route_message(self, addr: Any, msg: dict):
        t = msg["type"]
        client = self.clients[addr]
        if t == "message":
            txt = msg["message"]
            timestamp = time.time()
            
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            room_info = f"[{client['room']}]" if client["room"] else "[public]"
            print(f"{room_info} [{current_time}]\n    {client['nickname']}: {txt}")
            
            pack = {
                "type": "message",
                "nickname": client["nickname"],
                "message": txt,
                "timestamp": timestamp,
                "room": client["room"],
            }
            self.chat_history.append({
                "timestamp": datetime.utcnow().isoformat(),
                "local_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "user": client["nickname"],
                "message": txt,
                "room": client["room"],
            })
            self._broadcast(pack, room=client["room"])

        elif t == "ping":
            sock = client["socket"]
            response = self._encrypt_response({
                "type": "pong", 
                "timestamp": msg["timestamp"]
            }, client["public_key"])
            sock.send(response)
            
        elif t == "online":
            sock = client["socket"]
            response = self._encrypt_response({
                "type": "online",
                "count": len(self.clients),
                "nicknames": [c["nickname"] for c in self.clients.values()],
            }, client["public_key"])
            sock.send(response)

    # ---------- Broadcasting ----------
    def _broadcast(self, msg: dict, room=None, exclude=None):
        """Broadcast message to relevant clients"""
        for addr, c in self.clients.items():
            if exclude and addr == exclude:
                continue
            if room is not None and c["room"] != room:
                continue
            try:
                encrypted_msg = self._encrypt_response(msg, c["public_key"])
                c["socket"].send(encrypted_msg)
            except (BrokenPipeError, OSError):
                pass

    def _admin_console(self):
        print("=== Admin Console ===")
        print("tips: type /help to get help info")
        while self.running:
            try:
                line = input("").strip()
            except (EOFError, KeyboardInterrupt):
                self._stop()
            if line.startswith("/"):
                self._handle_admin(line[1:])
            elif line:
                pack = {
                    "type": "message",
                    "nickname": "Admin",
                    "message": line,
                    "timestamp": time.time(),
                    "room": None,
                }
                self._broadcast(pack)

    def _handle_admin(self, cmd: str):
        parts = cmd.split()
        if not parts:
            return
        c = parts[0].lower()
        if c in self.admin_cmds:
            self.admin_cmds[c](parts[1:])
        else:
            print("Unknown command")

    def _kick(self, args):
        if not args:
            print("Usage: /kick <nickname>")
            return
        nick = " ".join(args)
        for addr, c in list(self.clients.items()):
            if c["nickname"].lower() == nick.lower():
                try:
                    response = self._encrypt_response({
                        "type": "system", 
                        "message": "Kicked by admin"
                    }, c["public_key"])
                    c["socket"].send(response)
                    c["socket"].close()
                except:
                    pass
                del self.clients[addr]
                print(f"Kicked {nick}")
                return
        print("User not found")

    def _ban(self, args):
        if not args:
            print("Usage: /ban <nickname|ip>")
            return
        target = " ".join(args)

        found = False
        for addr, c in list(self.clients.items()):
            if c["nickname"].lower() == target.lower():
                self.bans["users"].add(c["nickname"].lower())
                # Kick the user
                try:
                    response = self._encrypt_response({
                        "type": "system", 
                        "message": "Banned by admin"
                    }, c["public_key"])
                    c["socket"].send(response)
                    c["socket"].close()
                except:
                    pass
                del self.clients[addr]
                found = True
                print(f"Banned user {target}")
                break
        if not found:
            self.bans["ips"].add(target)
            print(f"Banned IP {target}")
        self._save_bans()

    def _unban(self, args):
        if not args:
            print("Usage: /unban <nickname|ip>")
            return
        target = " ".join(args)
        if target.lower() in self.bans["users"]:
            self.bans["users"].remove(target.lower())
            print(f"Unbanned user {target}")
        elif target in self.bans["ips"]:
            self.bans["ips"].remove(target)
            print(f"Unbanned IP {target}")
        else:
            print("Not found in ban list")
        self._save_bans()

    def _list_bans(self, _args):
        print("Banned users:", sorted(self.bans["users"]))
        print("Banned IPs:", sorted(self.bans["ips"]))

    def _admin_help(self, _args):
        print("/kick <nick>  /ban <nick|ip>  /unban <nick|ip>  /listbans  /save  /stop  /help")

    # ---------- Persistence ----------
    def _load_bans(self):
        if os.path.exists(self.bans_file):
            try:
                with open(self.bans_file, encoding="utf-8") as f:
                    b = json.load(f)
                    self.bans = {
                        "ips": set(b.get("ips", [])), 
                        "users": set(b.get("users", []))
                    }
            except Exception as e:
                print("Load bans error:", e)

    def _save_bans(self):
        try:
            with open(self.bans_file, "w", encoding="utf-8") as f:
                json.dump({
                    "ips": list(self.bans["ips"]), 
                    "users": list(self.bans["users"])
                }, f, indent=2)
        except Exception as e:
            print("Save bans error:", e)

    def _load_rooms(self):
        pass

    def _motd(self, room=None):
        return self.cfg.get("motd", "Welcome")

    def _verify_server_pwd(self, pwd: str) -> bool:
        if not self.cfg.get("enable_password") == "true":
            return True
        if os.path.exists("password.hash"):
            with open("password.hash", encoding="utf-8") as f:
                h = f.read().strip()
            return h == hashlib.sha256(pwd.encode()).hexdigest()
        if os.path.exists("password.txt"):
            with open("password.txt", encoding="utf-8") as f:
                return f.read().strip() == pwd
        return True

    def _save_history(self, _args=None):
        if not self.chat_history:
            print("No history")
            return
        fname = f"server_history_{int(time.time())}.txt"
        with open(fname, "w", encoding="utf-8") as f:
            for item in self.chat_history:
                f.write(f"[{item['local_time']}] {item['user']}: {item['message']}\n")
        print(f"Saved -> {fname}")

    def _auto_save(self):
        delay = int(self.cfg.get("autosave_delay", 300))
        while True:
            time.sleep(delay)
            self._save_history()