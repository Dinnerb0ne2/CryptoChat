import os
import sys
import json
import time
import socket
import threading
import hashlib
from datetime import datetime
from typing import Dict, Any

from .crypto import RSA

class ChatServer:
    def init(self, config: dict):
        self.cfg = config
        self.ip = config["ip"]
        self.port = int(config["port"])
        self.clients: Dict[Any, dict] = {}  # (ip,port)->dict
        self.bans = {"ips": set(), "users": set()}
        self.bans_file = "bans.json"
        self.rooms = {}  # 若启用
        self.chat_history = []
            
        self._load_bans()
        if config.get("enable_rooms") == "true":
            self._load_rooms()

        # 管理员命令
        self.admin_cmds = {
            "kick": self._kick,
            "ban": self._ban,
            "unban": self._unban,
            "listbans": self._list_bans,
            "stop": self._stop,
            "help": self._admin_help,
            "save": self._save_history,
        }

        # 启动
        self.run()

    # life cycle
    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.ip, self.port))
        self.sock.listen(5)
        print(f"Server listening {self.ip}:{self.port}")

        threading.Thread(target=self._admin_console, daemon=True).start()
         
        # auto save
        if self.cfg.get("enable_autosave") == "true":
            threading.Thread(target=self._auto_save, daemon=True).start()

        while True:
            try:
                conn, addr = self.sock.accept()
            except OSError:
                break  
            if len(self.clients) >= int(self.cfg.get("max_users", 20)):
                try:
                    conn.send(json.dumps({"type": "system", "message": "Server full"}).encode())
                    conn.close()
                except:
                    pass
                continue
            threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
        print("Server thread exit")

    def _stop(self, _args=None):
        print("Shutting down...")
        self._save_history()
        self._save_bans()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
        except:
            pass
        sys.exit(0)

    def _handle_client(self, sock: socket.socket, addr: Any):
        try:
            data = sock.recv(4096)
            hello = json.loads(data.decode())
            nick = hello.get("nickname", "Unknown").strip() or "Unknown"
            room = hello.get("room") if self.cfg.get("enable_rooms") == "true" else None
            # ban
            if nick.lower() in self.bans["users"] or addr[0] in self.bans["ips"]:
                sock.send(json.dumps({"type": "system", "message": "Banned"}).encode())
                sock.close()
                return
            # pwd
            if self.cfg.get("enable_password") == "true":
                pwd = hello.get("password", "")
                if not self._verify_server_pwd(pwd):
                    sock.send(json.dumps({"type": "system", "message": "Wrong password"}).encode())
                    sock.close()
                    return
            # 登记
            self.clients[addr] = {"socket": sock, "nickname": nick, "room": room, "last": time.time()}
            self._broadcast({"type": "system", "message": f"{nick} joined"}, room=room, exclude=addr)
            sock.send(json.dumps({"type": "system", "message": self._motd(room)}).encode())

            # main
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                msg = json.loads(data.decode())
                self._route_message(addr, msg)
        except (ConnectionResetError, json.JSONDecodeError):
            pass
        finally:
            if addr in self.clients:
                nick = self.clients[addr]["nickname"]
                room = self.clients[addr]["room"]
                del self.clients[addr]
                self._broadcast({"type": "system", "message": f"{nick} left"}, room=room)
                print(f"{nick} disconnected")
            try:
                sock.close()
            except:
                pass

    def _route_message(self, addr: Any, msg: dict):
        t = msg["type"]
        client = self.clients[addr]
        if t == "message":
            txt = msg["message"]
            pack = {
                "type": "message",
                "nickname": client["nickname"],
                "message": txt,
                "timestamp": time.time(),
                "room": client["room"],
            }
            self.chat_history.append(
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "local_time": datetime.now().strftime("%m/%d %H:%M:%S"),
                    "user": client["nickname"],
                    "message": txt,
                    "room": client["room"],
                }
            )
            self._broadcast(pack, room=client["room"])
        elif t == "ping":
            sock = client["socket"]
            sock.send(json.dumps({"type": "pong", "timestamp": msg["timestamp"]}).encode())
        elif t == "online":
            sock = client["socket"]
            sock.send(
                json.dumps(
                    {
                        "type": "online",
                        "count": len(self.clients),
                        "nicknames": [c["nickname"] for c in self.clients.values()],
                    }
                ).encode()
            )

    # ---------- 广播 ----------
    def _broadcast(self, msg: dict, room=None, exclude=None):
        payload = json.dumps(msg)
        for addr, c in self.clients.items():
            if exclude and addr == exclude:
                continue
            if room is not None and c["room"] != room:
                continue
            try:
                c["socket"].send(payload.encode())
            except (BrokenPipeError, OSError):
                pass

    # ---------- 管理员 ----------
    def _admin_console(self):
        print("=== Admin Console ===  /help")
        while True:
            try:
                line = input("admin> ").strip()
            except (EOFError, KeyboardInterrupt):
                self._stop()
            if line.startswith("/"):
                self._handle_admin(line[1:])
            elif line:
                # 管理员聊天
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
                    c["socket"].send(json.dumps({"type": "system", "message": "Kicked by admin"}).encode())
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
                # kick
                try:
                    c["socket"].send(json.dumps({"type": "system", "message": "Banned by admin"}).encode())
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

    # ---------- 持久化 ----------
    def _load_bans(self):
        if os.path.exists(self.bans_file):
            try:
                with open(self.bans_file, encoding="utf-8") as f:
                    b = json.load(f)
                    self.bans = {"ips": set(b.get("ips", [])), "users": set(b.get("users", []))}
            except Exception as e:
                print("Load bans error:", e)

    def _save_bans(self):
        try:
            with open(self.bans_file, "w", encoding="utf-8") as f:
                json.dump({"ips": list(self.bans["ips"]), "users": list(self.bans["users"])}, f, indent=2)
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