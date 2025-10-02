import os
import sys
import json
import time
import shutil
import socket
import threading
import hashlib
from datetime import datetime
from typing import Dict, Any

from .crypto import CryptoManager


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

        self.client_keys_dir = self.cfg["client_keys_dir"]  # Directory to store client public keys
        os.makedirs(self.client_keys_dir, exist_ok=True)  # Ensure the directory exists

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

        if os.path.exists(self.client_keys_dir):
            try:
                shutil.rmtree(self.client_keys_dir)
                print(f"Deleted client keys directory: {self.client_keys_dir}")
            except Exception as e:
                print(f"Failed in cleaning client public keys: {e}")

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
            print(f"Connection from {addr}")
            # hello
            data = sock.recv(4096)
            if not data:
                raise ConnectionAbortedError("")
            
            hello = self._decrypt_client_data(data, None)

            # client info
            nick = hello.get("nickname", "Unknown").strip() or "Unknown"
            client_pub_key = hello.get("public_key")
            room = hello.get("room") if self.cfg.get("enable_rooms") == "true" else None
            
            if client_pub_key:
                timestamp = int(time.time())
                key_filename = f"{addr[0]}_{addr[1]}_{timestamp}.pem"
                key_filepath = os.path.join(self.client_keys_dir, key_filename)
                with open(key_filepath, "w", encoding="utf-8") as key_file:
                    key_file.write(client_pub_key)

            if nick.lower() in self.bans["users"] or addr[0] in self.bans["ips"]:
                response = self._encrypt_response({
                    "type": "system", 
                    "message": "Banned"
                }, client_pub_key)
                sock.send(response)
                sock.close()
                return
            
            # Password verification
            if self.cfg.get("enable_password") == "true":
                pwd = hello.get("password", "")
                if not self._verify_server_pwd(pwd):
                    response = self._encrypt_response({
                        "type": "system", 
                        "message": "Incorrect password"
                    }, client_pub_key)
                    sock.send(response)
                    sock.close()
                    return
            
            # Send server public key
            server_pub_key = self.crypto.get_public_key_pem()
            sock.send(json.dumps({"server_public_key": server_pub_key}).encode())
            
            # Register client info
            self.clients[addr] = {
                "socket": sock, 
                "nickname": nick, 
                "room": room, 
                "last_active": time.time(),
                "public_key": client_pub_key
            }
            
            # Broadcast user join message
            self._broadcast({
                "type": "system", 
                "message": f"{nick} has joined the chat"
            }, room=room, exclude=addr)
            
            # Send welcome message (MOTD)
            motd_msg = self._encrypt_response({
                "type": "system", 
                "message": self._motd(room)
            }, client_pub_key)
            sock.send(motd_msg)
            
            while True:
                data = sock.recv(4096)
                if not data:
                    break  # Client disconnected
                
                # Update last active time
                self.clients[addr]["last_active"] = time.time()
                
                # Decrypt client message and route handling
                msg = self._decrypt_client_data(data, client_pub_key)
                self._route_message(addr, msg)
                
        except ConnectionResetError:
            print(f"Client {addr} forcibly disconnected")
        except json.JSONDecodeError:
            print(f"Client {addr} sent invalid JSON data")
        except Exception as e:
            print(f"Error while handling client {addr}: {str(e)}")
        finally:
            # Clean up client connection
            if addr in self.clients:
                nick = self.clients[addr]["nickname"]
                room = self.clients[addr]["room"]
                del self.clients[addr]
                
                # Broadcast user leave message
                self._broadcast({
                    "type": "system", 
                    "message": f"{nick} has left the chat"
                }, room=room)
                print(f"{nick} has disconnected")
            
            # Ensure socket is closed
            try:
                sock.close()
            except Exception as e:
                print(f"Error while closing client socket: {str(e)}")

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
            # Get list of online users in the same room
            room = client["room"]
            online_nicks = [
                c["nickname"] for addr, c in self.clients.items()
                if c["room"] == room
            ]
            response = self._encrypt_response({
                "type": "online",
                "nicknames": online_nicks,
                "count": len(online_nicks)
            }, client["public_key"])
            sock.send(response)
            
        elif t == "join" and self.cfg.get("enable_rooms"):
            target_room = msg.get("room")
            room_pwd = msg.get("room_password", "")
            
            # Validate room exists or create if allowed
            if target_room not in self.rooms:
                # Check if room creation is allowed (configurable)
                if not self.cfg.get("allow_room_creation", True):
                    response = self._encrypt_response({
                        "type": "system",
                        "message": "Room creation not allowed"
                    }, client["public_key"])
                    sock.send(response)
                    return
                # Create new room
                self.rooms[target_room] = _Room(
                    name=target_room,
                    cfg_dir=self.room_config_dir
                )
                self.rooms[target_room].load_bans()
            
            room_obj = self.rooms[target_room]
            
            # Check room bans
            if room_obj.is_banned(client["nickname"], addr[0]):
                response = self._encrypt_response({
                    "type": "system",
                    "message": f"Banned from room {target_room}"
                }, client["public_key"])
                sock.send(response)
                return
            
            # Verify room password
            if not room_obj.check_password(room_pwd, self.cfg.get("enable_hash")):
                response = self._encrypt_response({
                    "type": "system",
                    "message": "Incorrect room password"
                }, client["public_key"])
                sock.send(response)
                return
            
            # Update client's room
            old_room = client["room"]
            client["room"] = target_room
            
            # Broadcast room change
            if old_room:
                self._broadcast({
                    "type": "system",
                    "message": f"{client['nickname']} left the room"
                }, room=old_room, exclude=addr)
            
            self._broadcast({
                "type": "system",
                "message": f"{client['nickname']} joined the room"
            }, room=target_room, exclude=addr)
            
            # Send room join confirmation
            response = self._encrypt_response({
                "type": "join",
                "room": target_room,
                "message": f"Successfully joined {target_room}"
            }, client["public_key"])
            sock.send(response)
            
        elif t == "rooms" and self.cfg.get("enable_rooms"):
            # List available rooms
            room_list = list(self.rooms.keys())
            response = self._encrypt_response({
                "type": "system",
                "message": f"Rooms: {', '.join(room_list) or 'None'}"
            }, client["public_key"])
            sock.send(response)

    # Broadcast functionality
    def _broadcast(self, data: dict, room: str = None, exclude: Any = None):
        """Broadcast message to relevant clients"""
        encrypted_data_map = {}  # Cache encrypted messages per public key
        
        for addr, client in self.clients.items():
            if addr == exclude:
                continue
                
            # Check room filter
            if room is not None and client["room"] != room:
                continue
                
            # Get pre-encrypted data or encrypt once per public key
            pub_key = client["public_key"]
            if pub_key not in encrypted_data_map:
                encrypted_data_map[pub_key] = self._encrypt_response(data, pub_key)
                
            # Send message
            try:
                client["socket"].send(encrypted_data_map[pub_key])
            except Exception as e:
                print(f"Failed to broadcast to {addr}: {str(e)}")

    # Admin console
    def _admin_console(self):
        """Handle admin commands from server console"""
        while self.running:
            try:
                cmd = input("Admin> ").strip()
                if not cmd:
                    continue
                parts = cmd.split()
                cmd_name = parts[0].lower()
                if cmd_name in self.admin_cmds:
                    self.admin_cmds[cmd_name](parts[1:])
                else:
                    print("Unknown command. Type 'help' for list.")
            except (KeyboardInterrupt, EOFError):
                self._stop()
                break

    # Admin command handlers
    def _kick(self, args):
        if not args:
            print("Usage: kick <nickname>")
            return
        target_nick = args[0].lower()
        for addr, client in self.clients.items():
            if client["nickname"].lower() == target_nick:
                try:
                    response = self._encrypt_response({
                        "type": "system",
                        "message": "You have been kicked"
                    }, client["public_key"])
                    client["socket"].send(response)
                    client["socket"].close()
                    print(f"Kicked {target_nick}")
                except:
                    pass
                return
        print(f"User {target_nick} not found")

    def _ban(self, args):
        if len(args) < 2 or args[0] not in ["user", "ip"]:
            print("Usage: ban <user|ip> <target>")
            return
        target_type, target = args[0], args[1].lower()
        if target_type == "user":
            self.bans["users"].add(target)
            print(f"Banned user {target}")
        elif target_type == "ip":
            self.bans["ips"].add(target)
            print(f"Banned IP {target}")
        self._save_bans()

    def _unban(self, args):
        if len(args) < 2 or args[0] not in ["user", "ip"]:
            print("Usage: unban <user|ip> <target>")
            return
        target_type, target = args[0], args[1].lower()
        if target_type == "user" and target in self.bans["users"]:
            self.bans["users"].remove(target)
            print(f"Unbanned user {target}")
        elif target_type == "ip" and target in self.bans["ips"]:
            self.bans["ips"].remove(target)
            print(f"Unbanned IP {target}")
        self._save_bans()

    def _list_bans(self, _args=None):
        print("Banned users:", ", ".join(self.bans["users"]) or "None")
        print("Banned IPs:", ", ".join(self.bans["ips"]) or "None")

    def _admin_help(self, _args=None):
        print("Admin commands:", ", ".join(self.admin_cmds.keys()))

    # Persistence
    def _load_bans(self):
        if os.path.exists(self.bans_file):
            try:
                with open(self.bans_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.bans["ips"] = set(data.get("ips", []))
                    self.bans["users"] = set(data.get("users", []))
            except Exception as e:
                print(f"Error loading bans: {e}")

    def _save_bans(self):
        try:
            with open(self.bans_file, "w", encoding="utf-8") as f:
                json.dump({
                    "ips": list(self.bans["ips"]),
                    "users": list(self.bans["users"])
                }, f, indent=2)
        except Exception as e:
            print(f"Error saving bans: {e}")

    def _load_rooms(self):
        """Load rooms from configuration directory"""
        if not os.path.exists(self.room_config_dir):
            os.makedirs(self.room_config_dir)
            return
            
        for filename in os.listdir(self.room_config_dir):
            if filename.endswith(".cfg"):
                room_name = filename[:-4]
                room = _Room(
                    name=room_name,
                    cfg_dir=self.room_config_dir
                )
                # Load room config
                with open(os.path.join(self.room_config_dir, filename), "r", encoding="utf-8") as f:
                    for line in f:
                        if "=" in line:
                            key, value = line.strip().split("=", 1)
                            if key == "motd":
                                room.motd = value
                            elif key == "password":
                                room.password = value
                            elif key == "password_hash":
                                room.password_hash = value
                room.load_bans()
                self.rooms[room_name] = room

    def _save_history(self, _args=None):
        """Save chat history to file"""
        if not self.chat_history:
            print("No history to save")
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"chat_history_{timestamp}.json"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(self.chat_history, f, indent=2)
            print(f"History saved to {filename}")
        except Exception as e:
            print(f"Error saving history: {e}")

    def _auto_save(self):
        """Auto-save chat history at intervals"""
        delay = int(self.cfg.get("autosave_delay", 300))
        while self.running:
            time.sleep(delay)
            if self.running:  # Check again after sleep
                self._save_history()

    def _motd(self, room: str = None) -> str:
        """Get Message of the Day"""
        if room and self.cfg.get("enable_rooms") and room in self.rooms:
            return self.rooms[room].motd or self.cfg.get("motd", "Welcome!")
        return self.cfg.get("motd", "Welcome to the chat!")

    def _verify_server_pwd(self, pwd: str) -> bool:
        """Verify server password"""
        if not self.cfg.get("server_password_hash"):
            return True  # No password set
        if self.cfg.get("enable_hash"):
            return hashlib.sha256(pwd.encode()).hexdigest() == self.cfg["server_password_hash"]
        return pwd == self.cfg.get("server_password", "")
