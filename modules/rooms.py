# rooms.py
import os
import json
import hashlib
import threading
from typing import Dict, Set, Optional, List

class RoomError(Exception):
    pass

class RoomManager:
    def __init__(self, cfg_dir: str, enable_hash: bool = False):
        self.cfg_dir = os.path.abspath(cfg_dir)
        self.enable_hash = enable_hash
        os.makedirs(self.cfg_dir, exist_ok=True)

        # In-memory structure {room_name: _Room}
        self._rooms: Dict[str, "_Room"] = {}
        self._lock = threading.RLock()

        self._load_all_rooms()

    # Public API
    def list_rooms(self) -> List[str]:
        with self._lock:
            return sorted(self._rooms.keys())

    def room_exist(self, name: str) -> bool:
        #　Check if a room exists
        with self._lock:
            return name in self._rooms

    def join_room(self, room: str, nick: str, ip: str, password: str = "") -> None:
        """
        Join a room with nickname and IP
        Raises RoomError if banned or wrong password
        """
        with self._lock:
            r = self._get_room(room)
            if r.is_banned(nick, ip):
                raise RoomError("You are banned")
            if not r.check_password(password, self.enable_hash):
                raise RoomError("Incorrect room password")
            r.members.add(nick)

    def leave_room(self, room: str, nick: str) -> None:
        # Remove a user from a room
        with self._lock:
            r = self._rooms.get(room)
            if r:
                r.members.discard(nick)

    def broadcast_packet(self, room: Optional[str], packet: dict, curr_members: Set[str]):
        """
        For server use only:
        If room is None -> broadcast globally
        Otherwise send only to room members (nick must be in curr_members)
        Returns list of sockets to send to
        """
        with self._lock:
            if room is None:
                # Global broadcast
                return [c["socket"] for c in curr_members]
            r = self._rooms.get(room)
            if not r:
                return []
            return [c["socket"] for c in curr_members if c["nickname"] in r.members]

    def ban(self, room: str, *, nick: Optional[str] = None, ip: Optional[str] = None) -> None:
        """Room-level ban, specify at least nick or ip"""
        if not nick and not ip:
            raise RoomError("Must specify either nick or ip")
        with self._lock:
            r = self._get_room(room)
            if nick:
                r.ban_nicks.add(nick.lower())
            if ip:
                r.ban_ips.add(ip)
            r.save_bans()

    def unban(self, room: str, *, nick: Optional[str] = None, ip: Optional[str] = None) -> None:
        """Remove ban for a user or IP in a room"""
        with self._lock:
            r = self._get_room(room)
            if nick and nick.lower() in r.ban_nicks:
                r.ban_nicks.remove(nick.lower())
            if ip and ip in r.ban_ips:
                r.ban_ips.remove(ip)
            r.save_bans()

    def set_password(self, room: str, new_pwd: str) -> None:
        """Set room password (auto-hashes if enabled)"""
        with self._lock:
            r = self._get_room(room)
            if self.enable_hash:
                r.password_hash = hashlib.sha256(new_pwd.encode()).hexdigest()
                r.password = ""  # Clear plaintext
            else:
                r.password = new_pwd
                r.password_hash = ""
            r.save_config()

    # -------------------- Internal methods --------------------
    def _get_room(self, name: str) -> "_Room":
        """Get room by name or raise RoomError if not exists"""
        r = self._rooms.get(name)
        if not r:
            raise RoomError("Room does not exist")
        return r

    def _load_all_rooms(self) -> None:
        """Load all rooms from *.cfg files in cfg_dir on startup"""
        for fname in os.listdir(self.cfg_dir):
            if not fname.endswith(".cfg"):
                continue
            path = os.path.join(self.cfg_dir, fname)
            try:
                with open(path, encoding="utf-8") as f:
                    cfg = dict(line.strip().split("=", 1) for line in f if "=" in line)
                name = cfg["name"]
                r = _Room(
                    name=name,
                    motd=cfg.get("motd", ""),
                    password=cfg.get("password", ""),
                    password_hash=cfg.get("password_hash", ""),
                    cfg_dir=self.cfg_dir,
                )
                # Load bans for this room
                r.load_bans()
                self._rooms[name] = r
            except Exception as e:
                print(f"[RoomManager] Skipping invalid config {fname}: {e}")


class _Room:
    """Internal room representation"""
    def __init__(
        self,
        name: str,
        motd: str = "",
        password: str = "",
        password_hash: str = "",
        cfg_dir: str = "",
    ):
        self.name = name
        self.motd = motd
        self.password = password
        self.password_hash = password_hash
        self.cfg_dir = cfg_dir

        self.members: Set[str] = set()
        
        self.ban_nicks: Set[str] = set()
        self.ban_ips: Set[str] = set()

    def is_banned(self, nick: str, ip: str) -> bool:
        """Check if a user (by nick or IP) is banned from this room"""
        return nick.lower() in self.ban_nicks or ip in self.ban_ips

    def save_bans(self) -> None:
        """Save ban list to file"""
        path = os.path.join(self.cfg_dir, f"{self.name}_bans.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"nicks": list(self.ban_nicks), "ips": list(self.ban_ips)}, f, indent=2)

    def load_bans(self) -> None:
        """Load ban list from file"""
        path = os.path.join(self.cfg_dir, f"{self.name}_bans.json")
        if not os.path.exists(path):
            return
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
            self.ban_nicks = set(data.get("nicks", []))
            self.ban_ips = set(data.get("ips", []))

    def check_password(self, pwd: str, enable_hash: bool) -> bool:
        """Check if password is correct (empty password means no authentication)"""
        if enable_hash:
            if not self.password_hash:
                return True
            return hashlib.sha256(pwd.encode()).hexdigest() == self.password_hash
        else:
            return self.password == pwd or self.password == ""

    def save_config(self) -> None:
        """Save room configuration to file"""
        path = os.path.join(self.cfg_dir, f"{self.name}.cfg")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"name={self.name}\n")
            f.write(f"motd={self.motd}\n")
            if self.password_hash:
                f.write(f"password_hash={self.password_hash}\n")
            else:
                f.write(f"password={self.password}\n")