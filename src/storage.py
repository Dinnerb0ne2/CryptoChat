from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any

from .utils import now_epoch, now_text


class ChatStorage:
    def __init__(self, db_path: str) -> None:
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self.init_db()

    def close(self) -> None:
        self._conn.close()

    def init_db(self) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_text TEXT NOT NULL,
                    timestamp_epoch REAL NOT NULL,
                    nickname TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    room TEXT NOT NULL,
                    content TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS clients (
                    session_id TEXT PRIMARY KEY,
                    nickname TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    room TEXT NOT NULL,
                    connected_at TEXT NOT NULL,
                    disconnected_at TEXT,
                    is_online INTEGER NOT NULL
                )
                """
            )

    def add_message(self, nickname: str, ip: str, port: int, room: str, content: str) -> dict[str, Any]:
        ts_text = now_text()
        ts_epoch = now_epoch()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO messages (timestamp_text, timestamp_epoch, nickname, ip, port, room, content)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (ts_text, ts_epoch, nickname, ip, port, room, content),
            )
        return {
            "timestamp": ts_text,
            "nickname": nickname,
            "ip": ip,
            "port": port,
            "room": room,
            "content": content,
        }

    def set_client_online(self, session_id: str, nickname: str, ip: str, port: int, room: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO clients (session_id, nickname, ip, port, room, connected_at, disconnected_at, is_online)
                VALUES (?, ?, ?, ?, ?, ?, NULL, 1)
                ON CONFLICT(session_id) DO UPDATE SET
                    nickname=excluded.nickname,
                    ip=excluded.ip,
                    port=excluded.port,
                    room=excluded.room,
                    connected_at=excluded.connected_at,
                    disconnected_at=NULL,
                    is_online=1
                """,
                (session_id, nickname, ip, port, room, now_text()),
            )

    def update_client_room(self, session_id: str, room: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE clients SET room = ? WHERE session_id = ?", (room, session_id))

    def set_client_offline(self, session_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE clients SET is_online = 0, disconnected_at = ? WHERE session_id = ?",
                (now_text(), session_id),
            )

    def list_online_users(self, room: str | None = None) -> list[dict[str, Any]]:
        query = """
            SELECT nickname, ip, port, room, connected_at
            FROM clients
            WHERE is_online = 1
        """
        params: tuple[Any, ...] = ()
        if room:
            query += " AND room = ?"
            params = (room,)
        query += " ORDER BY connected_at ASC"
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_history(self, limit: int, room: str | None = None) -> list[dict[str, Any]]:
        query = """
            SELECT timestamp_text AS timestamp, nickname, ip, port, room, content
            FROM messages
        """
        params: list[Any] = []
        if room:
            query += " WHERE room = ?"
            params.append(room)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()
        out = [dict(row) for row in rows]
        out.reverse()
        return out

    def clear_history(self, room: str | None = None) -> int:
        with self._lock, self._conn:
            if room:
                cur = self._conn.execute("DELETE FROM messages WHERE room = ?", (room,))
            else:
                cur = self._conn.execute("DELETE FROM messages")
        return cur.rowcount
