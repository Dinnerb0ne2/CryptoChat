from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class ClientSession:
    session_id: str
    username: str
    last_heartbeat: datetime = field(default_factory=lambda: datetime.now(UTC))

    def heartbeat(self) -> None:
        self.last_heartbeat = datetime.now(UTC)


class SessionManager:
    def __init__(self) -> None:
        self._sessions: dict[str, ClientSession] = {}
        self._lock = asyncio.Lock()

    async def put(self, session: ClientSession) -> None:
        async with self._lock:
            self._sessions[session.session_id] = session

    async def touch(self, session_id: str) -> None:
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is not None:
                session.heartbeat()

    async def remove(self, session_id: str) -> None:
        async with self._lock:
            self._sessions.pop(session_id, None)

    async def snapshot(self) -> list[ClientSession]:
        async with self._lock:
            return list(self._sessions.values())
