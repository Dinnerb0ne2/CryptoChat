from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from cryptochat.core import ChatService, create_session_factory, dispose_engine, init_db

from .auth import issue_token, verify_token
from .schemas import LoginRequest, PostMessageRequest, RegisterRequest


class ConnectionHub:
    def __init__(self) -> None:
        self._room_sockets: dict[str, set[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def join(self, room: str, socket: WebSocket) -> None:
        await socket.accept()
        async with self._lock:
            self._room_sockets.setdefault(room, set()).add(socket)

    async def leave(self, room: str, socket: WebSocket) -> None:
        async with self._lock:
            sockets = self._room_sockets.get(room)
            if not sockets:
                return
            sockets.discard(socket)
            if not sockets:
                self._room_sockets.pop(room, None)

    async def broadcast(self, room: str, payload: dict[str, Any]) -> None:
        async with self._lock:
            targets = list(self._room_sockets.get(room, set()))
        for socket in targets:
            await socket.send_json(payload)


def create_app(
    db_url: str = "sqlite:///cryptochat.db", secret_key: str = "cryptochat-dev-secret"
) -> FastAPI:
    init_db(db_url)
    session_factory = create_session_factory(db_url)
    service = ChatService(session_factory)
    hub = ConnectionHub()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        dispose_engine(db_url)

    app = FastAPI(title="CryptoChat API", version="2.0.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    frontend_root = Path(__file__).resolve().parent.parent / "frontend"

    def require_user(authorization: str = Header(default="")) -> str:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token = authorization.replace("Bearer ", "", 1)
        username = verify_token(token, secret_key)
        if username is None:
            raise HTTPException(status_code=401, detail="invalid token")
        return username

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(frontend_root / "index.html")

    @app.get("/admin")
    async def admin_page() -> FileResponse:
        return FileResponse(frontend_root / "admin.html")

    @app.post("/api/register")
    async def register(payload: RegisterRequest) -> dict[str, Any]:
        service.register(payload.username, payload.password)
        return {"ok": True}

    @app.post("/api/login")
    async def login(payload: LoginRequest) -> dict[str, Any]:
        if not service.authenticate(payload.username, payload.password):
            raise HTTPException(status_code=401, detail="invalid credentials")
        return {"ok": True, "token": issue_token(payload.username, secret_key)}

    @app.post("/api/messages")
    async def post_message(
        payload: PostMessageRequest, username: str = Depends(require_user)
    ) -> dict[str, Any]:
        if username != payload.username:
            raise HTTPException(status_code=403, detail="user mismatch")
        routed = service.post_message(payload.room, payload.username, payload.body)
        body = {
            "room": routed.room,
            "username": routed.username,
            "body": routed.body,
            "created_at": routed.created_at.isoformat(),
        }
        await hub.broadcast(payload.room, body)
        return {"ok": True, "message": body}

    @app.get("/api/history/{room}")
    async def get_history(
        room: str, limit: int = 50, _: str = Depends(require_user)
    ) -> dict[str, Any]:
        rows = service.history(room, limit)
        return {
            "ok": True,
            "messages": [
                {
                    "room": r.room,
                    "username": r.username,
                    "body": r.body,
                    "created_at": r.created_at.isoformat(),
                }
                for r in rows
            ],
        }

    @app.websocket("/ws/{room}")
    async def room_ws(socket: WebSocket, room: str) -> None:
        await hub.join(room, socket)
        try:
            while True:
                _ = await socket.receive_text()
        except WebSocketDisconnect:
            await hub.leave(room, socket)

    return app
