from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.table import Table

from cryptochat.config import load_config
from cryptochat.core import ChatService, create_session_factory, init_db
from cryptochat.logging_utils import setup_logging
from cryptochat.network import AsyncTcpClient, AsyncTcpServer
from cryptochat.web.backend.app import create_app

console = Console()


def _ensure_service(config_path: str | None) -> ChatService:
    config = load_config(config_path)
    init_db(config.db_url)
    session_factory = create_session_factory(config.db_url)
    return ChatService(session_factory)


@click.group()
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
@click.option("--log-level", default="INFO", show_default=True)
@click.pass_context
def cli(ctx: click.Context, config_path: Path | None, log_level: str) -> None:
    setup_logging(log_level)
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = str(config_path) if config_path else None


@cli.group()
def server() -> None:
    """Server-side commands."""


@server.command("bootstrap-admin")
@click.option("--username", required=True)
@click.option("--password", required=True, hide_input=True)
@click.pass_context
def bootstrap_admin(ctx: click.Context, username: str, password: str) -> None:
    service = _ensure_service(ctx.obj["config_path"])
    service.register(username=username, password=password, is_admin=True)
    console.print(f"[green]Admin created:[/green] {username}")


@server.command("ban")
@click.option("--username", required=True)
@click.option("--reason", default="policy_violation")
@click.pass_context
def ban_user(ctx: click.Context, username: str, reason: str) -> None:
    service = _ensure_service(ctx.obj["config_path"])
    service.ban(username=username, reason=reason)
    console.print(f"[yellow]Banned:[/yellow] {username} ({reason})")


@server.command("serve-tcp")
@click.pass_context
def serve_tcp(ctx: click.Context) -> None:
    config = load_config(ctx.obj["config_path"])
    service = _ensure_service(ctx.obj["config_path"])

    async def handler(packet: dict[str, Any]) -> dict[str, Any]:
        action = packet.get("action")
        if action == "heartbeat":
            return {"ok": True, "type": "heartbeat"}
        if action == "register":
            service.register(packet["username"], packet["password"])
            return {"ok": True, "type": "register"}
        if action == "login":
            ok = service.authenticate(packet["username"], packet["password"])
            return {"ok": ok, "type": "login"}
        if action == "send":
            routed = service.post_message(packet["room"], packet["username"], packet["body"])
            return {
                "ok": True,
                "type": "message",
                "room": routed.room,
                "username": routed.username,
                "body": routed.body,
                "created_at": routed.created_at.isoformat(),
            }
        if action == "history":
            rows = service.history(packet["room"], int(packet.get("limit", 50)))
            return {
                "ok": True,
                "type": "history",
                "messages": [
                    {
                        "room": row.room,
                        "username": row.username,
                        "body": row.body,
                        "created_at": row.created_at.isoformat(),
                    }
                    for row in rows
                ],
            }
        return {"ok": False, "error": "unknown_action"}

    async def run() -> None:
        server = AsyncTcpServer(config.host, config.port, handler)
        await server.start()
        await server.serve_forever()

    asyncio.run(run())


@server.command("serve-web")
@click.pass_context
def serve_web(ctx: click.Context) -> None:
    import uvicorn

    config = load_config(ctx.obj["config_path"])
    app = create_app(config.db_url, config.secret_key)
    uvicorn.run(app, host=config.host, port=config.port)


@cli.group()
def client() -> None:
    """Client-side commands."""


@client.command("register")
@click.option("--username", required=True)
@click.option("--password", required=True, hide_input=True)
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8765, type=int)
def client_register(username: str, password: str, host: str, port: int) -> None:
    async def run() -> None:
        c = AsyncTcpClient(host, port)
        resp = await c.send({"action": "register", "username": username, "password": password})
        await c.close()
        console.print_json(json.dumps(resp, ensure_ascii=False))

    asyncio.run(run())


@client.command("login")
@click.option("--username", required=True)
@click.option("--password", required=True, hide_input=True)
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8765, type=int)
def client_login(username: str, password: str, host: str, port: int) -> None:
    async def run() -> None:
        c = AsyncTcpClient(host, port)
        resp = await c.send({"action": "login", "username": username, "password": password})
        await c.close()
        console.print_json(json.dumps(resp, ensure_ascii=False))

    asyncio.run(run())


@client.command("send")
@click.option("--username", required=True)
@click.option("--room", required=True)
@click.option("--body", required=True)
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8765, type=int)
def client_send(username: str, room: str, body: str, host: str, port: int) -> None:
    async def run() -> None:
        c = AsyncTcpClient(host, port)
        resp = await c.send({"action": "send", "username": username, "room": room, "body": body})
        await c.close()
        console.print_json(json.dumps(resp, ensure_ascii=False))

    asyncio.run(run())


@client.command("history")
@click.option("--room", required=True)
@click.option("--limit", default=20, type=int)
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8765, type=int)
def client_history(room: str, limit: int, host: str, port: int) -> None:
    async def run() -> None:
        c = AsyncTcpClient(host, port)
        resp = await c.send({"action": "history", "room": room, "limit": limit})
        await c.close()
        table = Table(title=f"Room: {room}")
        table.add_column("Time")
        table.add_column("User")
        table.add_column("Message")
        for row in resp.get("messages", []):
            table.add_row(row["created_at"], row["username"], row["body"])
        console.print(table)

    asyncio.run(run())
