import asyncio
import socket
from contextlib import suppress

import pytest

from cryptochat.network.client import AsyncTcpClient
from cryptochat.network.server import AsyncTcpServer


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.mark.asyncio
async def test_tcp_server_client_roundtrip() -> None:
    port = _free_port()

    async def handler(packet: dict[str, object]) -> dict[str, object]:
        if packet.get("action") == "heartbeat":
            return {"ok": True, "type": "heartbeat"}
        return {"ok": True, "echo": packet}

    server = AsyncTcpServer("127.0.0.1", port, handler)
    await server.start()
    task = asyncio.create_task(server.serve_forever())

    client = AsyncTcpClient("127.0.0.1", port)
    response = await client.send({"action": "heartbeat"})
    assert response["ok"] is True
    assert response["type"] == "heartbeat"
    await client.close()

    await server.stop()
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task

