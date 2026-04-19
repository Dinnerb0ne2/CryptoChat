from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from .protocol import decode_packet, encode_packet

PacketHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


class AsyncTcpServer:
    def __init__(self, host: str, port: int, handler: PacketHandler) -> None:
        self._host = host
        self._port = port
        self._handler = handler
        self._server: asyncio.AbstractServer | None = None
        self._logger = logging.getLogger("cryptochat.network.server")

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self._host, self._port)
        self._logger.info("TCP server started at %s:%s", self._host, self._port)

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._logger.info("TCP server stopped")

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                packet = decode_packet(line)
                response = await self._handler(packet)
                writer.write(encode_packet(response))
                await writer.drain()
        except Exception as exc:
            self._logger.exception("client handler error: %s", exc)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
