from __future__ import annotations

import asyncio
from typing import Any

from .protocol import decode_packet, encode_packet


class AsyncTcpClient:
    def __init__(self, host: str, port: int, reconnect_interval: float = 1.0) -> None:
        self._host = host
        self._port = port
        self._reconnect_interval = reconnect_interval
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def connect(self) -> None:
        while True:
            try:
                self._reader, self._writer = await asyncio.open_connection(self._host, self._port)
                return
            except OSError:
                await asyncio.sleep(self._reconnect_interval)

    async def send(self, packet: dict[str, Any]) -> dict[str, Any]:
        if self._writer is None or self._reader is None:
            await self.connect()
        assert self._reader is not None and self._writer is not None
        self._writer.write(encode_packet(packet))
        await self._writer.drain()
        line = await self._reader.readline()
        return decode_packet(line)

    async def close(self) -> None:
        if self._writer is None:
            return
        self._writer.close()
        await self._writer.wait_closed()
