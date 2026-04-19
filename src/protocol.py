from __future__ import annotations

import json
from typing import Any, BinaryIO


def send_packet(stream: BinaryIO, payload: dict[str, Any]) -> None:
    wire = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
    stream.write(wire)
    stream.flush()


def recv_packet(stream: BinaryIO) -> dict[str, Any] | None:
    raw = stream.readline()
    if not raw:
        return None
    text = raw.decode("utf-8").strip()
    if not text:
        return None
    packet = json.loads(text)
    if not isinstance(packet, dict):
        raise ValueError("packet must be a JSON object")
    return packet
