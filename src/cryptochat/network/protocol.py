from __future__ import annotations

import json
from typing import Any


def encode_packet(data: dict[str, Any]) -> bytes:
    return (json.dumps(data, ensure_ascii=False) + "\n").encode("utf-8")


def decode_packet(line: bytes) -> dict[str, Any]:
    parsed = json.loads(line.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("packet must be a JSON object")
    return parsed
