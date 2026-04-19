from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any


DEFAULT_CONFIG: dict[str, Any] = {
    "database": {
        "path": "data/chat.db",
    },
    "server": {
        "host": "127.0.0.1",
        "port": 9443,
        "certfile": "certs/server.crt",
        "keyfile": "certs/server.key",
        "ca_file": "",
        "allow_insecure_clients": True,
        "backlog": 128,
    },
    "client": {
        "server_host": "127.0.0.1",
        "server_port": 9443,
        "cert_verify": False,
        "ca_file": "",
        "nickname": "guest",
        "room": "",
    },
    "rooms": {
        "enabled": False,
        "default_room": "lobby",
        "allow_dynamic": True,
        "room_scoped_history": True,
        "room_scoped_clear": True,
        "rooms": {
            "lobby": {"password": ""},
        },
    },
    "history": {
        "default_limit": 50,
        "max_limit": 500,
    },
    "web": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 9444,
        "use_tls": False,
        "certfile": "certs/server.crt",
        "keyfile": "certs/server.key",
        "static_dir": "src/static",
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    merged = copy.deepcopy(DEFAULT_CONFIG)
    if not config_path.exists():
        return merged
    loaded = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("config file root must be a JSON object")
    return _deep_merge(merged, loaded)
