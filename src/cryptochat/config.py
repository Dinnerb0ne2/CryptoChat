from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AppConfig:
    host: str = "127.0.0.1"
    port: int = 8765
    db_url: str = "sqlite:///cryptochat.db"
    secret_key: str = "cryptochat-dev-secret"


def load_config(path: str | Path | None = None) -> AppConfig:
    if path is None:
        return AppConfig()
    config_path = Path(path)
    if not config_path.exists():
        return AppConfig()
    data: dict[str, Any] = tomllib.loads(config_path.read_text(encoding="utf-8"))
    app_data = data.get("app", {})
    return AppConfig(
        host=str(app_data.get("host", "127.0.0.1")),
        port=int(app_data.get("port", 8765)),
        db_url=str(app_data.get("db_url", "sqlite:///cryptochat.db")),
        secret_key=str(app_data.get("secret_key", "cryptochat-dev-secret")),
    )
