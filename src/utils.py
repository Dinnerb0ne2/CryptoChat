from __future__ import annotations

from datetime import datetime


TIME_FORMAT = "%m-%d %H:%M:%S"


def now_text() -> str:
    return datetime.now().strftime(TIME_FORMAT)


def now_epoch() -> float:
    return datetime.now().timestamp()
