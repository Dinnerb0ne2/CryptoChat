from pathlib import Path

import pytest

from cryptochat.core import ChatService, create_session_factory, init_db


def _service(tmp_path: Path) -> ChatService:
    db_url = f"sqlite:///{(tmp_path / 'edge.db').as_posix()}"
    init_db(db_url)
    return ChatService(create_session_factory(db_url))


def test_register_duplicate_raises(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.register("u1", "p1")
    with pytest.raises(ValueError):
        service.register("u1", "p1")


def test_post_message_requires_user(tmp_path: Path) -> None:
    service = _service(tmp_path)
    with pytest.raises(ValueError):
        service.post_message("general", "missing", "x")


def test_ban_blocks_post(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.register("u1", "p1")
    service.ban("u1", "test")
    with pytest.raises(PermissionError):
        service.post_message("general", "u1", "x")

