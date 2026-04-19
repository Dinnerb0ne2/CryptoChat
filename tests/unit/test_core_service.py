from pathlib import Path

from cryptochat.core import ChatService, create_session_factory, init_db


def test_chat_service_flow(tmp_path: Path) -> None:
    db_path = tmp_path / "chat.db"
    db_url = f"sqlite:///{db_path.as_posix()}"
    init_db(db_url)
    service = ChatService(create_session_factory(db_url))

    service.register("u1", "p1")
    assert service.authenticate("u1", "p1") is True

    routed = service.post_message("general", "u1", "hello")
    assert routed.body == "hello"

    rows = service.history("general", limit=10)
    assert len(rows) == 1
    assert rows[0].username == "u1"
