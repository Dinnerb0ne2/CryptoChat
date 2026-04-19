import pytest

from cryptochat.network.session import ClientSession, SessionManager


@pytest.mark.asyncio
async def test_session_manager_lifecycle() -> None:
    manager = SessionManager()
    session = ClientSession(session_id="s1", username="u1")
    await manager.put(session)
    assert len(await manager.snapshot()) == 1
    await manager.touch("s1")
    await manager.remove("s1")
    assert await manager.snapshot() == []

