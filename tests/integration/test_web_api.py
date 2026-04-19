from fastapi.testclient import TestClient

from cryptochat.web.backend.app import create_app


def test_web_register_login_message(tmp_path) -> None:
    db_url = f"sqlite:///{(tmp_path / 'web.db').as_posix()}"
    app = create_app(db_url=db_url, secret_key="s")
    client = TestClient(app)

    r = client.post("/api/register", json={"username": "u1", "password": "p1"})
    assert r.status_code == 200

    r = client.post("/api/login", json={"username": "u1", "password": "p1"})
    assert r.status_code == 200
    token = r.json()["token"]

    r = client.post(
        "/api/messages",
        json={"room": "general", "username": "u1", "body": "hello"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200

    r = client.get("/api/history/general", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert len(r.json()["messages"]) == 1
