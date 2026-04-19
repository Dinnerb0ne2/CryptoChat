from pathlib import Path
from typing import Any

from click.testing import CliRunner

from cryptochat.cli.app import cli


def _write_config(tmp_path: Path) -> Path:
    config_path = tmp_path / "config.toml"
    db_url = f"sqlite:///{(tmp_path / 'cli.db').as_posix()}"
    config_path.write_text(
        f"""
[app]
host = "127.0.0.1"
port = 9876
db_url = "{db_url}"
secret_key = "x"
""".strip(),
        encoding="utf-8",
    )
    return config_path


class _FakeClient:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

    async def send(self, packet: dict[str, Any]) -> dict[str, Any]:
        action = packet["action"]
        if action == "history":
            return {"messages": [{"created_at": "t", "username": "u", "body": "b"}]}
        return {"ok": True, "type": action}

    async def close(self) -> None:
        return None


def test_cli_server_commands(tmp_path: Path) -> None:
    runner = CliRunner()
    config_path = _write_config(tmp_path)
    result = runner.invoke(
        cli,
        [
            "--config",
            str(config_path),
            "server",
            "bootstrap-admin",
            "--username",
            "admin",
            "--password",
            "p1",
        ],
    )
    assert result.exit_code == 0

    result = runner.invoke(
        cli,
        [
            "--config",
            str(config_path),
            "server",
            "ban",
            "--username",
            "admin",
            "--reason",
            "test",
        ],
    )
    assert result.exit_code == 0


def test_cli_client_commands(monkeypatch) -> None:
    runner = CliRunner()
    monkeypatch.setattr("cryptochat.cli.app.AsyncTcpClient", _FakeClient)

    assert (
        runner.invoke(
            cli,
            [
                "client",
                "register",
                "--username",
                "u1",
                "--password",
                "p1",
                "--host",
                "127.0.0.1",
                "--port",
                "1",
            ],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli,
            [
                "client",
                "login",
                "--username",
                "u1",
                "--password",
                "p1",
                "--host",
                "127.0.0.1",
                "--port",
                "1",
            ],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli,
            [
                "client",
                "send",
                "--username",
                "u1",
                "--room",
                "general",
                "--body",
                "hello",
                "--host",
                "127.0.0.1",
                "--port",
                "1",
            ],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            cli,
            [
                "client",
                "history",
                "--room",
                "general",
                "--limit",
                "1",
                "--host",
                "127.0.0.1",
                "--port",
                "1",
            ],
        ).exit_code
        == 0
    )


def test_cli_serve_web(monkeypatch) -> None:
    runner = CliRunner()
    called = {"ok": False}

    def fake_run(*args: Any, **kwargs: Any) -> None:
        called["ok"] = True

    monkeypatch.setattr("uvicorn.run", fake_run)
    result = runner.invoke(cli, ["server", "serve-web"])
    assert result.exit_code == 0
    assert called["ok"] is True


def test_cli_serve_tcp(monkeypatch) -> None:
    runner = CliRunner()

    class _FakeServer:
        def __init__(self, host: str, port: int, handler: Any) -> None:
            self._handler = handler

        async def start(self) -> None:
            return None

        async def serve_forever(self) -> None:
            await self._handler({"action": "heartbeat"})

    monkeypatch.setattr("cryptochat.cli.app.AsyncTcpServer", _FakeServer)
    result = runner.invoke(cli, ["server", "serve-tcp"])
    assert result.exit_code == 0

