from pathlib import Path

from cryptochat.config import load_config
from cryptochat.web.backend.auth import issue_token, verify_token


def test_load_config_default() -> None:
    config = load_config()
    assert config.host == "127.0.0.1"
    assert config.port == 8765


def test_load_config_from_file(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[app]
host = "0.0.0.0"
port = 9000
db_url = "sqlite:///x.db"
secret_key = "abc"
""".strip(),
        encoding="utf-8",
    )
    config = load_config(config_file)
    assert config.host == "0.0.0.0"
    assert config.port == 9000
    assert config.db_url == "sqlite:///x.db"
    assert config.secret_key == "abc"


def test_issue_and_verify_token() -> None:
    token = issue_token("alice", "secret")
    assert verify_token(token, "secret") == "alice"
    assert verify_token(token, "wrong") is None
    assert verify_token("bad-token", "secret") is None

