from __future__ import annotations

import argparse
import time
from pathlib import Path

from .client import ChatClient, add_client_args
from .config import DEFAULT_CONFIG, load_config
from .server import ChatServer
from .storage import ChatStorage
from .webui import ChatWebUIServer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chat.py", description="CryptoChat (TLS1.3 + sqlite3 + stdlib only)")
    parser.add_argument("--config", default="config/chat_config.json", help="config file path")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="initialize sqlite schema")
    sub.add_parser("server", help="run TLS chat server")
    client_parser = sub.add_parser("client", help="run CLI chat client")
    add_client_args(client_parser)
    sub.add_parser("web", help="run chat server and web ui in one process")
    sub.add_parser("print-default-config", help="print default config as JSON")
    return parser


def run_server(config: dict) -> int:
    server = ChatServer(config)
    print(f"TLS chat server on {config['server']['host']}:{config['server']['port']}")
    try:
        server.start(background=False)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


def run_web(config: dict) -> int:
    server = ChatServer(config)
    web = ChatWebUIServer(config, server)
    try:
        server.start(background=True)
        print(
            f"Chat server {config['server']['host']}:{config['server']['port']} + "
            f"Web UI {config['web']['host']}:{config['web']['port']}"
        )
        web.start(background=False)
    except KeyboardInterrupt:
        pass
    finally:
        web.stop()
        server.stop()
    return 0


def run_client(config: dict, args: argparse.Namespace) -> int:
    nickname = args.nickname or config["client"]["nickname"]
    room = args.room or config["client"].get("room", "")
    room_password = args.room_password
    client = ChatClient(config, nickname=nickname, room=room, room_password=room_password)
    return client.run()


def run_init_db(config: dict) -> int:
    storage = ChatStorage(config["database"]["path"])
    storage.close()
    print(f"DB initialized: {config['database']['path']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "print-default-config":
        import json

        print(json.dumps(DEFAULT_CONFIG, ensure_ascii=False, indent=2))
        return 0
    config = load_config(Path(args.config))
    if args.command == "init-db":
        return run_init_db(config)
    if args.command == "server":
        return run_server(config)
    if args.command == "client":
        return run_client(config, args)
    if args.command == "web":
        return run_web(config)
    time.sleep(0.1)
    return 1
