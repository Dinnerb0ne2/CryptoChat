# CryptoChat v2.0

CryptoChat is a Python 3.14.3 encrypted chat application with both CLI and Web UI.

## Tech Stack
- FastAPI + Alpine.js
- Click + rich
- cryptography (RSA + AES-GCM)
- SQLite + SQLAlchemy
- asyncio TCP + WebSocket

## Quick Start
```bash
python -m venv .venv
.venv\Scripts\python -m pip install --upgrade pip
.venv\Scripts\python -m pip install -r requests.txt
.venv\Scripts\python -m pip install -e .
```

## CLI
```bash
cryptochat server bootstrap-admin --username admin --password admin123
cryptochat server serve-tcp
cryptochat client register --username u1 --password p1
cryptochat client send --username u1 --room general --body "hello"
```

## Web
```bash
cryptochat server serve-web
```
Open `http://127.0.0.1:8765`.

## Quality
```bash
ruff check .
ruff format .
mypy src
pytest
```

## Packaging
```bash
python build.py
```

