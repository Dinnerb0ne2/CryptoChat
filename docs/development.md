# Development Guide

## Structure
- `src/cryptochat/core`: domain + persistence
- `src/cryptochat/crypto`: encryption utilities
- `src/cryptochat/network`: asyncio TCP transport
- `src/cryptochat/cli`: Click-based CLI
- `src/cryptochat/web`: FastAPI backend + frontend pages
- `tests/`: unit and integration tests

## Local Commands
```bash
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m pip install -e .
.venv\Scripts\ruff check .
.venv\Scripts\ruff format .
.venv\Scripts\mypy src
.venv\Scripts\pytest
```

