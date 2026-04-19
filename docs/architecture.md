# CryptoChat v2.0 Architecture

## Overview
CryptoChat is split into three layers:

1. **Core Layer (`cryptochat.core`)**: domain models, room/message routing, ban policy, persistence.
2. **Interface Layer (`cryptochat.cli`, `cryptochat.web`)**: CLI and Web API/UI adapters.
3. **Infrastructure Layer (`cryptochat.crypto`, `cryptochat.network`)**: encryption and async TCP transport.

## Module Structure
- `src/cryptochat/crypto/`: RSA key management + hybrid RSA/AES-GCM encryption.
- `src/cryptochat/network/`: asyncio protocol parsing, heartbeat, reconnect, session handling.
- `src/cryptochat/core/`: SQLAlchemy storage and chat business services.
- `src/cryptochat/cli/`: Click command tree, server/client orchestration.
- `src/cryptochat/web/backend/`: FastAPI app, auth endpoints, WebSocket gateway.
- `src/cryptochat/web/frontend/`: Jinja/static-compatible pages using Alpine.js.

## Data Flow
1. User authenticates via CLI/Web.
2. Client sends message command to service.
3. Core validates user/room/ban policy.
4. Message is persisted and routed to active sessions.
5. Transport layer delivers payload over TCP/WebSocket.
6. Optional payload encryption is handled by `crypto` module.

## Design Constraints
- Python `3.14.3`
- Storage: SQLite + SQLAlchemy
- No Django/React/Vue/Angular/PostgreSQL/MySQL/Celery

## Quality Gates
- Ruff + mypy + pytest in CI
- Unit + integration tests under `tests/`
