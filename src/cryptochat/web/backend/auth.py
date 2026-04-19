from __future__ import annotations

import base64
import hmac
from hashlib import sha256


def issue_token(username: str, secret_key: str) -> str:
    digest = hmac.new(secret_key.encode("utf-8"), username.encode("utf-8"), sha256).digest()
    return f"{username}.{base64.urlsafe_b64encode(digest).decode('utf-8')}"


def verify_token(token: str, secret_key: str) -> str | None:
    if "." not in token:
        return None
    username, encoded = token.split(".", 1)
    expected = issue_token(username, secret_key).split(".", 1)[1]
    if hmac.compare_digest(encoded, expected):
        return username
    return None
