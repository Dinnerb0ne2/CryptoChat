from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.orm import Session, sessionmaker

from .repository import ChatRepository


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RoutedMessage:
    room: str
    username: str
    body: str
    created_at: datetime


class ChatService:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def register(self, username: str, password: str, is_admin: bool = False) -> None:
        with self._session_factory() as session:
            repo = ChatRepository(session)
            if repo.get_user(username) is not None:
                raise ValueError(f"user already exists: {username}")
            repo.create_user(
                username=username, password_hash=_hash_password(password), is_admin=is_admin
            )

    def authenticate(self, username: str, password: str) -> bool:
        with self._session_factory() as session:
            repo = ChatRepository(session)
            user = repo.get_user(username)
            if user is None:
                return False
            return user.password_hash == _hash_password(password)

    def ban(self, username: str, reason: str) -> None:
        with self._session_factory() as session:
            repo = ChatRepository(session)
            repo.ban_user(username=username, reason=reason)

    def post_message(self, room: str, username: str, body: str) -> RoutedMessage:
        with self._session_factory() as session:
            repo = ChatRepository(session)
            if repo.is_banned(username):
                raise PermissionError(f"user is banned: {username}")
            user = repo.get_user(username)
            if user is None:
                raise ValueError(f"user not found: {username}")
            room_obj = repo.get_or_create_room(room)
            message = repo.save_message(room=room_obj, user=user, body=body)
            return RoutedMessage(
                room=room, username=username, body=message.body, created_at=message.created_at
            )

    def history(self, room: str, limit: int = 50) -> list[RoutedMessage]:
        with self._session_factory() as session:
            repo = ChatRepository(session)
            rows = repo.list_messages(room_name=room, limit=limit)
            return [
                RoutedMessage(
                    room=room,
                    username=row.user.username,
                    body=row.body,
                    created_at=row.created_at.astimezone(UTC),
                )
                for row in rows
            ]
