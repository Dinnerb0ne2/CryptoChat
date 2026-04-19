from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Ban, Message, Room, User


class ChatRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_user(self, username: str) -> User | None:
        return self.session.scalar(select(User).where(User.username == username))

    def create_user(self, username: str, password_hash: str, is_admin: bool = False) -> User:
        user = User(username=username, password_hash=password_hash, is_admin=is_admin)
        self.session.add(user)
        self.session.commit()
        self.session.refresh(user)
        return user

    def get_or_create_room(self, name: str) -> Room:
        room = self.session.scalar(select(Room).where(Room.name == name))
        if room is not None:
            return room
        room = Room(name=name)
        self.session.add(room)
        self.session.commit()
        self.session.refresh(room)
        return room

    def ban_user(self, username: str, reason: str) -> Ban:
        record = self.session.scalar(select(Ban).where(Ban.username == username))
        if record is not None:
            record.reason = reason
            self.session.commit()
            self.session.refresh(record)
            return record
        record = Ban(username=username, reason=reason)
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def is_banned(self, username: str) -> bool:
        return self.session.scalar(select(Ban).where(Ban.username == username)) is not None

    def save_message(self, room: Room, user: User, body: str) -> Message:
        message = Message(room_id=room.id, user_id=user.id, body=body)
        self.session.add(message)
        self.session.commit()
        self.session.refresh(message)
        return message

    def list_messages(self, room_name: str, limit: int = 50) -> list[Message]:
        room = self.session.scalar(select(Room).where(Room.name == room_name))
        if room is None:
            return []
        stmt = (
            select(Message)
            .where(Message.room_id == room.id)
            .order_by(Message.created_at.desc())
            .limit(limit)
        )
        rows = list(self.session.scalars(stmt).all())
        rows.reverse()
        return rows
