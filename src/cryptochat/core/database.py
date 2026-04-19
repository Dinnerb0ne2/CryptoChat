from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .models import Base


def create_session_factory(db_url: str) -> sessionmaker[Session]:
    engine = create_engine(db_url, future=True)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db(db_url: str) -> None:
    engine = create_engine(db_url, future=True)
    Base.metadata.create_all(engine)
