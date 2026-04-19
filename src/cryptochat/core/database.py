from __future__ import annotations

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

_ENGINES: dict[str, Engine] = {}


def _get_engine(db_url: str) -> Engine:
    engine = _ENGINES.get(db_url)
    if engine is None:
        engine = create_engine(db_url, future=True)
        _ENGINES[db_url] = engine
    return engine


def create_session_factory(db_url: str) -> sessionmaker[Session]:
    engine = _get_engine(db_url)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db(db_url: str) -> None:
    engine = _get_engine(db_url)
    Base.metadata.create_all(engine)


def dispose_engine(db_url: str) -> None:
    engine = _ENGINES.pop(db_url, None)
    if engine is not None:
        engine.dispose()
