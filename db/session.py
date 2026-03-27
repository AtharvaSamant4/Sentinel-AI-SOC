"""
db/session.py
-------------
SQLAlchemy engine, session factory, declarative base, and startup helper.

The database file lives next to this file's package root so it is easy to
locate and back up.  On startup call ``init_db()`` once to create all tables.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)

# sentinel.db sits at the project root (one level above db/)
_DB_PATH = Path(__file__).resolve().parent.parent / "sentinel.db"
DATABASE_URL = f"sqlite:///{_DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # required for SQLite + threads
    echo=False,
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    pass


def get_db() -> Session:
    """
    Yield a database session and guarantee it is closed afterwards.
    Intended for use in FastAPI dependency injection or plain ``with`` blocks.

    Usage (FastAPI):
        db: Session = Depends(get_db)

    Usage (plain Python):
        with get_db() as db:
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables that do not yet exist.  Safe to call on every startup."""
    # Import models here so their metadata is registered with Base before
    # create_all is called.
    from db import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    logger.info("[db] SQLite database ready: %s", _DB_PATH)
