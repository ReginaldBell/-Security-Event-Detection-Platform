from __future__ import annotations

from contextlib import contextmanager
import os
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.models import Base

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - python-dotenv is optional at runtime.
    def load_dotenv() -> None:
        return None


load_dotenv()

_DATABASE_URL_ENV_NAMES = ("SECUREWATCH_DATABASE_URL", "DATABASE_URL")
_POSTGRES_SETUP_DOC = "docs/postgres_setup.md"


def _normalize_database_url(url: str) -> str:
    value = url.strip()
    if value.startswith("postgres://"):
        return "postgresql+psycopg://" + value.removeprefix("postgres://")
    if value.startswith("postgresql://"):
        return "postgresql+psycopg://" + value.removeprefix("postgresql://")
    return value


def get_database_url() -> str:
    for name in _DATABASE_URL_ENV_NAMES:
        value = os.getenv(name)
        if value and value.strip():
            database_url = _normalize_database_url(value)
            if not database_url.startswith("postgresql+psycopg://"):
                raise RuntimeError(
                    "DATABASE_URL must use Postgres with psycopg. "
                    f"See {_POSTGRES_SETUP_DOC}"
                )
            return database_url
    raise RuntimeError(
        "DATABASE_URL not set. SecureWatch requires Postgres. "
        f"See {_POSTGRES_SETUP_DOC}"
    )


def _build_engine():
    database_url = get_database_url()
    return create_engine(
        database_url,
        pool_pre_ping=True,
    )


engine = _build_engine()
_SessionFactory = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    """Create all tables. Safe to call multiple times (CREATE IF NOT EXISTS)."""
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_session() -> Generator[Session, None, None]:
    session = _SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
