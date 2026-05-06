from __future__ import annotations

import pytest

from app.db import database


def test_database_url_requires_postgres(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("SECUREWATCH_DATABASE_URL", raising=False)

    with pytest.raises(RuntimeError, match="SecureWatch requires Postgres"):
        database.get_database_url()


def test_database_url_rejects_sqlite(monkeypatch):
    monkeypatch.delenv("SECUREWATCH_DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", "sqlite:///runs/securewatch.db")

    with pytest.raises(RuntimeError, match="must use Postgres"):
        database.get_database_url()


def test_database_url_prefers_securewatch_env(monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://default:default@localhost:5432/default",
    )
    monkeypatch.setenv(
        "SECUREWATCH_DATABASE_URL",
        "postgresql+psycopg://securewatch:securewatch@localhost:5432/securewatch",
    )

    assert (
        database.get_database_url()
        == "postgresql+psycopg://securewatch:securewatch@localhost:5432/securewatch"
    )


def test_database_url_normalizes_postgres_aliases(monkeypatch):
    monkeypatch.delenv("SECUREWATCH_DATABASE_URL", raising=False)
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgres://securewatch:securewatch@localhost:5432/securewatch",
    )

    assert (
        database.get_database_url()
        == "postgresql+psycopg://securewatch:securewatch@localhost:5432/securewatch"
    )
