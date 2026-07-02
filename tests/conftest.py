"""Shared fixtures for the P1.1 ledger suite.

Substrate: real Postgres via DATABASE_URL (default: local ``airlock_test``).
Schema is created once per session; ``commit_records`` and the test-only
``effects_log`` table are truncated before every test.

Side-effect ground truth (PLAN.md section 7): ``effects_log`` rows written on
a SEPARATE autocommit connection — an effect is counted the instant it
happens, independent of any ledger transaction.

Import discipline: sqlalchemy (the ``postgres`` extra) is imported lazily
inside fixtures/helpers, never at module level — the core CI job runs the
scaffold tests with extras UNINSTALLED (PLAN.md section 3.1) and this conftest
must still be collectable there.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/airlock_test")

EFFECTS_LOG_DDL = """
CREATE TABLE IF NOT EXISTS effects_log (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    idempotency_key TEXT NOT NULL,
    worker_pid      INT  NOT NULL,
    logged_at       TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


@pytest.fixture(scope="session")
def database_url() -> str:
    return DATABASE_URL


@pytest.fixture(scope="session")
def schema_engine(database_url: str) -> Iterator[Engine]:
    """Session-wide engine; creates the ledger schema plus effects_log once."""
    from sqlalchemy import create_engine, text

    from airlock.store._schema import ensure_schema
    from airlock.store.postgres import normalize_postgres_url

    engine = create_engine(normalize_postgres_url(database_url))
    ensure_schema(engine)
    with engine.begin() as conn:
        conn.execute(text(EFFECTS_LOG_DDL))
    yield engine
    engine.dispose()


@pytest.fixture
def db(schema_engine: Engine) -> Engine:
    """Truncates ledger + effects tables before each test; returns the engine."""
    from sqlalchemy import text

    with schema_engine.begin() as conn:
        conn.execute(text("TRUNCATE commit_records, effects_log RESTART IDENTITY"))
    return schema_engine


@pytest.fixture
def store(db: Engine, database_url: str) -> Iterator[PostgresStore]:
    from airlock.store.postgres import PostgresStore

    pg_store = PostgresStore(database_url)
    yield pg_store
    pg_store.close()


class EffectsLog:
    """Ground-truth side-effect counter on a dedicated autocommit connection."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def log(self, key: str) -> None:
        from sqlalchemy import text

        with self._engine.connect() as conn:
            conn.execute(
                text(
                    "INSERT INTO effects_log (idempotency_key, worker_pid)"
                    " VALUES (:key, pg_backend_pid())"
                ),
                {"key": key},
            )

    def count(self, key: str) -> int:
        from sqlalchemy import text

        with self._engine.connect() as conn:
            found = conn.execute(
                text("SELECT count(*) FROM effects_log WHERE idempotency_key = :key"),
                {"key": key},
            ).scalar_one()
        return int(found)


@pytest.fixture
def effects(db: Engine, database_url: str) -> Iterator[EffectsLog]:
    from sqlalchemy import create_engine

    from airlock.store.postgres import normalize_postgres_url

    engine = create_engine(normalize_postgres_url(database_url), isolation_level="AUTOCOMMIT")
    yield EffectsLog(engine)
    engine.dispose()


def bump_epoch(engine: Engine, key: str) -> None:
    """Simulate an external takeover: bump the ownership epoch (attempts)."""
    from sqlalchemy import text

    with engine.begin() as conn:
        rowcount = conn.execute(
            text("UPDATE commit_records SET attempts = attempts + 1 WHERE idempotency_key = :key"),
            {"key": key},
        ).rowcount
    assert rowcount == 1, f"no row to bump for {key!r}"
