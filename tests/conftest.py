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
from datetime import datetime
from typing import TYPE_CHECKING, Any

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


class FakeClock:
    """A controllable clock — the P1.3 determinism substrate (PLAN.md section 7).

    "A pending row past the reconcile timeout" is produced by *advancing* this
    clock, NEVER by ``time.sleep``: the store's ``now_fn`` and the reconciler
    share one instance, so ``advance(seconds)`` makes an in-flight row cross the
    staleness cutoff instantly and deterministically. The reconciler tests read
    ``FakeClock`` as ``now_fn`` and the reconciler's ``now_fn`` argument.
    """

    def __init__(self, start: datetime) -> None:
        self._now = start

    def __call__(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        from datetime import timedelta

        self._now = self._now + timedelta(seconds=seconds)


@pytest.fixture
def fake_clock() -> FakeClock:
    """A fake clock starting at a fixed UTC instant (advance it, never sleep)."""
    from datetime import UTC, datetime

    return FakeClock(datetime(2026, 7, 3, 12, 0, 0, tzinfo=UTC))


@pytest.fixture
def clock_store(db: Engine, database_url: str, fake_clock: FakeClock) -> Iterator[PostgresStore]:
    """A PostgresStore whose ``now_fn`` is the shared :class:`FakeClock`.

    The store computes the staleness cutoff from this clock, so a reconciler
    given the same ``fake_clock`` scans exactly the rows the test intends.
    """
    from airlock.store.postgres import PostgresStore

    pg_store = PostgresStore(database_url, now_fn=fake_clock)
    yield pg_store
    pg_store.close()


def read_row(engine: Engine, key: str) -> Any:
    """Read a commit_records row from a FRESH connection (durability check)."""
    from sqlalchemy import text

    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT state, guarantee, attempts, downstream_key, result_json, error_json,"
                " committed_at FROM commit_records WHERE idempotency_key = :key"
            ),
            {"key": key},
        ).one()
