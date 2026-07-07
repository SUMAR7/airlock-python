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
from hypothesis import HealthCheck, Phase, settings

# The mechanical no-time.sleep guard (PLAN.md 7 / P1.4): re-exporting the
# autouse fixture here makes it apply to EVERY test in the suite. Any test whose
# call stack reaches time.sleep fails loudly — all synchronization must be
# barriers/events/FakeClock/DB-polling-with-a-deadline. See tests/_no_sleep.py.
from tests._no_sleep import no_time_sleep  # noqa: F401  (autouse fixture, used by collection)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/airlock_test")

# ---------------------------------------------------------------------------
# Hypothesis profiles (PLAN.md 7 / SPEC.md 9 / P1.4 deliverable 4).
#
# The property suite (tests/test_property_commit.py) is DB-backed and drives the
# real ledger/reconciler, so each example is not cheap; the budgets are chosen so
# the PR CI leg is MINUTES, not tens of minutes (PLAN.md 8).
#
# - "ci" (the default here): derandomize=True so a red PR is a REAL bug and never
#   dice; a fixed, modest max_examples; deadline=None because a DB round-trip per
#   step legitimately exceeds Hypothesis's default per-example deadline (the
#   suite's determinism guarantee is the no-time.sleep guard + FakeClock, not a
#   wall-clock deadline). Explain-phase off to keep output terse.
# - "dev": a small, RANDOM budget for fast local iteration (each `pytest` run
#   explores fresh interleavings).
# - "nightly": documented for a future cron (the cron itself is out of P1.4
#   scope). It seeds from a run id via HYPOTHESIS_SEED, explores a far larger
#   max_examples, and prints the failing example blob (print_blob=True) so any
#   nightly counterexample can be pasted back as a permanent @example regression.
#   Select it with HYPOTHESIS_PROFILE=nightly (and set HYPOTHESIS_SEED=<run id>).
#
# Selection: HYPOTHESIS_PROFILE overrides; otherwise CI (env CI=true) picks "ci",
# a developer machine picks "dev".
# ---------------------------------------------------------------------------
settings.register_profile(
    "ci",
    max_examples=150,
    deadline=None,
    derandomize=True,
    print_blob=True,
    phases=(Phase.explicit, Phase.reuse, Phase.generate, Phase.target, Phase.shrink),
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.data_too_large,
        HealthCheck.filter_too_much,
    ],
)
settings.register_profile(
    "dev",
    max_examples=40,
    deadline=None,
    derandomize=False,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.data_too_large,
        HealthCheck.filter_too_much,
    ],
)
settings.register_profile(
    "nightly",
    max_examples=2000,
    deadline=None,
    derandomize=False,
    print_blob=True,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.data_too_large,
        HealthCheck.filter_too_much,
    ],
)
settings.load_profile(
    os.environ.get("HYPOTHESIS_PROFILE") or ("ci" if os.environ.get("CI") else "dev")
)

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
    """Truncates ledger + effects + audit tables before each test; returns the engine.

    The audit chain is global by construction (one gapless chain per database),
    so per-test isolation is a TRUNCATE + genesis re-seed — a test-harness
    reset of the whole chain, NOT a row deletion (which the append-only
    trigger forbids and the chain would detect). TRUNCATE is available here
    because the test role owns the table (the REVOKE strips it from PUBLIC).
    """
    from sqlalchemy import text

    from airlock.store._schema import seed_genesis

    with schema_engine.begin() as conn:
        conn.execute(text("TRUNCATE commit_records, paused_runs, effects_log RESTART IDENTITY"))
        conn.execute(text("TRUNCATE audit_events, audit_chain_head RESTART IDENTITY"))
    seed_genesis(schema_engine)
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


@pytest.fixture
def guard_isolation() -> Iterator[None]:
    """Isolate @guard tests: reset the ambient runtime AND the shared registry.

    ``airlock.init`` sets a process-wide contextvar and ``@guard`` populates the
    process-wide default registry; without a reset those leak across tests (a
    stale runtime, or a "already registered with a different registration"
    collision when two tests reuse an action_type). This fixture snapshots and
    restores both around a test. Request it in every @guard test (P2.1).
    """
    from airlock._guard import _runtime_var
    from airlock.registry import registry

    token = _runtime_var.set(None)
    saved_registrations = dict(registry._registrations)
    registry._registrations.clear()
    try:
        yield
    finally:
        registry._registrations.clear()
        registry._registrations.update(saved_registrations)
        _runtime_var.reset(token)
