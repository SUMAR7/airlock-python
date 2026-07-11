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

import json
import os
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid4

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
# The store backend MATRIX (P4.1, PLAN.md 7 / 10.10).
#
# The store-backed suites run against BOTH backends — Postgres (the production
# substrate of record) and SQLite (the single-host quickstart) — so the full
# Section-9 suite proves SqliteStore holds the SAME ADR-1/4/5 guarantees.
#
# The matrix is OPT-IN, so the existing Postgres-only suites (which assert
# Postgres internals: xmin provenance, SERIALIZABLE pinning, pg_get_constraintdef)
# are untouched. A test file joins the matrix with ``pytestmark =
# pytest.mark.matrix`` (or a per-test ``@pytest.mark.matrix``); everything else
# stays Postgres-only. ``pytest_generate_tests`` parametrizes the shared
# ``backend`` fixture: ["postgres"] by default, ["postgres", "sqlite"] for a
# matrix test. Because ``store`` / ``clock_store`` / ``db`` / ``effects`` /
# ``store_dsn`` all derive from ``backend``, a matrix file's tests fan out over
# both backends with no per-test change.
# ---------------------------------------------------------------------------

_BACKENDS_DEFAULT = ("postgres",)
_BACKENDS_MATRIX = ("postgres", "sqlite")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "matrix: run this test on BOTH store backends (postgres + sqlite) — P4.1",
    )


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Parametrize ``backend`` for any test that reaches it (transitively).

    A test that requests ``store`` / ``clock_store`` / ``db`` / ``effects`` /
    ``store_dsn`` has ``backend`` in its transitive fixture set. Default:
    postgres only (identical to pre-P4.1 behavior). With the ``matrix`` marker
    (per-test or module ``pytestmark``): postgres AND sqlite.
    """
    if "backend" not in metafunc.fixturenames:
        return
    marked = metafunc.definition.get_closest_marker("matrix") is not None
    backends = _BACKENDS_MATRIX if marked else _BACKENDS_DEFAULT
    metafunc.parametrize("backend", backends, indirect=True)


_SQLITE_EFFECTS_LOG_DDL = """
CREATE TABLE IF NOT EXISTS effects_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    idempotency_key TEXT NOT NULL,
    worker_pid      INTEGER NOT NULL,
    logged_at       TEXT DEFAULT CURRENT_TIMESTAMP
)
"""

#: How long a busy SQLite lock-acquire waits in tests (ms). Generous so the
#: 8-process barrier release never turns box contention into a flake (PLAN.md 7);
#: SQLite waits in C, so this never trips the no-time.sleep guard.
SQLITE_TEST_BUSY_TIMEOUT_MS = 30000


class _Backend:
    """A store backend under test: builds stores/effects, resets, raw-reads.

    One instance per test (function-scoped ``backend`` fixture). Postgres reuses
    the session schema engine + truncate; SQLite gets a FRESH file per test (so
    "reset" is a fresh DB — sidestepping the audit append-only DELETE the
    triggers forbid).
    """

    name: str
    engine: Any  # sqlalchemy Engine for raw test reads (both backends)
    dsn: str  # a DSN a spawn subprocess rebuilds a store from (from_url)

    def make_store(self, now_fn: Any | None = None) -> Any:  # pragma: no cover - overridden
        raise NotImplementedError

    def make_effects(self) -> EffectsLog:  # pragma: no cover - overridden
        raise NotImplementedError

    def teardown(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError


class _PostgresBackend(_Backend):
    name = "postgres"

    def __init__(self, database_url: str, schema_engine: Any) -> None:
        from sqlalchemy import text

        self.dsn = database_url
        self.engine = schema_engine
        with schema_engine.begin() as conn:
            conn.execute(text("TRUNCATE commit_records, paused_runs, effects_log RESTART IDENTITY"))
            conn.execute(text("TRUNCATE audit_events, audit_chain_head RESTART IDENTITY"))
        from airlock.store._schema import seed_genesis

        seed_genesis(schema_engine)

    def make_store(self, now_fn: Any | None = None) -> Any:
        from airlock.store.postgres import PostgresStore

        return PostgresStore(self.dsn, now_fn=now_fn) if now_fn else PostgresStore(self.dsn)

    def make_effects(self) -> EffectsLog:
        from sqlalchemy import create_engine

        from airlock.store.postgres import normalize_postgres_url

        engine = create_engine(normalize_postgres_url(self.dsn), isolation_level="AUTOCOMMIT")
        return EffectsLog(engine, use_pg_pid=True, owns_engine=True)

    def teardown(self) -> None:
        pass  # the session schema engine is reused; nothing per-test to dispose


class _SqliteBackend(_Backend):
    name = "sqlite"

    def __init__(self, path: str) -> None:
        from sqlalchemy import create_engine, text

        self._path = path
        self.dsn = f"sqlite:///{path}?busy_timeout_ms={SQLITE_TEST_BUSY_TIMEOUT_MS}"
        # Create schema (and set WAL) via a real SqliteStore, then a sqlalchemy
        # engine for raw test reads/writes with a matching busy timeout.
        from airlock.store.sqlite import SqliteStore

        setup = SqliteStore(path, busy_timeout_ms=SQLITE_TEST_BUSY_TIMEOUT_MS)
        setup.ensure_schema()
        setup.close()
        self.engine = create_engine(
            f"sqlite+pysqlite:///{path}",
            connect_args={"timeout": SQLITE_TEST_BUSY_TIMEOUT_MS / 1000},
        )
        with self.engine.begin() as conn:
            conn.execute(text(_SQLITE_EFFECTS_LOG_DDL))

    def make_store(self, now_fn: Any | None = None) -> Any:
        from airlock.store.sqlite import SqliteStore

        return SqliteStore(
            self._path, now_fn=now_fn or _default_now, busy_timeout_ms=SQLITE_TEST_BUSY_TIMEOUT_MS
        )

    def make_effects(self) -> EffectsLog:
        return EffectsLog(self.engine, use_pg_pid=False, owns_engine=False)

    def teardown(self) -> None:
        self.engine.dispose()


def _default_now() -> datetime:
    from datetime import UTC

    return datetime.now(UTC)


@pytest.fixture
def backend(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> Any:
    """The store backend under test (see the matrix docstring above)."""
    param = getattr(request, "param", "postgres")
    if param == "postgres":
        schema_engine = request.getfixturevalue("schema_engine")
        database_url = request.getfixturevalue("database_url")
        b: _Backend = _PostgresBackend(database_url, schema_engine)
    else:
        path = tmp_path_factory.mktemp("airlock_sqlite") / f"{uuid4().hex}.db"
        b = _SqliteBackend(str(path))
    try:
        yield b
    finally:
        b.teardown()


def make_effects_for_dsn(dsn: str) -> EffectsLog:
    """Build an :class:`EffectsLog` from a DSN alone (spawn-subprocess helper).

    A concurrency/crash worker re-imports this module fresh (no fixture graph)
    and needs the SAME ground-truth ``effects_log`` counter the parent reads,
    on the SAME backend — dispatched by DSN scheme.
    """
    from sqlalchemy import create_engine

    if dsn.startswith("sqlite:"):
        from airlock.store.sqlite import sqlite_path_from_url

        engine = create_engine(
            f"sqlite+pysqlite:///{sqlite_path_from_url(dsn)}",
            connect_args={"timeout": SQLITE_TEST_BUSY_TIMEOUT_MS / 1000},
        )
        return EffectsLog(engine, use_pg_pid=False, owns_engine=True)
    from airlock.store.postgres import normalize_postgres_url

    engine = create_engine(normalize_postgres_url(dsn), isolation_level="AUTOCOMMIT")
    return EffectsLog(engine, use_pg_pid=True, owns_engine=True)

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
settings.register_profile(
    "noshrink",
    max_examples=200,
    deadline=None,
    derandomize=False,
    print_blob=True,
    phases=(Phase.explicit, Phase.reuse, Phase.generate, Phase.target),  # no shrink
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
def db(backend: _Backend) -> Any:
    """The raw-read sqlalchemy Engine for the backend under test.

    The backend already reset itself (Postgres: TRUNCATE + genesis re-seed;
    SQLite: a fresh file) when the ``backend`` fixture built it, so this simply
    exposes the engine. The audit chain is global per database, so the reset is
    a test-harness whole-chain reset (Postgres) or a fresh file (SQLite), never
    a row DELETE (the append-only trigger forbids that and the chain detects it).
    """
    return backend.engine


@pytest.fixture
def store(backend: _Backend) -> Iterator[Any]:
    st = backend.make_store()
    yield st
    st.close()


@pytest.fixture
def store_dsn(backend: _Backend) -> str:
    """A DSN a spawn subprocess rebuilds the SAME-backend store from (from_url)."""
    return backend.dsn


class EffectsLog:
    """Ground-truth side-effect counter on a dedicated connection (both backends).

    Postgres logs ``pg_backend_pid()``; SQLite logs the OS pid (``os.getpid()``)
    — the pid column is only ever asserted-against via the worker's own report,
    not this table, so either identifier is ground truth for the count that
    matters (side-effect count per key).
    """

    def __init__(self, engine: Any, *, use_pg_pid: bool, owns_engine: bool) -> None:
        self._engine = engine
        self._use_pg_pid = use_pg_pid
        self._owns_engine = owns_engine

    def log(self, key: str) -> None:
        from sqlalchemy import text

        with self._engine.connect() as conn:
            if self._use_pg_pid:
                conn.execute(
                    text(
                        "INSERT INTO effects_log (idempotency_key, worker_pid)"
                        " VALUES (:key, pg_backend_pid())"
                    ),
                    {"key": key},
                )
            else:
                conn.execute(
                    text(
                        "INSERT INTO effects_log (idempotency_key, worker_pid)"
                        " VALUES (:key, :pid)"
                    ),
                    {"key": key, "pid": os.getpid()},
                )
                conn.commit()

    def count(self, key: str) -> int:
        from sqlalchemy import text

        with self._engine.connect() as conn:
            found = conn.execute(
                text("SELECT count(*) FROM effects_log WHERE idempotency_key = :key"),
                {"key": key},
            ).scalar_one()
        return int(found)

    def dispose(self) -> None:
        if self._owns_engine:
            self._engine.dispose()


@pytest.fixture
def effects(backend: _Backend) -> Iterator[EffectsLog]:
    log = backend.make_effects()
    yield log
    log.dispose()


def bump_epoch(engine: Any, key: str) -> None:
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
def clock_store(backend: _Backend, fake_clock: FakeClock) -> Iterator[Any]:
    """A store whose ``now_fn`` is the shared :class:`FakeClock`.

    The store computes the staleness cutoff from this clock, so a reconciler
    given the same ``fake_clock`` scans exactly the rows the test intends.
    """
    st = backend.make_store(now_fn=fake_clock)
    yield st
    st.close()


class _Row:
    """A backend-neutral commit_records row view (attribute access).

    JSON columns are parsed to Python objects regardless of backend (Postgres
    JSONB returns dicts; SQLite TEXT returns JSON strings — parsed here), so a
    test's ``row.result_json == {...}`` holds on both.
    """

    __slots__ = (
        "attempts",
        "committed_at",
        "downstream_key",
        "error_json",
        "guarantee",
        "result_json",
        "state",
    )

    def __init__(self, mapping: dict[str, Any]) -> None:
        self.state = mapping["state"]
        self.guarantee = mapping["guarantee"]
        self.attempts = mapping["attempts"]
        self.downstream_key = mapping["downstream_key"]
        self.result_json = _maybe_json(mapping["result_json"])
        self.error_json = _maybe_json(mapping["error_json"])
        self.committed_at = mapping["committed_at"]


def _maybe_json(value: Any) -> Any:
    """Parse a JSON string (SQLite TEXT column) to Python; pass dicts through."""
    if isinstance(value, str):
        return json.loads(value)
    return value


def read_row(engine: Any, key: str) -> _Row:
    """Read a commit_records row from a FRESH connection (durability check)."""
    from sqlalchemy import text

    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT state, guarantee, attempts, downstream_key, result_json, error_json,"
                " committed_at FROM commit_records WHERE idempotency_key = :key"
            ),
            {"key": key},
        ).mappings().one()
    return _Row(dict(row))


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
