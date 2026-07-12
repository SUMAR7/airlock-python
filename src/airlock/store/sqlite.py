"""SQLite-backed commit ledger — the zero-config quickstart store (P4.1).

**The guarantee (PLAN.md 3.7): all eight SPEC.md section-5 scenarios hold on a
single host / single volume — exactly-once commit, durable pause, and the
tamper-evident audit chain — with the SAME semantics as
:class:`~airlock.store.postgres.PostgresStore`, method for method. The ONLY
limitation is scope, not correctness: SQLite is a single-writer, single-host
database, so this store is for one process or a few cooperating processes on
one machine (dev, tests, a single-node quickstart), never a multi-host
deployment. Use Postgres in production. Nothing here weakens an ADR-1 / ADR-4 /
ADR-5 invariant to make SQLite pass; where Postgres uses a mechanism SQLite
lacks, the SQLite equivalent delivers the same end guarantee (documented at
each method).**

Built on the standard library's ``sqlite3`` — NO new runtime dependency, NO
sqlalchemy (that stays behind the ``postgres`` extra). ``import airlock`` and a
base install both stay import-light; ``sqlite3`` is stdlib.

How the Postgres semantics map onto SQLite
==========================================

- **Connection setup** (once per connection): ``PRAGMA journal_mode=WAL``
  (concurrent readers alongside one writer), ``PRAGMA busy_timeout`` (each
  lock-acquire waits up to this many ms — SQLite's own C-level busy handler, so
  it never trips the no-``time.sleep`` test guard), ``PRAGMA foreign_keys=ON``,
  ``PRAGMA synchronous=NORMAL`` (durable and WAL-safe). ``sqlite3`` connections
  are not shareable across threads, so this store keeps ONE connection PER
  THREAD (a ``threading.local``) and tracks them all for :meth:`close`.

- **The write lock is the serializer.** Every mutating method runs inside
  ``BEGIN IMMEDIATE`` — SQLite takes the database write lock UP FRONT rather
  than lazily upgrading a deferred transaction mid-statement, which is what
  avoids the ``SQLITE_BUSY`` deadlock two writers hit when both hold a read
  lock and try to upgrade. Combined with ``busy_timeout`` (and a bounded,
  sleep-free retry on the rare ``BEGIN IMMEDIATE`` contention miss), eight
  processes hammering one key serialize cleanly instead of flaking.

- **``claim``** = ``INSERT ... ON CONFLICT(idempotency_key) DO NOTHING
  RETURNING *`` inside ``BEGIN IMMEDIATE``; a conflict returns no row, so the
  existing row is read back in the SAME transaction (the write lock guarantees
  any competing insert already committed — SQLite's equivalent of the Postgres
  READ COMMITTED read-back).

- **``mark_executing`` / ``finalize`` / ``record_error`` / ``bump_epoch``** =
  the SAME epoch-guarded ``UPDATE ... WHERE ... AND attempts = :epoch`` with a
  ``rowcount`` check — a fenced writer matches zero rows and returns ``False``,
  exactly as on Postgres.

- **``stale_inflight`` / ``stale_approved_paused`` / ``stale_polled_paused``**:
  Postgres uses ``FOR UPDATE SKIP LOCKED`` so two reconcilers never contend on a
  row. SQLite has no such clause and does not need it: it is single-host, so the
  database write lock (taken by ``bump_epoch`` / ``apply_decision``) IS the
  cross-process serializer — a second reconciler that reads the same stale row
  loses the ``bump_epoch`` CAS (rowcount 0) and skips it. Each row is still
  recovered exactly once. These scans are therefore plain reads.

- **``append_audit`` / the finalize+append atomicity**: the chain-head row is
  read inside ``BEGIN IMMEDIATE`` (which already holds the whole-database write
  lock — the SQLite equivalent of Postgres's ``SELECT ... FOR UPDATE`` on the
  head singleton), so appenders across threads/processes are serialized and the
  gapless ``seq`` is assigned atomically. The ``row_hash`` is computed IN THE
  SDK (never a DB trigger). A finalize's terminal CAS and its chained audit
  append are ONE ``BEGIN IMMEDIATE`` transaction — both land or neither does.

- **Append-only audit**: SQLite has no ``REVOKE``, so ``audit_events`` is made
  append-only by ``BEFORE UPDATE`` / ``BEFORE DELETE`` triggers that
  ``RAISE(ABORT, ...)`` (``airlock.store._schema``) — the same end guarantee as
  the Postgres trigger, and the hash chain is the tamper evidence either way.

Dialect choices (PLAN.md 3.7)
=============================

- **Timestamps** (``TIMESTAMPTZ`` -> ``TEXT``): stored as fixed-width RFC3339
  UTC with microseconds, ``YYYY-MM-DDTHH:MM:SS.ffffff+00:00``
  (:func:`sqlite_dt_to_text`). Fixed width + a single UTC offset makes string
  comparison order == chronological order, so the staleness scans compare
  timestamps as TEXT correctly. Read back with :func:`sqlite_text_to_dt` to a
  tz-aware ``datetime``; the value round-trips to the same instant the audit
  chain hashes.
- **JSON** (``JSONB`` -> ``TEXT``): ``args_json`` / ``result_json`` /
  ``error_json`` / ``serialized_state`` / ``payload_json`` are stored as JSON
  text (canonical where the Postgres store canonicalizes) and parsed back with
  ``json.loads``.
- **Hashes** (``BYTEA`` -> ``BLOB``): ``prev_hash`` / ``row_hash`` are 32 raw
  bytes, stored and read as ``bytes``.
- **UUID** (``UUID`` -> ``TEXT``): ``approval_ref`` is stored as its string form.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import JsonValue

from airlock._canonical import canonical_json
from airlock.audit import compute_row_hash
from airlock.errors import AirlockError
from airlock.types import (
    IN_FLIGHT_LEDGER_STATES,
    PAUSE_TRANSITIONS,
    RESOLVED_PAUSE_STATUSES,
    TERMINAL_LEDGER_STATES,
    ApprovalDecision,
    AuditEvent,
    AuditHead,
    AuditRow,
    Claim,
    CommitRecord,
    Guarantee,
    LedgerState,
    PauseClaim,
    PausedRun,
    PauseStatus,
)

__all__ = ["SqliteStore", "sqlite_dt_to_text", "sqlite_path_from_url", "sqlite_text_to_dt"]

#: The default ``busy_timeout`` (ms): each lock-acquire waits up to this long
#: inside SQLite's C busy handler before raising. 5s is ample for the small,
#: fast transactions this store runs; the 8-process concurrency suite bumps it
#: via ``AIRLOCK_SQLITE_BUSY_TIMEOUT_MS`` / the DSN query so a loaded box's
#: contention never turns into a flake (PLAN.md 7).
DEFAULT_BUSY_TIMEOUT_MS = 5000

#: How many times to re-attempt ``BEGIN IMMEDIATE`` on a "database is locked"
#: miss. Each attempt is itself backed by ``busy_timeout`` (SQLite waits in C),
#: so this is a small, SLEEP-FREE multiplier on the total wait — never a
#: python-level ``time.sleep`` (which the test guard forbids). ``busy_timeout``
#: alone almost always suffices; the retry is belt-and-braces for the 8-process
#: barrier release where many writers arrive in the same instant.
_BEGIN_IMMEDIATE_RETRIES = 8


def _utcnow() -> datetime:
    return datetime.now(UTC)


def sqlite_dt_to_text(value: datetime) -> str:
    """Render a tz-aware ``datetime`` as fixed-width RFC3339 UTC text.

    ``YYYY-MM-DDTHH:MM:SS.ffffff+00:00`` — always UTC, always microseconds, so
    the width is constant and lexicographic order == chronological order (the
    staleness scans compare these as TEXT). A naive datetime is rejected: it has
    no defined instant, and storing a guess would corrupt both the staleness
    order and the audit hash round-trip.
    """
    if value.tzinfo is None:
        raise ValueError(
            f"SQLite timestamps must be timezone-aware, got naive {value!r} — a naive "
            "datetime has no defined UTC instant"
        )
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


def sqlite_text_to_dt(value: str | None) -> datetime | None:
    """Parse stored RFC3339 UTC text back to a tz-aware ``datetime`` (or ``None``)."""
    if value is None:
        return None
    return datetime.fromisoformat(value)


def _require_dt(value: str) -> datetime:
    """Parse a NOT NULL timestamp column (never ``None``) to a tz-aware datetime."""
    return datetime.fromisoformat(value)


def sqlite_path_from_url(url: str) -> str:
    """Extract the database file path (and no query) from a ``sqlite://`` DSN.

    Mirrors the SQLAlchemy convention: ``sqlite:///rel.db`` is the relative path
    ``rel.db``; ``sqlite:////abs.db`` is the absolute path ``/abs.db``;
    ``sqlite:///:memory:`` is the in-memory database. A bare filesystem path
    (no scheme) is returned unchanged. Any ``?query`` is stripped (parsed
    separately for options like ``busy_timeout_ms``).
    """
    raw = url
    if "://" in raw:
        scheme, _, rest = raw.partition("://")
        if scheme.lower() != "sqlite":
            raise ValueError(f"not a sqlite DSN: {url!r}")
        rest = rest.split("?", 1)[0]
        # netloc is empty for a local file DSN; strip exactly one leading slash
        # so sqlite:///rel -> rel (relative) and sqlite:////abs -> /abs.
        path = rest[1:] if rest.startswith("/") else rest
    else:
        path = raw.split("?", 1)[0]
    return path


def _busy_timeout_from_url(url: str, default: int) -> int:
    if "?" not in url:
        return default
    query = url.split("?", 1)[1]
    for pair in query.split("&"):
        name, _, value = pair.partition("=")
        if name in ("busy_timeout_ms", "busy_timeout"):
            try:
                return int(value)
            except ValueError:
                return default
    return default


def _is_locked_error(exc: sqlite3.OperationalError) -> bool:
    message = str(exc).lower()
    return "locked" in message or "busy" in message


# --- Row -> model mappers ----------------------------------------------------


def _json_or_none(value: str | None) -> JsonValue:
    return None if value is None else json.loads(value)


def _row_to_record(row: sqlite3.Row) -> CommitRecord:
    return CommitRecord(
        id=row["id"],
        idempotency_key=row["idempotency_key"],
        action_type=row["action_type"],
        state=LedgerState(row["state"]),
        guarantee=Guarantee(row["guarantee"]),
        args_json=json.loads(row["args_json"]),
        downstream_key=row["downstream_key"],
        run_id=row["run_id"],
        result_json=_json_or_none(row["result_json"]),
        error_json=_json_or_none(row["error_json"]),
        attempts=row["attempts"],
        last_attempt_at=_require_dt(row["last_attempt_at"]),
        created_at=_require_dt(row["created_at"]),
        committed_at=sqlite_text_to_dt(row["committed_at"]),
    )


def _row_to_paused(row: sqlite3.Row) -> PausedRun:
    return PausedRun(
        id=row["id"],
        run_id=row["run_id"],
        idempotency_key=row["idempotency_key"],
        approval_ref=str(row["approval_ref"]),
        approval_id=row["approval_id"],
        action_type=row["action_type"],
        serialized_state=json.loads(row["serialized_state"]),
        state_version=row["state_version"],
        status=PauseStatus(row["status"]),
        approved_action_json=_json_or_none(row["approved_action_json"]),
        decided_by=row["decided_by"],
        decided_by_display=row["decided_by_display"],
        decided_at=sqlite_text_to_dt(row["decided_at"]),
        decision_latency_ms=row["decision_latency_ms"],
        reason=row["reason"],
        reason_code=row["reason_code"],
        created_at=_require_dt(row["created_at"]),
        resolved_at=sqlite_text_to_dt(row["resolved_at"]),
    )


def _row_to_audit(row: sqlite3.Row) -> AuditRow:
    return AuditRow(
        id=row["id"],
        seq=row["seq"],
        run_id=row["run_id"],
        action_type=row["action_type"],
        event_type=row["event_type"],
        payload=json.loads(row["payload_json"]),
        prev_hash=bytes(row["prev_hash"]),
        row_hash=bytes(row["row_hash"]),
        created_at=_require_dt(row["created_at"]),
    )


# --- SQL (dialect-adapted from postgres.py; same semantics) ------------------

_CLAIM_SQL = """
    INSERT INTO commit_records
        (idempotency_key, action_type, state, guarantee, args_json,
         downstream_key, attempts, last_attempt_at, created_at)
    VALUES
        (:key, :action_type, :pending, :guarantee, :args_json,
         :downstream_key, 1, :now, :now)
    ON CONFLICT (idempotency_key) DO NOTHING
    RETURNING *
"""

_LOAD_SQL = "SELECT * FROM commit_records WHERE idempotency_key = :key"

_MARK_EXECUTING_SQL = """
    UPDATE commit_records
       SET state = :executing, last_attempt_at = :now
     WHERE idempotency_key = :key AND state = :pending AND attempts = :epoch
"""

_IN_FLIGHT_STATE_LIST = ", ".join(f"'{state.value}'" for state in IN_FLIGHT_LEDGER_STATES)

_RECORD_ERROR_SQL = f"""
    UPDATE commit_records
       SET error_json = :error_json
     WHERE idempotency_key = :key
       AND state IN ({_IN_FLIGHT_STATE_LIST})
       AND attempts = :epoch
"""

_STALE_INFLIGHT_SQL = f"""
    SELECT * FROM commit_records
     WHERE state IN ({_IN_FLIGHT_STATE_LIST})
       AND last_attempt_at < :cutoff
     ORDER BY last_attempt_at
"""

_BUMP_EPOCH_SQL = f"""
    UPDATE commit_records
       SET attempts = attempts + 1, last_attempt_at = :now
     WHERE idempotency_key = :key
       AND state IN ({_IN_FLIGHT_STATE_LIST})
       AND last_attempt_at < :cutoff
    RETURNING attempts
"""

_SAVE_PAUSED_SQL = """
    INSERT INTO paused_runs
        (run_id, idempotency_key, approval_ref, action_type, serialized_state,
         state_version, status, created_at)
    VALUES
        (:run_id, :key, :approval_ref, :action_type, :serialized_state,
         :state_version, :proposed, :now)
    ON CONFLICT (idempotency_key) DO NOTHING
    RETURNING *
"""

_LOAD_PAUSED_BY_KEY_SQL = "SELECT * FROM paused_runs WHERE idempotency_key = :key"

_LOAD_PAUSED_BY_REF_SQL = "SELECT * FROM paused_runs WHERE approval_ref = :approval_ref"

_STALE_APPROVED_SQL = f"""
    SELECT * FROM paused_runs
     WHERE status = '{PauseStatus.APPROVED.value}'
       AND decided_at < :cutoff
     ORDER BY decided_at
"""

_SET_APPROVAL_ID_SQL = "UPDATE paused_runs SET approval_id = :approval_id WHERE run_id = :run_id"

_STALE_POLLED_SQL = f"""
    SELECT * FROM paused_runs
     WHERE status = '{PauseStatus.PROPOSED.value}'
       AND approval_id IS NOT NULL
       AND created_at < :cutoff
     ORDER BY created_at
"""

_AUDIT_HEAD_READ_SQL = "SELECT seq, row_hash FROM audit_chain_head WHERE singleton = 1"

_AUDIT_INSERT_SQL = """
    INSERT INTO audit_events
        (seq, run_id, action_type, event_type, payload_json, prev_hash, row_hash, created_at)
    VALUES
        (:seq, :run_id, :action_type, :event_type, :payload, :prev_hash, :row_hash, :created_at)
    RETURNING *
"""

_AUDIT_HEAD_UPDATE_SQL = (
    "UPDATE audit_chain_head SET seq = :seq, row_hash = :row_hash WHERE singleton = 1"
)

_AUDIT_ITER_SQL = "SELECT * FROM audit_events WHERE seq >= :start ORDER BY seq"


def _transition_paused_sql(with_decision: bool) -> str:
    decision_sets = (
        """,
               decided_by = :decided_by,
               decided_by_display = :decided_by_display,
               decided_at = :decided_at,
               decision_latency_ms = :decision_latency_ms,
               reason = :reason,
               reason_code = :reason_code"""
        if with_decision
        else ""
    )
    return f"""
        UPDATE paused_runs
           SET status = :to_status,
               resolved_at = :resolved_at{decision_sets}
         WHERE run_id = :run_id AND status = :from_status
    """


_TRANSITION_PAUSED_SQL = _transition_paused_sql(with_decision=False)
_TRANSITION_PAUSED_WITH_DECISION_SQL = _transition_paused_sql(with_decision=True)


def _finalize_sql(from_states: tuple[LedgerState, ...]) -> str:
    state_list = ", ".join(f"'{state.value}'" for state in from_states)
    return f"""
        UPDATE commit_records
           SET state = :state,
               result_json = :result_json,
               committed_at = :committed_at
         WHERE idempotency_key = :key AND attempts = :epoch AND state IN ({state_list})
    """


# Legal finalize transitions per target state — IDENTICAL to postgres.py
# (PLAN.md 3.2): committed only from executing; aborted from any in-flight;
# failed/unknown only from executing (both are statements about an executed
# effect, false for a provably effect-free pending row).
_FINALIZE_FROM_STATES: dict[LedgerState, tuple[LedgerState, ...]] = {
    LedgerState.COMMITTED: (LedgerState.EXECUTING,),
    LedgerState.ABORTED: IN_FLIGHT_LEDGER_STATES,
    LedgerState.FAILED: (LedgerState.EXECUTING,),
    LedgerState.UNKNOWN: (LedgerState.EXECUTING,),
}
_FINALIZE_SQL: dict[LedgerState, str] = {
    target: _finalize_sql(from_states) for target, from_states in _FINALIZE_FROM_STATES.items()
}


class SqliteStore:
    """The ledger of record on a local SQLite file (ADR-1) — single host.

    Semantics match :class:`~airlock.store.postgres.PostgresStore` method for
    method (see the module docstring for the mechanism mapping). ``now_fn`` is
    injectable (PLAN.md 7 determinism substrate): every persisted timestamp is
    SDK-supplied, never a DB default.

    Args:
        path: the database file path, or a ``sqlite://`` DSN (parsed via
            :func:`sqlite_path_from_url`). ``:memory:`` works for a single
            connection but is not shareable across processes.
        now_fn: the injectable clock.
        busy_timeout_ms: how long each lock-acquire waits before raising
            (default :data:`DEFAULT_BUSY_TIMEOUT_MS`, overridable via the
            ``AIRLOCK_SQLITE_BUSY_TIMEOUT_MS`` env var or a ``?busy_timeout_ms=``
            DSN query).
    """

    def __init__(
        self,
        path: str,
        *,
        now_fn: Callable[[], datetime] = _utcnow,
        busy_timeout_ms: int | None = None,
    ) -> None:
        env_default = os.environ.get("AIRLOCK_SQLITE_BUSY_TIMEOUT_MS")
        default_busy = int(env_default) if env_default else DEFAULT_BUSY_TIMEOUT_MS
        if busy_timeout_ms is None:
            busy_timeout_ms = _busy_timeout_from_url(path, default_busy)
        self._path = sqlite_path_from_url(path)
        self._now_fn = now_fn
        self._busy_timeout_ms = busy_timeout_ms
        self._local = threading.local()
        self._all_conns: list[sqlite3.Connection] = []
        self._lock = threading.Lock()

    # -- connection management (one connection per thread) --------------------

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                self._path,
                # isolation_level=None -> autocommit; we drive BEGIN IMMEDIATE /
                # COMMIT / ROLLBACK explicitly so the write lock is taken up front.
                isolation_level=None,
                # A thread never shares its connection with another thread; the
                # threading.local guarantees that, so we can relax the check for
                # frameworks that hand a fresh worker thread the same store.
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
            with self._lock:
                self._all_conns.append(conn)
        return conn

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        """Run a mutating transaction under ``BEGIN IMMEDIATE`` (write lock up front).

        The write lock is taken before any statement, so two writers serialize
        cleanly instead of both grabbing a read lock and deadlocking on the
        upgrade (the classic ``SQLITE_BUSY``). ``busy_timeout`` waits (in C) for
        the lock; a bounded, sleep-free retry covers the rare miss when many
        writers arrive at once (the 8-process barrier). Commits on success,
        rolls back on any exception.
        """
        conn = self._conn()
        last_exc: sqlite3.OperationalError | None = None
        for _attempt in range(_BEGIN_IMMEDIATE_RETRIES):
            try:
                conn.execute("BEGIN IMMEDIATE")
                break
            except sqlite3.OperationalError as exc:
                if _is_locked_error(exc):
                    last_exc = exc
                    continue  # busy_timeout already waited; try again
                raise
        else:  # pragma: no cover - only under pathological sustained contention
            raise AirlockError(
                "SQLite could not acquire the write lock (BEGIN IMMEDIATE) after "
                f"{_BEGIN_IMMEDIATE_RETRIES} attempts, each backed by a "
                f"{self._busy_timeout_ms}ms busy_timeout — sustained contention. "
                "SQLite is single-host; raise busy_timeout or reduce writer fan-out."
            ) from last_exc
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")

    def ensure_schema(self) -> None:
        """Create the ledger + audit schema if missing (idempotent)."""
        from airlock.store._schema import ensure_sqlite_schema

        with self._write() as conn:
            ensure_sqlite_schema(conn)

    def close(self) -> None:
        """Close every per-thread connection opened by this store."""
        with self._lock:
            conns = list(self._all_conns)
            self._all_conns.clear()
        for conn in conns:
            with suppress(sqlite3.Error):  # best-effort teardown
                conn.close()
        self._local = threading.local()

    # -- ledger (ADR-1) -------------------------------------------------------

    def claim(
        self,
        key: str,
        action_type: str,
        guarantee: Guarantee,
        args_json: Mapping[str, JsonValue],
        downstream_key: str | None,
    ) -> Claim:
        now = sqlite_dt_to_text(self._now_fn())
        with self._write() as conn:
            inserted = conn.execute(
                _CLAIM_SQL,
                {
                    "key": key,
                    "action_type": action_type,
                    "pending": LedgerState.PENDING.value,
                    "guarantee": guarantee.value,
                    "args_json": json.dumps(dict(args_json)),
                    "downstream_key": downstream_key,
                    "now": now,
                },
            ).fetchone()
            if inserted is not None:
                return Claim(won=True, record=_row_to_record(inserted))
            # Conflict: the write lock guarantees the competing insert already
            # committed, so this same-transaction read sees the winner.
            existing = conn.execute(_LOAD_SQL, {"key": key}).fetchone()
        if existing is None:
            raise AirlockError(
                f"claim for key {key!r} conflicted but the row is gone — "
                "ledger rows must never be deleted (ADR-1)"
            )
        return Claim(won=False, record=_row_to_record(existing))

    def mark_executing(self, key: str, epoch: int) -> bool:
        now = sqlite_dt_to_text(self._now_fn())
        with self._write() as conn:
            rowcount = conn.execute(
                _MARK_EXECUTING_SQL,
                {
                    "key": key,
                    "epoch": epoch,
                    "now": now,
                    "executing": LedgerState.EXECUTING.value,
                    "pending": LedgerState.PENDING.value,
                },
            ).rowcount
        return rowcount == 1

    def record_error(self, key: str, epoch: int, error_json: JsonValue) -> bool:
        with self._write() as conn:
            rowcount = conn.execute(
                _RECORD_ERROR_SQL,
                {"key": key, "epoch": epoch, "error_json": json.dumps(error_json)},
            ).rowcount
        return rowcount == 1

    def finalize(
        self,
        key: str,
        epoch: int,
        state: LedgerState,
        result_json: JsonValue,
        audit: object | None,
    ) -> bool:
        if state not in TERMINAL_LEDGER_STATES:
            raise ValueError(f"finalize target must be a terminal state, got {state!r}")
        if audit is not None and not isinstance(audit, AuditEvent):
            raise TypeError(
                f"finalize audit must be an airlock.types.AuditEvent or None, "
                f"got {type(audit).__name__}"
            )
        committed = state is LedgerState.COMMITTED
        sql = _FINALIZE_SQL[state]
        with self._write() as conn:
            rowcount = conn.execute(
                sql,
                {
                    "key": key,
                    "epoch": epoch,
                    "state": state.value,
                    "result_json": None if result_json is None else json.dumps(result_json),
                    "committed_at": sqlite_dt_to_text(self._now_fn()) if committed else None,
                },
            ).rowcount
            # The terminal CAS and the chained audit append are ONE transaction:
            # both land or neither does. The append happens ONLY when the CAS
            # matched — a fenced finalize must not put a false statement on the
            # tamper-evident chain (identical to postgres.py).
            if rowcount == 1 and audit is not None:
                self._append_audit_on(conn, audit)
        return rowcount == 1

    def load(self, key: str) -> CommitRecord | None:
        conn = self._conn()
        row = conn.execute(_LOAD_SQL, {"key": key}).fetchone()
        return None if row is None else _row_to_record(row)

    def stale_inflight(self, older_than: timedelta) -> list[CommitRecord]:
        cutoff = sqlite_dt_to_text(self._now_fn() - older_than)
        conn = self._conn()
        rows = conn.execute(_STALE_INFLIGHT_SQL, {"cutoff": cutoff}).fetchall()
        return [_row_to_record(row) for row in rows]

    def bump_epoch(self, key: str, older_than: timedelta) -> int | None:
        now = self._now_fn()
        cutoff = sqlite_dt_to_text(now - older_than)
        with self._write() as conn:
            row = conn.execute(
                _BUMP_EPOCH_SQL,
                {"key": key, "now": sqlite_dt_to_text(now), "cutoff": cutoff},
            ).fetchone()
        return None if row is None else int(row["attempts"])

    # -- pause (ADR-4) --------------------------------------------------------

    def save_paused(
        self,
        *,
        run_id: str,
        idempotency_key: str,
        approval_ref: str,
        action_type: str,
        serialized_state: Mapping[str, JsonValue],
        state_version: int = 1,
        audit: AuditEvent | None = None,
    ) -> PauseClaim:
        now = sqlite_dt_to_text(self._now_fn())
        with self._write() as conn:
            inserted = conn.execute(
                _SAVE_PAUSED_SQL,
                {
                    "run_id": run_id,
                    "key": idempotency_key,
                    "approval_ref": approval_ref,
                    "action_type": action_type,
                    # Canonicalized here (like postgres.py) so a value outside the
                    # airlock-canon-1 domain fails BEFORE anything is durable.
                    "serialized_state": canonical_json(dict(serialized_state)),
                    "state_version": state_version,
                    "proposed": PauseStatus.PROPOSED.value,
                    "now": now,
                },
            ).fetchone()
            if inserted is not None:
                if audit is not None:
                    self._append_audit_on(conn, audit)
                return PauseClaim(created=True, run=_row_to_paused(inserted))
            existing = conn.execute(_LOAD_PAUSED_BY_KEY_SQL, {"key": idempotency_key}).fetchone()
        if existing is None:
            raise AirlockError(
                f"save_paused for key {idempotency_key!r} conflicted but the row is gone — "
                "paused_runs rows must never be deleted (ADR-4)"
            )
        return PauseClaim(created=False, run=_row_to_paused(existing))

    def load_paused_by_ref(self, approval_ref: str) -> PausedRun | None:
        conn = self._conn()
        row = conn.execute(_LOAD_PAUSED_BY_REF_SQL, {"approval_ref": approval_ref}).fetchone()
        return None if row is None else _row_to_paused(row)

    def transition_paused(
        self,
        run_id: str,
        from_status: PauseStatus,
        to_status: PauseStatus,
        *,
        decision: ApprovalDecision | None = None,
        audit: AuditEvent | tuple[AuditEvent, ...] | None = None,
    ) -> bool:
        if (from_status, to_status) not in PAUSE_TRANSITIONS:
            raise ValueError(
                f"illegal paused_runs transition {from_status.value!r} -> "
                f"{to_status.value!r}: the ADR-4 state machine allows exactly "
                f"proposed -> approved|rejected -> committed|aborted (PLAN.md 3.2)"
            )
        resolved_at = self._now_fn() if to_status in RESOLVED_PAUSE_STATUSES else None
        params: dict[str, Any] = {
            "run_id": run_id,
            "from_status": from_status.value,
            "to_status": to_status.value,
            "resolved_at": None if resolved_at is None else sqlite_dt_to_text(resolved_at),
        }
        if decision is not None:
            decided_at = decision.decided_at if decision.decided_at is not None else self._now_fn()
            params.update(
                {
                    "decided_by": decision.decided_by,
                    "decided_by_display": decision.decided_by_display,
                    "decided_at": sqlite_dt_to_text(decided_at),
                    "decision_latency_ms": decision.decision_latency_ms,
                    "reason": decision.reason,
                    "reason_code": decision.reason_code,
                }
            )
            sql = _TRANSITION_PAUSED_WITH_DECISION_SQL
        else:
            sql = _TRANSITION_PAUSED_SQL
        events: tuple[AuditEvent, ...]
        if audit is None:
            events = ()
        elif isinstance(audit, AuditEvent):
            events = (audit,)
        else:
            events = tuple(audit)
        with self._write() as conn:
            rowcount = conn.execute(sql, params).rowcount
            if rowcount == 1:
                for event in events:
                    self._append_audit_on(conn, event)
        return rowcount == 1

    def stale_approved_paused(self, older_than: timedelta) -> list[PausedRun]:
        cutoff = sqlite_dt_to_text(self._now_fn() - older_than)
        conn = self._conn()
        rows = conn.execute(_STALE_APPROVED_SQL, {"cutoff": cutoff}).fetchall()
        return [_row_to_paused(row) for row in rows]

    def set_approval_id(self, run_id: str, approval_id: str) -> bool:
        with self._write() as conn:
            rowcount = conn.execute(
                _SET_APPROVAL_ID_SQL, {"run_id": run_id, "approval_id": approval_id}
            ).rowcount
        return rowcount == 1

    def stale_polled_paused(self, older_than: timedelta) -> list[PausedRun]:
        cutoff = sqlite_dt_to_text(self._now_fn() - older_than)
        conn = self._conn()
        rows = conn.execute(_STALE_POLLED_SQL, {"cutoff": cutoff}).fetchall()
        return [_row_to_paused(row) for row in rows]

    # -- audit (ADR-5) --------------------------------------------------------

    def append_audit(self, event: AuditEvent) -> AuditRow:
        """Append one hash-chained audit row in its own transaction (ADR-5)."""
        with self._write() as conn:
            return self._append_audit_on(conn, event)

    def _append_audit_on(self, conn: sqlite3.Connection, event: AuditEvent) -> AuditRow:
        """The append protocol (PLAN.md 5.1/5.2), on the CALLER'S BEGIN IMMEDIATE.

        The enclosing ``BEGIN IMMEDIATE`` already holds the whole-database write
        lock — the SQLite equivalent of Postgres's ``SELECT ... FOR UPDATE`` on
        the head singleton — so appenders serialize and ``seq`` is gapless by
        construction. ``row_hash`` is computed IN THE SDK; a payload outside the
        airlock-canon-1 domain raises HERE, before any write, aborting the whole
        transaction (the finalize+append atomicity tests inject exactly this).
        """
        head = conn.execute(_AUDIT_HEAD_READ_SQL).fetchone()
        if head is None:
            raise AirlockError(
                "audit_chain_head is missing — the audit schema is not initialized; "
                "run ensure_schema() before appending audit events (ADR-5)"
            )
        seq = int(head["seq"]) + 1
        prev_hash = bytes(head["row_hash"])
        created_at = event.created_at if event.created_at is not None else self._now_fn()
        row_hash = compute_row_hash(
            prev_hash,
            seq=seq,
            run_id=event.run_id,
            action_type=event.action_type,
            event_type=event.event_type,
            created_at=created_at,
            payload=event.payload,
        )
        inserted = conn.execute(
            _AUDIT_INSERT_SQL,
            {
                "seq": seq,
                "run_id": event.run_id,
                "action_type": event.action_type,
                "event_type": event.event_type,
                "payload": canonical_json(event.payload),
                "prev_hash": prev_hash,
                "row_hash": row_hash,
                "created_at": sqlite_dt_to_text(created_at),
            },
        ).fetchone()
        conn.execute(_AUDIT_HEAD_UPDATE_SQL, {"seq": seq, "row_hash": row_hash})
        return _row_to_audit(inserted)

    def audit_head(self) -> AuditHead | None:
        conn = self._conn()
        head = conn.execute(_AUDIT_HEAD_READ_SQL).fetchone()
        if head is None:
            return None
        return AuditHead(seq=int(head["seq"]), row_hash=bytes(head["row_hash"]))

    def iter_audit(self, start_seq: int = 0) -> Iterator[AuditRow]:
        """Stream audit rows ``ORDER BY seq`` from ``start_seq`` (inclusive).

        Uses a DEDICATED short-lived connection so the streaming cursor never
        interferes with the store's per-thread connection, and streams in
        batches (``fetchmany``) for constant memory — the O(n)
        ``verify_chain`` read path.
        """
        conn = sqlite3.connect(self._path, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
        try:
            cursor = conn.execute(_AUDIT_ITER_SQL, {"start": start_seq})
            while True:
                rows = cursor.fetchmany(500)
                if not rows:
                    break
                for row in rows:
                    yield _row_to_audit(row)
        finally:
            conn.close()
