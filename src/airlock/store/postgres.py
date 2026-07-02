"""Postgres-backed commit ledger (PLAN.md sections 4.1 and 5.1).

SQLAlchemy CORE only (no ORM), psycopg3 driver. This module is imported
lazily — via ``airlock.store.from_url`` or an explicit import — so the base
``import airlock`` never pulls in sqlalchemy (the import-light CI guard).

Transaction boundaries are the whole point (PLAN.md 4.1); every method below
runs in its own short transaction, never held open across the caller's
side effect:

- ``claim``          INSERT ... ON CONFLICT DO NOTHING, committed before
                     anything else executes.
- ``mark_executing`` CAS pending -> executing, committed BEFORE the effect
                     is invoked — that ordering is what makes a ``pending``
                     row provably effect-free.
- ``record_error``   epoch-guarded error_json write; state stays ``executing``.
- ``finalize``       CAS to a terminal state; ONE transaction that P2.2 will
                     extend with the hash-chained audit append (same
                     signature, same transaction).
- ``load``           plain read.

Lost races are detected by guarded-UPDATE rowcount (the epoch fence), never
by SELECT-then-UPDATE.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from pydantic import JsonValue
from sqlalchemy import create_engine, text

from airlock.errors import AirlockError
from airlock.types import (
    IN_FLIGHT_LEDGER_STATES,
    TERMINAL_LEDGER_STATES,
    Claim,
    CommitRecord,
    Guarantee,
    LedgerState,
)

__all__ = ["PostgresStore", "normalize_postgres_url"]


def _utcnow() -> datetime:
    return datetime.now(UTC)


def normalize_postgres_url(url: str) -> str:
    """Pin the SQLAlchemy dialect to psycopg3.

    ``postgresql://`` (the conventional DSN shape, e.g. a DATABASE_URL) would
    otherwise select SQLAlchemy's default psycopg2 driver.
    """
    scheme, _, rest = url.partition("://")
    if not rest:
        raise ValueError(f"not a DSN: {url!r}")
    dialect = scheme.split("+", 1)[0].lower()
    if dialect not in ("postgres", "postgresql"):
        raise ValueError(f"not a postgres DSN: {url!r}")
    return f"postgresql+psycopg://{rest}"


_CLAIM_SQL = text(
    """
    INSERT INTO commit_records
        (idempotency_key, action_type, state, guarantee, args_json,
         downstream_key, attempts, last_attempt_at, created_at)
    VALUES
        (:key, :action_type, :pending, :guarantee, CAST(:args_json AS JSONB),
         :downstream_key, 1, :now, :now)
    ON CONFLICT (idempotency_key) DO NOTHING
    RETURNING *
    """
).bindparams(pending=LedgerState.PENDING.value)

_LOAD_SQL = text("SELECT * FROM commit_records WHERE idempotency_key = :key")

_MARK_EXECUTING_SQL = text(
    """
    UPDATE commit_records
       SET state = :executing, last_attempt_at = :now
     WHERE idempotency_key = :key AND state = :pending AND attempts = :epoch
    """
).bindparams(
    executing=LedgerState.EXECUTING.value,
    pending=LedgerState.PENDING.value,
)

_RECORD_ERROR_SQL = text(
    """
    UPDATE commit_records
       SET error_json = CAST(:error_json AS JSONB)
     WHERE idempotency_key = :key AND state = :executing AND attempts = :epoch
    """
).bindparams(executing=LedgerState.EXECUTING.value)


def _finalize_sql(from_states: tuple[LedgerState, ...]) -> Any:
    state_list = ", ".join(f"'{state.value}'" for state in from_states)
    return text(
        f"""
        UPDATE commit_records
           SET state = :state,
               result_json = CAST(:result_json AS JSONB),
               committed_at = :committed_at
         WHERE idempotency_key = :key AND attempts = :epoch AND state IN ({state_list})
        """
    )


# committed is only reachable from executing (the marker committed before the
# effect ran); the other terminal states may also abort a pending row that
# provably never started its effect (PLAN.md 4.1 step 2).
_FINALIZE_COMMITTED_SQL = _finalize_sql((LedgerState.EXECUTING,))
_FINALIZE_OTHER_SQL = _finalize_sql(IN_FLIGHT_LEDGER_STATES)


class PostgresStore:
    """The ledger of record on the customer's Postgres (ADR-1).

    ``now_fn`` is injectable (PLAN.md section 7 determinism substrate): every
    persisted timestamp is SDK-supplied, never ``DEFAULT now()``.
    """

    def __init__(self, url: str, *, now_fn: Callable[[], datetime] = _utcnow) -> None:
        self._engine = create_engine(normalize_postgres_url(url))
        self._now_fn = now_fn

    def ensure_schema(self) -> None:
        """Create the ledger schema if missing (idempotent)."""
        from airlock.store._schema import ensure_schema

        ensure_schema(self._engine)

    def close(self) -> None:
        """Dispose the connection pool."""
        self._engine.dispose()

    def claim(
        self,
        key: str,
        action_type: str,
        guarantee: Guarantee,
        args_json: Mapping[str, JsonValue],
        downstream_key: str | None,
    ) -> Claim:
        with self._engine.begin() as conn:
            inserted = (
                conn.execute(
                    _CLAIM_SQL,
                    {
                        "key": key,
                        "action_type": action_type,
                        "guarantee": guarantee.value,
                        "args_json": json.dumps(dict(args_json)),
                        "downstream_key": downstream_key,
                        "now": self._now_fn(),
                    },
                )
                .mappings()
                .first()
            )
            if inserted is not None:
                return Claim(won=True, record=_row_to_record(inserted))
            # ON CONFLICT DO NOTHING waited out any in-flight competing insert,
            # so under READ COMMITTED this statement sees the committed winner.
            existing = conn.execute(_LOAD_SQL, {"key": key}).mappings().first()
        if existing is None:
            raise AirlockError(
                f"claim for key {key!r} conflicted but the row is gone — "
                "ledger rows must never be deleted (ADR-1)"
            )
        return Claim(won=False, record=_row_to_record(existing))

    def mark_executing(self, key: str, epoch: int) -> bool:
        with self._engine.begin() as conn:
            rowcount = conn.execute(
                _MARK_EXECUTING_SQL,
                {"key": key, "epoch": epoch, "now": self._now_fn()},
            ).rowcount
        return rowcount == 1

    def record_error(self, key: str, epoch: int, error_json: JsonValue) -> bool:
        with self._engine.begin() as conn:
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
        committed = state is LedgerState.COMMITTED
        sql = _FINALIZE_COMMITTED_SQL if committed else _FINALIZE_OTHER_SQL
        with self._engine.begin() as conn:
            rowcount = conn.execute(
                sql,
                {
                    "key": key,
                    "epoch": epoch,
                    "state": state.value,
                    "result_json": None if result_json is None else json.dumps(result_json),
                    "committed_at": self._now_fn() if committed else None,
                },
            ).rowcount
            # Documented no-op seam: P2.2 appends the hash-chained audit row
            # RIGHT HERE, inside this same transaction, without changing the
            # finalize signature (PLAN.md section 10 sequencing). P1.1
            # persists nothing for `audit`.
            _ = audit
        return rowcount == 1

    def load(self, key: str) -> CommitRecord | None:
        with self._engine.begin() as conn:
            row = conn.execute(_LOAD_SQL, {"key": key}).mappings().first()
        return None if row is None else _row_to_record(row)


def _row_to_record(row: Mapping[Any, Any]) -> CommitRecord:
    # Accepts sqlalchemy's RowMapping (keyed by str | SQL expression) — we only
    # ever index by column-name strings.
    return CommitRecord(
        id=row["id"],
        idempotency_key=row["idempotency_key"],
        action_type=row["action_type"],
        state=LedgerState(row["state"]),
        guarantee=Guarantee(row["guarantee"]),
        args_json=row["args_json"],
        downstream_key=row["downstream_key"],
        run_id=row["run_id"],
        result_json=row["result_json"],
        error_json=row["error_json"],
        attempts=row["attempts"],
        last_attempt_at=row["last_attempt_at"],
        created_at=row["created_at"],
        committed_at=row["committed_at"],
    )
