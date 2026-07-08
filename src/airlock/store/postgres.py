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
- ``finalize``       CAS to a terminal state PLUS (P2.2) the hash-chained
                     audit append, in ONE transaction — the P1.1 seam
                     upgraded without changing the signature (PLAN.md 10).
- ``load``           plain read.
- ``stale_inflight`` (P1.3) FOR UPDATE SKIP LOCKED scan of stale in-flight
                     rows for the reconciler.
- ``bump_epoch``     (P1.3) the takeover fence: atomically bump the epoch of a
                     still-stale in-flight row, returning the new epoch.
- ``append_audit``   (P2.2, ADR-5) append one hash-chained ``audit_events``
                     row: SELECT the chain head FOR UPDATE (the head-row lock
                     serializes appenders across processes), compute the
                     row_hash IN THE SDK (``airlock.audit`` — never a DB
                     trigger), INSERT, UPDATE the head. Gapless ``seq`` by
                     construction.
- ``audit_head`` / ``iter_audit``  the verifier's read surface
                     (``airlock.audit.verify_chain``): the head singleton, and
                     a streaming ORDER BY seq scan (server-side cursor,
                     constant memory).
- ``save_paused``    (P2.3, ADR-4) INSERT ... ON CONFLICT (idempotency_key)
                     DO NOTHING + read-back — the durable pause; the creation
                     audit event rides in the same transaction.
- ``load_paused_by_ref`` plain read by approval_ref (post-restart rehydration).
- ``transition_paused`` guarded CAS along the ADR-4 DAG + chained audit
                     event(s), ONE transaction; illegal edges refused in code.
- ``stale_approved_paused`` (P2.3) FOR UPDATE SKIP LOCKED scan of approved
                     rows whose commit never landed — the reconciler sweep.

Lost races are detected by guarded-UPDATE rowcount (the epoch fence), never
by SELECT-then-UPDATE.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import JsonValue
from sqlalchemy import Connection, create_engine, text

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

# The in-flight state list is GENERATED from IN_FLIGHT_LEDGER_STATES (the
# single vocabulary source, PLAN.md 10 point 5) — never retyped — so the scan,
# the takeover fence, and record_error can never diverge from the partial index
# or the DDL.
_IN_FLIGHT_STATE_LIST = ", ".join(f"'{state.value}'" for state in IN_FLIGHT_LEDGER_STATES)

# record_error writes error_json only (never state), epoch-guarded, on any
# IN-FLIGHT row — pending OR executing. commit_once always calls it after the
# executing mark (state=executing), but the reconciler records recovery
# evidence on the PENDING abort path BEFORE the pending->aborted finalize: the
# row is still pending then, so a state='executing'-only guard would silently
# drop that evidence (the ledger must keep the reconciled/aborted reason). It
# is refused on terminal rows so a fenced/late writer cannot scribble on a
# resolved row (I5).
_RECORD_ERROR_SQL = text(
    f"""
    UPDATE commit_records
       SET error_json = CAST(:error_json AS JSONB)
     WHERE idempotency_key = :key
       AND state IN ({_IN_FLIGHT_STATE_LIST})
       AND attempts = :epoch
    """
)

# The stale-in-flight scan (PLAN.md 4.2). Ordered by last_attempt_at so the
# oldest stale rows recover first; SKIP LOCKED so two reconcilers never contend
# on the same row (the partial index commit_records_inflight_idx supports the
# WHERE + ORDER BY). The lock is released when the reading txn commits — the
# reconciler takes durable ownership via bump_epoch, not by holding this lock.
_STALE_INFLIGHT_SQL = text(
    f"""
    SELECT * FROM commit_records
     WHERE state IN ({_IN_FLIGHT_STATE_LIST})
       AND last_attempt_at < :cutoff
     ORDER BY last_attempt_at
     FOR UPDATE SKIP LOCKED
    """
)

# The takeover fence (PLAN.md 4.2 / 10 point 2). Bump the epoch and refresh
# last_attempt_at ONLY while the row is still in-flight AND still stale — the
# staleness re-check inside the atomic UPDATE closes the window where a slow
# owner re-touched the row (or another reconciler already bumped it) between
# the stale_inflight read and this write. RETURNING the new epoch; rowcount 0
# (no row returned) => already terminal or no longer stale => caller skips.
_BUMP_EPOCH_SQL = text(
    f"""
    UPDATE commit_records
       SET attempts = attempts + 1, last_attempt_at = :now
     WHERE idempotency_key = :key
       AND state IN ({_IN_FLIGHT_STATE_LIST})
       AND last_attempt_at < :cutoff
    RETURNING attempts
    """
)


# --- The durable pause (P2.3, ADR-4) ----------------------------------------
#
# Same discipline as the ledger: every transition is a guarded UPDATE whose
# rowcount is the truth about who moved the row (never SELECT-then-UPDATE),
# and every chained audit event rides INSIDE the transaction that made the
# transition it evidences (the P2.2 finalize pattern).

_SAVE_PAUSED_SQL = text(
    """
    INSERT INTO paused_runs
        (run_id, idempotency_key, approval_ref, action_type, serialized_state,
         state_version, status, created_at)
    VALUES
        (:run_id, :key, CAST(:approval_ref AS UUID), :action_type,
         CAST(:serialized_state AS JSONB), :state_version, :proposed, :now)
    ON CONFLICT (idempotency_key) DO NOTHING
    RETURNING *
    """
).bindparams(proposed=PauseStatus.PROPOSED.value)

_LOAD_PAUSED_BY_KEY_SQL = text("SELECT * FROM paused_runs WHERE idempotency_key = :key")

_LOAD_PAUSED_BY_REF_SQL = text(
    "SELECT * FROM paused_runs WHERE approval_ref = CAST(:approval_ref AS UUID)"
)

# The stale-APPROVED sweep scan (PLAN.md 4.2): the decision landed
# (decided_at) but the commit never did. Oldest decisions first; SKIP LOCKED
# so two reconcilers never contend on the same row (the partial index
# paused_runs_approved_idx supports the WHERE + ORDER BY). Durable exclusion
# among concurrent appliers is the LEDGER's job (commit_once dedupes), so no
# epoch fence is needed here — apply_decision is idempotent by construction.
_STALE_APPROVED_SQL = text(
    f"""
    SELECT * FROM paused_runs
     WHERE status = '{PauseStatus.APPROVED.value}'
       AND decided_at < :cutoff
     ORDER BY decided_at
     FOR UPDATE SKIP LOCKED
    """
)


def _transition_paused_sql(with_decision: bool) -> Any:
    decision_sets = (
        """,
               decided_by = :decided_by,
               decided_by_display = :decided_by_display,
               decided_at = :decided_at,
               decision_latency_ms = :decision_latency_ms"""
        if with_decision
        else ""
    )
    return text(
        f"""
        UPDATE paused_runs
           SET status = :to_status,
               resolved_at = :resolved_at{decision_sets}
         WHERE run_id = :run_id AND status = :from_status
        """
    )


_TRANSITION_PAUSED_SQL = _transition_paused_sql(with_decision=False)
_TRANSITION_PAUSED_WITH_DECISION_SQL = _transition_paused_sql(with_decision=True)


# --- The audit chain (P2.2, ADR-5) ------------------------------------------
#
# The append protocol (PLAN.md 5.1/5.2), always inside the enclosing
# transaction: lock the head row (FOR UPDATE — THE serialization point for
# appenders across processes), compute row_hash in the SDK, INSERT the row at
# seq = head.seq + 1 (gapless by construction: the lock makes the read-
# increment-insert atomic), UPDATE the head. The DB never hashes.

_AUDIT_HEAD_LOCK_SQL = text("SELECT seq, row_hash FROM audit_chain_head WHERE singleton FOR UPDATE")

_AUDIT_HEAD_READ_SQL = text("SELECT seq, row_hash FROM audit_chain_head WHERE singleton")

_AUDIT_INSERT_SQL = text(
    """
    INSERT INTO audit_events
        (seq, run_id, action_type, event_type, payload_json, prev_hash, row_hash, created_at)
    VALUES
        (:seq, :run_id, :action_type, :event_type, CAST(:payload AS JSONB),
         :prev_hash, :row_hash, :created_at)
    RETURNING *
    """
)

_AUDIT_HEAD_UPDATE_SQL = text(
    "UPDATE audit_chain_head SET seq = :seq, row_hash = :row_hash WHERE singleton"
)

_AUDIT_ITER_SQL = text(
    """
    SELECT * FROM audit_events
     WHERE seq >= :start
     ORDER BY seq
    """
)


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


# Legal finalize transitions per target state (PLAN.md 3.2 semantics; the
# honest state machine makes false claims unrepresentable, PLAN.md 10 point 1):
#
# - committed: only from executing — the marker committed before the effect ran.
# - aborted:   from pending (precondition abort before the mark, PLAN.md 4.1
#              step 2) or executing (the P1.3 probe-absent recovery path).
# - failed:    only from executing. "Executed and confirmed not to have taken
#              effect" is a false statement about a pending row, which provably
#              never started its effect.
# - unknown:   only from executing — same argument; a pending row is never
#              "may have executed".
_FINALIZE_FROM_STATES: dict[LedgerState, tuple[LedgerState, ...]] = {
    LedgerState.COMMITTED: (LedgerState.EXECUTING,),
    LedgerState.ABORTED: IN_FLIGHT_LEDGER_STATES,
    LedgerState.FAILED: (LedgerState.EXECUTING,),
    LedgerState.UNKNOWN: (LedgerState.EXECUTING,),
}
_FINALIZE_SQL: dict[LedgerState, Any] = {
    target: _finalize_sql(from_states) for target, from_states in _FINALIZE_FROM_STATES.items()
}


class PostgresStore:
    """The ledger of record on the customer's Postgres (ADR-1).

    ``now_fn`` is injectable (PLAN.md section 7 determinism substrate): every
    persisted timestamp is SDK-supplied, never ``DEFAULT now()``.
    """

    def __init__(self, url: str, *, now_fn: Callable[[], datetime] = _utcnow) -> None:
        # READ COMMITTED is pinned, never inherited: ADR-1 puts the ledger in
        # the CUSTOMER'S Postgres, where default_transaction_isolation is
        # theirs. claim()'s loser read-back runs in the same transaction as
        # the conflicting INSERT and relies on each statement taking a fresh
        # snapshot — under an inherited REPEATABLE READ/SERIALIZABLE default
        # the loser's snapshot predates the winner's commit, the read-back
        # comes back empty, and SPEC section 5 scenario 2 breaks (and under
        # SERIALIZABLE the guarded CAS UPDATEs can additionally raise
        # serialization failures after the effect ran).
        self._engine = create_engine(normalize_postgres_url(url), isolation_level="READ COMMITTED")
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
            # and the engine pins READ COMMITTED (see __init__), so this
            # statement takes a fresh snapshot that sees the committed winner.
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
        if audit is not None and not isinstance(audit, AuditEvent):
            raise TypeError(
                f"finalize audit must be an airlock.types.AuditEvent or None, "
                f"got {type(audit).__name__}"
            )
        committed = state is LedgerState.COMMITTED
        sql = _FINALIZE_SQL[state]
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
            # The P1.1 seam, upgraded (PLAN.md 10 / SPEC section 5 step 5):
            # the terminal-state CAS and the hash-chained audit append are ONE
            # transaction — a crash/rollback between them is impossible;
            # either both land or neither does. The append happens ONLY when
            # the CAS matched (rowcount 1): a fenced finalize did not
            # transition the row, so appending its event would put a false
            # statement on the tamper-evident chain.
            if rowcount == 1 and audit is not None:
                self._append_audit_on(conn, audit)
        return rowcount == 1

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
        """Durably persist the ``proposed`` pause (ADR-4), one transaction.

        ``ON CONFLICT (idempotency_key) DO NOTHING`` + read-back, exactly the
        ``claim`` pattern: the UNIQUE constraint is the concurrency guard, and
        a conflicting insert returns the existing row (attach / surface —
        PLAN.md 4.3). ``serialized_state`` is canonicalized here so a value
        outside the airlock-canon-1 domain fails BEFORE anything is durable
        (a float smuggled into the persisted state would rehydrate wrong).
        The creation ``audit`` event is appended inside this same transaction,
        only when the insert landed.
        """
        with self._engine.begin() as conn:
            inserted = (
                conn.execute(
                    _SAVE_PAUSED_SQL,
                    {
                        "run_id": run_id,
                        "key": idempotency_key,
                        "approval_ref": approval_ref,
                        "action_type": action_type,
                        "serialized_state": canonical_json(dict(serialized_state)),
                        "state_version": state_version,
                        "now": self._now_fn(),
                    },
                )
                .mappings()
                .first()
            )
            if inserted is not None:
                if audit is not None:
                    self._append_audit_on(conn, audit)
                return PauseClaim(created=True, run=_row_to_paused(inserted))
            existing = conn.execute(_LOAD_PAUSED_BY_KEY_SQL, {"key": idempotency_key}).mappings()
            row = existing.first()
        if row is None:
            raise AirlockError(
                f"save_paused for key {idempotency_key!r} conflicted but the row is gone — "
                "paused_runs rows must never be deleted (ADR-4)"
            )
        return PauseClaim(created=False, run=_row_to_paused(row))

    def load_paused_by_ref(self, approval_ref: str) -> PausedRun | None:
        with self._engine.begin() as conn:
            row = (
                conn.execute(_LOAD_PAUSED_BY_REF_SQL, {"approval_ref": approval_ref})
                .mappings()
                .first()
            )
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
        """Guarded CAS along the ADR-4 DAG + chained audit, ONE transaction.

        An illegal (from, to) pair raises ``ValueError`` before any SQL — the
        DAG (``airlock.types.PAUSE_TRANSITIONS``) is enforced in code, and the
        CAS's ``WHERE status = :from_status`` enforces it against concurrent
        appliers (rowcount 0 = lost the race; the caller reads back the
        recorded state). The audit event(s) are appended ONLY when the CAS
        matched — a fenced transition must not put a false statement on the
        tamper-evident chain (the P2.2 finalize pattern).
        """
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
            "resolved_at": resolved_at,
        }
        if decision is not None:
            params.update(
                {
                    "decided_by": decision.decided_by,
                    "decided_by_display": decision.decided_by_display,
                    "decided_at": (
                        decision.decided_at if decision.decided_at is not None else self._now_fn()
                    ),
                    "decision_latency_ms": decision.decision_latency_ms,
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
        with self._engine.begin() as conn:
            rowcount = conn.execute(sql, params).rowcount
            if rowcount == 1:
                for event in events:
                    self._append_audit_on(conn, event)
        return rowcount == 1

    def stale_approved_paused(self, older_than: timedelta) -> list[PausedRun]:
        cutoff = self._now_fn() - older_than
        # FOR UPDATE SKIP LOCKED for the same reason as stale_inflight: two
        # concurrent sweeps never hand the same row to two recoverers in one
        # pass. The lock is released at commit; safety across passes comes
        # from apply_decision's idempotence (the ledger dedupes appliers).
        with self._engine.begin() as conn:
            rows = conn.execute(_STALE_APPROVED_SQL, {"cutoff": cutoff}).mappings().all()
        return [_row_to_paused(row) for row in rows]

    def append_audit(self, event: AuditEvent) -> AuditRow:
        """Append one hash-chained audit row in its own transaction (ADR-5)."""
        with self._engine.begin() as conn:
            return self._append_audit_on(conn, event)

    def _append_audit_on(self, conn: Connection, event: AuditEvent) -> AuditRow:
        """The append protocol (PLAN.md 5.1/5.2), on the CALLER'S transaction.

        Lock the chain head (``FOR UPDATE`` — serializes appenders across
        processes), assign ``seq = head.seq + 1`` (gapless under the lock),
        compute ``row_hash`` in the SDK, INSERT the row, UPDATE the head. The
        hashed ``created_at`` and the stored column are the same value: the
        event's SDK-supplied timestamp, or this store's ``now_fn`` when the
        event carries none — never ``DEFAULT now()``.
        """
        head = conn.execute(_AUDIT_HEAD_LOCK_SQL).mappings().first()
        if head is None:
            raise AirlockError(
                "audit_chain_head is missing — the audit schema is not initialized; "
                "run ensure_schema() before appending audit events (ADR-5)"
            )
        seq = int(head["seq"]) + 1
        prev_hash = bytes(head["row_hash"])
        created_at = event.created_at if event.created_at is not None else self._now_fn()
        # Hash first: a payload outside the airlock-canon-1 domain raises
        # CanonicalizationError HERE, before anything is written, aborting the
        # enclosing transaction whole (the finalize+append atomicity tests
        # inject exactly this fault).
        row_hash = compute_row_hash(
            prev_hash,
            seq=seq,
            run_id=event.run_id,
            action_type=event.action_type,
            event_type=event.event_type,
            created_at=created_at,
            payload=event.payload,
        )
        inserted = (
            conn.execute(
                _AUDIT_INSERT_SQL,
                {
                    "seq": seq,
                    "run_id": event.run_id,
                    "action_type": event.action_type,
                    "event_type": event.event_type,
                    "payload": canonical_json(event.payload),
                    "prev_hash": prev_hash,
                    "row_hash": row_hash,
                    "created_at": created_at,
                },
            )
            .mappings()
            .one()
        )
        conn.execute(_AUDIT_HEAD_UPDATE_SQL, {"seq": seq, "row_hash": row_hash})
        return _row_to_audit(inserted)

    def audit_head(self) -> AuditHead | None:
        """Read the ``audit_chain_head`` singleton (no lock), or ``None``."""
        with self._engine.begin() as conn:
            head = conn.execute(_AUDIT_HEAD_READ_SQL).mappings().first()
        if head is None:
            return None
        return AuditHead(seq=int(head["seq"]), row_hash=bytes(head["row_hash"]))

    def iter_audit(self, start_seq: int = 0) -> Iterator[AuditRow]:
        """Stream audit rows ``ORDER BY seq`` from ``start_seq`` (inclusive).

        Server-side cursor (``stream_results``) so ``verify_chain`` is O(n)
        with constant memory; the connection is held only while the generator
        is being consumed.
        """
        with self._engine.connect() as conn:
            result = conn.execution_options(stream_results=True, max_row_buffer=500).execute(
                _AUDIT_ITER_SQL, {"start": start_seq}
            )
            for row in result.mappings():
                yield _row_to_audit(row)

    def load(self, key: str) -> CommitRecord | None:
        with self._engine.begin() as conn:
            row = conn.execute(_LOAD_SQL, {"key": key}).mappings().first()
        return None if row is None else _row_to_record(row)

    def stale_inflight(self, older_than: timedelta) -> list[CommitRecord]:
        cutoff = self._now_fn() - older_than
        # The FOR UPDATE SKIP LOCKED lock lives only for this short read
        # transaction: we materialize the rows and commit, releasing the locks.
        # Durable ownership is taken separately by bump_epoch (the epoch fence),
        # so the reconciler never holds a row lock across its verification I/O —
        # a long probe cannot pin the row against a second reconciler pass.
        with self._engine.begin() as conn:
            rows = conn.execute(_STALE_INFLIGHT_SQL, {"cutoff": cutoff}).mappings().all()
        return [_row_to_record(row) for row in rows]

    def bump_epoch(self, key: str, older_than: timedelta) -> int | None:
        now = self._now_fn()
        cutoff = now - older_than
        with self._engine.begin() as conn:
            new_epoch = conn.execute(
                _BUMP_EPOCH_SQL, {"key": key, "now": now, "cutoff": cutoff}
            ).scalar_one_or_none()
        return None if new_epoch is None else int(new_epoch)


def _row_to_audit(row: Mapping[Any, Any]) -> AuditRow:
    return AuditRow(
        id=row["id"],
        seq=row["seq"],
        run_id=row["run_id"],
        action_type=row["action_type"],
        event_type=row["event_type"],
        payload=row["payload_json"],
        prev_hash=bytes(row["prev_hash"]),
        row_hash=bytes(row["row_hash"]),
        created_at=row["created_at"],
    )


def _row_to_paused(row: Mapping[Any, Any]) -> PausedRun:
    return PausedRun(
        id=row["id"],
        run_id=row["run_id"],
        idempotency_key=row["idempotency_key"],
        approval_ref=str(row["approval_ref"]),
        approval_id=row["approval_id"],
        action_type=row["action_type"],
        serialized_state=row["serialized_state"],
        state_version=row["state_version"],
        status=PauseStatus(row["status"]),
        approved_action_json=row["approved_action_json"],
        decided_by=row["decided_by"],
        decided_by_display=row["decided_by_display"],
        decided_at=row["decided_at"],
        decision_latency_ms=row["decision_latency_ms"],
        created_at=row["created_at"],
        resolved_at=row["resolved_at"],
    )


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
