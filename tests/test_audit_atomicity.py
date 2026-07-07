"""finalize + audit append atomicity (P2.2): ONE transaction, both or neither.

SPEC section 5 step 5 / PLAN.md 4.1 step 6: the terminal-state UPDATE and the
hash-chained audit append happen in one transaction, so a crash/rollback
between them is IMPOSSIBLE — there is no "between". Proven here by fault
injection: a poisoned audit event (payload outside the airlock-canon-1
domain) makes the append raise AFTER the terminal UPDATE has executed inside
the transaction; the transaction aborts, and NEITHER the terminal state nor
the audit row lands. Plus: a fenced finalize appends nothing (no false
transition on the chain), and the success path lands both atomically.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from airlock.audit import verify_chain
from airlock.errors import CanonicalizationError
from airlock.types import AuditEvent, Guarantee, LedgerState

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore

NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=UTC)
KEY = "atomicity-key"
ACTION = "test.atomicity"


def _stage_executing(store: PostgresStore) -> int:
    claim = store.claim(KEY, ACTION, Guarantee.VERIFIABLE, {"invoice": KEY}, None)
    assert claim.won
    assert store.mark_executing(KEY, claim.record.attempts)
    return claim.record.attempts


def _good_event() -> AuditEvent:
    return AuditEvent(
        event_type="action_event",
        run_id="run_atomicity",
        action_type=ACTION,
        payload={"outcome": "committed", "key": KEY},
        created_at=NOW,
    )


def _poisoned_event() -> AuditEvent:
    # A float smuggled into the payload: pydantic's JsonValue admits it, but
    # airlock-canon-1 rejects it AT HASH TIME — inside the finalize
    # transaction, after the terminal UPDATE has already executed.
    return AuditEvent(
        event_type="action_event",
        run_id="run_atomicity",
        action_type=ACTION,
        payload={"outcome": "committed", "amount": 12.5},
        created_at=NOW,
    )


def test_success_path_lands_state_and_audit_row_atomically(
    store: PostgresStore, db: Engine
) -> None:
    epoch = _stage_executing(store)
    event = _good_event()
    assert store.finalize(KEY, epoch, LedgerState.COMMITTED, {"ok": True}, event)

    with db.connect() as conn:
        state = conn.execute(
            text("SELECT state FROM commit_records WHERE idempotency_key = :k"), {"k": KEY}
        ).scalar_one()
        audit = conn.execute(text("SELECT * FROM audit_events WHERE seq = 1")).mappings().one()
    assert state == LedgerState.COMMITTED.value
    assert audit["event_type"] == "action_event"
    assert audit["run_id"] == "run_atomicity"
    assert audit["payload_json"] == {"outcome": "committed", "key": KEY}
    head = store.audit_head()
    assert head is not None and head.seq == 1
    verify_chain(store)


def test_aborted_append_aborts_the_terminal_update_too(store: PostgresStore, db: Engine) -> None:
    """THE fault injection: the append raises inside the finalize transaction
    (after the terminal UPDATE executed) -> the whole transaction rolls back.
    NEITHER the terminal state NOR the audit row landed; the row is still
    'executing' and the chain still verifies at the old head."""
    epoch = _stage_executing(store)
    head_before = store.audit_head()

    with pytest.raises(CanonicalizationError, match="float"):
        store.finalize(KEY, epoch, LedgerState.COMMITTED, {"ok": True}, _poisoned_event())

    with db.connect() as conn:
        state = conn.execute(
            text("SELECT state FROM commit_records WHERE idempotency_key = :k"), {"k": KEY}
        ).scalar_one()
        audit_count = conn.execute(text("SELECT count(*) FROM audit_events")).scalar_one()
    # The terminal UPDATE did NOT survive the aborted transaction:
    assert state == LedgerState.EXECUTING.value
    # ... and no audit row leaked either (genesis only):
    assert audit_count == 1
    assert store.audit_head() == head_before
    verify_chain(store)

    # The row is still owned and recoverable: the SAME owner can finalize with
    # a clean event and both halves land.
    assert store.finalize(KEY, epoch, LedgerState.COMMITTED, {"ok": True}, _good_event())
    verify_chain(store)


def test_fenced_finalize_appends_nothing(store: PostgresStore, db: Engine) -> None:
    """A fenced finalize (wrong epoch, rowcount 0) must not put a false
    transition on the chain: no audit row is appended."""
    epoch = _stage_executing(store)
    assert not store.finalize(KEY, epoch + 1, LedgerState.COMMITTED, {"ok": True}, _good_event())
    with db.connect() as conn:
        audit_count = conn.execute(text("SELECT count(*) FROM audit_events")).scalar_one()
        state = conn.execute(
            text("SELECT state FROM commit_records WHERE idempotency_key = :k"), {"k": KEY}
        ).scalar_one()
    assert audit_count == 1  # genesis only
    assert state == LedgerState.EXECUTING.value
    verify_chain(store)


def test_finalize_rejects_a_non_audit_event_object(store: PostgresStore) -> None:
    """The Store interface is unchanged (audit: object | None), so the store
    type-checks what rides the seam rather than persisting garbage."""
    epoch = _stage_executing(store)
    with pytest.raises(TypeError, match="AuditEvent"):
        store.finalize(KEY, epoch, LedgerState.COMMITTED, {"ok": True}, {"not": "an event"})


def test_finalize_with_none_audit_keeps_p1_behavior(store: PostgresStore, db: Engine) -> None:
    """audit=None (every pre-P2.2 caller, and bare commit_once) appends
    nothing — the seam is optional, the transition is unchanged."""
    epoch = _stage_executing(store)
    assert store.finalize(KEY, epoch, LedgerState.COMMITTED, {"ok": True}, None)
    with db.connect() as conn:
        audit_count = conn.execute(text("SELECT count(*) FROM audit_events")).scalar_one()
    assert audit_count == 1  # genesis only
    verify_chain(store)


def test_connection_drop_mid_transaction_rolls_back_both(
    store: PostgresStore, db: Engine, database_url: str
) -> None:
    """The crash shape, DB-visibly: run the terminal UPDATE + the audit INSERT
    + head UPDATE on one raw connection and DROP it before COMMIT (the
    property-machine crash model). Postgres rolls back the whole transaction:
    the row stays 'executing', the chain is untouched."""
    from sqlalchemy import create_engine
    from sqlalchemy.pool import NullPool

    from airlock.store.postgres import normalize_postgres_url

    epoch = _stage_executing(store)
    engine = create_engine(normalize_postgres_url(database_url), poolclass=NullPool)
    try:
        raw = engine.raw_connection()
        try:
            cur = raw.cursor()
            cur.execute(
                "UPDATE commit_records SET state = 'committed', result_json = '{}'::jsonb,"
                " committed_at = now() WHERE idempotency_key = %s AND attempts = %s"
                " AND state = 'executing'",
                (KEY, epoch),
            )
            cur.execute("SELECT seq, row_hash FROM audit_chain_head FOR UPDATE")
            head = cur.fetchone()
            assert head is not None
            cur.execute(
                "INSERT INTO audit_events (seq, event_type, payload_json, prev_hash, row_hash,"
                " created_at) VALUES (%s, 'action_event', '{}'::jsonb, %s, %s, now())",
                (head[0] + 1, bytes(head[1]), b"\x77" * 32),
            )
            # Deliberately no COMMIT: roll back and hard-close (the crash).
            raw.rollback()
        finally:
            raw.close()
    finally:
        engine.dispose()

    with db.connect() as conn:
        state = conn.execute(
            text("SELECT state FROM commit_records WHERE idempotency_key = :k"), {"k": KEY}
        ).scalar_one()
        audit_count = conn.execute(text("SELECT count(*) FROM audit_events")).scalar_one()
    assert state == LedgerState.EXECUTING.value
    assert audit_count == 1  # genesis only
    verify_chain(store)
