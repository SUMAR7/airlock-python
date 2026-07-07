"""The ``paused_runs`` store layer (P2.3, ADR-4 — PLAN.md 3.3 / 5.1).

Covers the durable-pause persistence primitives in isolation:

- DDL constraints: the status CHECK is generated from ``PauseStatus`` (the
  single vocabulary source — and it contains NO 'expired': ADR-4 is locked),
  UNIQUE(idempotency_key), UNIQUE(approval_ref).
- ``save_paused``: create / attach-to-open / surface-resolved semantics
  (collide-and-dedupe, PLAN.md 4.3), canonical-domain enforcement before
  anything is durable, the creation audit event in the SAME transaction.
- ``transition_paused``: guarded CAS (rowcount truth), the ADR-4 DAG enforced
  in code (illegal edges raise, never touch the DB), decision metadata
  persisted on the approve/reject edge, ``resolved_at`` stamped on terminal
  edges, the chained audit event(s) atomic with the CAS (same-xmin proof).
- ``stale_approved_paused``: only stale APPROVED rows; proposed rows are
  never swept (no TTL in v1).
"""

from __future__ import annotations

import re
import uuid
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from airlock.audit import verify_chain
from airlock.errors import CanonicalizationError
from airlock.types import (
    PAUSE_TRANSITIONS,
    ApprovalDecision,
    AuditEvent,
    HumanDecision,
    PauseStatus,
)
from tests.conftest import FakeClock

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore

ACTION = "pause.refund"
STATE: dict[str, Any] = {
    "arg_map": {"invoice": "inv_1"},
    "risk": {"reversibility": "irreversible"},
}


def _mint_ref() -> str:
    return str(uuid.uuid4())


def _save(
    store: PostgresStore,
    *,
    key: str = "pause-key-1",
    run_id: str = "run_1",
    ref: str | None = None,
    state: dict[str, Any] | None = None,
    audit: AuditEvent | None = None,
) -> Any:
    return store.save_paused(
        run_id=run_id,
        idempotency_key=key,
        approval_ref=ref if ref is not None else _mint_ref(),
        action_type=ACTION,
        serialized_state=state if state is not None else STATE,
        audit=audit,
    )


def _paused_row(db: Engine, run_id: str) -> Any:
    with db.connect() as conn:
        return (
            conn.execute(
                text("SELECT *, xmin::text AS row_xmin FROM paused_runs WHERE run_id = :r"),
                {"r": run_id},
            )
            .mappings()
            .one()
        )


# ---------------------------------------------------------------------------
# Schema: enum consistency + uniqueness (PLAN.md 10.5).
# ---------------------------------------------------------------------------


def test_status_check_matches_pause_status_enum(db: Engine) -> None:
    """The live CHECK list equals PauseStatus — the single vocabulary source."""
    with db.connect() as conn:
        constraint = conn.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint"
                " WHERE conrelid = 'paused_runs'::regclass AND conname = 'paused_runs_status_check'"
            )
        ).scalar_one()
    values = re.findall(r"'([^']*)'", str(constraint))
    assert values == [status.value for status in PauseStatus]


def test_no_expired_status_anywhere(db: Engine) -> None:
    """ADR-4 is LOCKED: no TTL/'expired' state in the enum or the DDL."""
    assert "expired" not in {status.value for status in PauseStatus}
    with db.begin() as conn, pytest.raises(IntegrityError, match="paused_runs_status_check"):
        conn.execute(
            text(
                "INSERT INTO paused_runs (run_id, idempotency_key, approval_ref, action_type,"
                " serialized_state, status, created_at)"
                " VALUES ('r-exp', 'k-exp', gen_random_uuid(), 'a', '{}'::jsonb,"
                " 'expired', now())"
            )
        )


def test_approval_ref_is_unique(db: Engine, store: PostgresStore) -> None:
    ref = _mint_ref()
    _save(store, key="k-ref-1", run_id="r-ref-1", ref=ref)
    with pytest.raises(IntegrityError, match="paused_runs_ref_uq"), db.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO paused_runs (run_id, idempotency_key, approval_ref,"
                " action_type, serialized_state, created_at)"
                " VALUES ('r-ref-2', 'k-ref-2', CAST(:ref AS UUID), 'a', '{}'::jsonb, now())"
            ),
            {"ref": ref},
        )


def test_dag_constant_is_exactly_adr4(db: Engine) -> None:
    """PAUSE_TRANSITIONS is exactly the five ADR-4 edges — nothing more."""
    expected = {
        (PauseStatus.PROPOSED, PauseStatus.APPROVED),
        (PauseStatus.PROPOSED, PauseStatus.REJECTED),
        (PauseStatus.APPROVED, PauseStatus.COMMITTED),
        (PauseStatus.APPROVED, PauseStatus.ABORTED),
        (PauseStatus.REJECTED, PauseStatus.ABORTED),
    }
    assert frozenset(expected) == PAUSE_TRANSITIONS


# ---------------------------------------------------------------------------
# save_paused: create / attach / surface (PLAN.md 4.3).
# ---------------------------------------------------------------------------


def test_save_paused_creates_proposed_row(store: PostgresStore, db: Engine) -> None:
    claim = _save(store, key="k-create", run_id="r-create")
    assert claim.created
    run = claim.run
    assert run.status is PauseStatus.PROPOSED
    assert run.state_version == 1
    assert run.approved_action_json is None  # reserved; NULL in v1
    assert run.decided_by is None and run.decided_at is None
    assert run.resolved_at is None
    # Durable on a FRESH connection:
    row = _paused_row(db, "r-create")
    assert row["status"] == PauseStatus.PROPOSED.value
    assert row["serialized_state"] == STATE


def test_save_paused_conflict_attaches_to_open_run(store: PostgresStore) -> None:
    first = _save(store, key="k-attach", run_id="r-attach-1")
    second = _save(store, key="k-attach", run_id="r-attach-2", ref=_mint_ref())
    assert first.created and not second.created
    # The EXISTING row comes back — same run_id, same approval_ref; the
    # second caller's fresh run_id/approval_ref were never persisted.
    assert second.run.run_id == "r-attach-1"
    assert second.run.approval_ref == first.run.approval_ref
    assert second.run.status is PauseStatus.PROPOSED


def test_save_paused_conflict_surfaces_resolved_run(store: PostgresStore) -> None:
    first = _save(store, key="k-surface", run_id="r-surface")
    assert store.transition_paused("r-surface", PauseStatus.PROPOSED, PauseStatus.REJECTED)
    assert store.transition_paused("r-surface", PauseStatus.REJECTED, PauseStatus.ABORTED)
    again = _save(store, key="k-surface", run_id="r-surface-2", ref=_mint_ref())
    assert not again.created
    assert again.run.status is PauseStatus.ABORTED
    assert again.run.approval_ref == first.run.approval_ref
    assert again.run.resolved_at is not None


def test_save_paused_rejects_non_canonical_state_before_persisting(
    store: PostgresStore, db: Engine
) -> None:
    """A float in serialized_state fails BEFORE anything is durable — it would
    rehydrate wrong and fork the resumed call from the proposed one."""
    with pytest.raises(CanonicalizationError):
        _save(store, key="k-canon", run_id="r-canon", state={"amount": 12.5})
    with db.connect() as conn:
        count = conn.execute(
            text("SELECT count(*) FROM paused_runs WHERE idempotency_key = 'k-canon'")
        ).scalar_one()
    assert count == 0


def test_save_paused_appends_creation_audit_in_same_txn(store: PostgresStore, db: Engine) -> None:
    """The creation event lands with the INSERT (same xmin ⇒ same transaction),
    and an attach appends NO duplicate creation event."""
    event = AuditEvent(
        event_type="pause_transition",
        run_id="r-audit",
        action_type=ACTION,
        payload={"to_status": "proposed", "approval_ref": "x"},
    )
    claim = _save(store, key="k-audit", run_id="r-audit", audit=event)
    assert claim.created
    with db.connect() as conn:
        pause_xmin = conn.execute(
            text("SELECT xmin::text FROM paused_runs WHERE run_id = 'r-audit'")
        ).scalar_one()
        audit_rows = (
            conn.execute(
                text(
                    "SELECT xmin::text AS x FROM audit_events"
                    " WHERE event_type = 'pause_transition' AND run_id = 'r-audit'"
                )
            )
            .mappings()
            .all()
        )
    assert len(audit_rows) == 1
    assert audit_rows[0]["x"] == pause_xmin  # physically ONE transaction

    # Attach: no second creation event.
    again = _save(store, key="k-audit", run_id="r-audit-2", audit=event)
    assert not again.created
    with db.connect() as conn:
        count = conn.execute(
            text(
                "SELECT count(*) FROM audit_events"
                " WHERE event_type = 'pause_transition' AND run_id = 'r-audit'"
            )
        ).scalar_one()
    assert count == 1
    verify_chain(store)


# ---------------------------------------------------------------------------
# load_paused_by_ref.
# ---------------------------------------------------------------------------


def test_load_paused_by_ref_round_trips(store: PostgresStore) -> None:
    ref = _mint_ref()
    _save(store, key="k-load", run_id="r-load", ref=ref)
    run = store.load_paused_by_ref(ref)
    assert run is not None
    assert run.run_id == "r-load"
    assert run.approval_ref == ref
    assert run.serialized_state == STATE  # byte-level content round-trip
    assert store.load_paused_by_ref(_mint_ref()) is None


# ---------------------------------------------------------------------------
# transition_paused: the guarded CAS + the DAG + decision metadata.
# ---------------------------------------------------------------------------


def test_transition_cas_rowcount_is_the_truth(store: PostgresStore) -> None:
    _save(store, key="k-cas", run_id="r-cas")
    decision = ApprovalDecision(decision=HumanDecision.APPROVED, decided_by="usr_1")
    assert store.transition_paused(
        "r-cas", PauseStatus.PROPOSED, PauseStatus.APPROVED, decision=decision
    )
    # Second identical CAS: the row is no longer proposed — fenced, False.
    assert not store.transition_paused(
        "r-cas", PauseStatus.PROPOSED, PauseStatus.APPROVED, decision=decision
    )
    # The losing reject CAS is fenced too (the approve won).
    assert not store.transition_paused(
        "r-cas",
        PauseStatus.PROPOSED,
        PauseStatus.REJECTED,
        decision=ApprovalDecision(decision=HumanDecision.REJECTED),
    )


def test_illegal_transitions_raise_before_touching_the_db(store: PostgresStore) -> None:
    """Every non-DAG edge is unrepresentable: ValueError, no SQL, row unchanged."""
    _save(store, key="k-dag", run_id="r-dag")
    illegal = [
        (PauseStatus.PROPOSED, PauseStatus.COMMITTED),  # skipping the decision
        (PauseStatus.PROPOSED, PauseStatus.ABORTED),
        (PauseStatus.REJECTED, PauseStatus.COMMITTED),  # a rejected run never commits
        (PauseStatus.APPROVED, PauseStatus.REJECTED),  # decisions never flip
        (PauseStatus.REJECTED, PauseStatus.APPROVED),
        (PauseStatus.COMMITTED, PauseStatus.ABORTED),  # terminal is terminal
        (PauseStatus.ABORTED, PauseStatus.COMMITTED),
        (PauseStatus.COMMITTED, PauseStatus.PROPOSED),
        (PauseStatus.APPROVED, PauseStatus.PROPOSED),
    ]
    for from_status, to_status in illegal:
        with pytest.raises(ValueError, match="ADR-4"):
            store.transition_paused("r-dag", from_status, to_status)
    attached = _save(store, key="k-dag", run_id="ignored")  # attach reads back
    assert attached.run.status is PauseStatus.PROPOSED  # untouched by the raises


def test_decision_metadata_persists_on_the_approve_edge(
    db: Engine, database_url: str, fake_clock: FakeClock
) -> None:
    from airlock.store.postgres import PostgresStore

    store = PostgresStore(database_url, now_fn=fake_clock)
    try:
        _save(store, key="k-meta", run_id="r-meta")
        decision = ApprovalDecision(
            decision=HumanDecision.APPROVED,
            decided_by="usr_abc",
            decided_by_display="Ada L.",
            decided_at=fake_clock(),
            decision_latency_ms=1234,
        )
        assert store.transition_paused(
            "r-meta", PauseStatus.PROPOSED, PauseStatus.APPROVED, decision=decision
        )
        row = _paused_row(db, "r-meta")
        assert row["decided_by"] == "usr_abc"
        assert row["decided_by_display"] == "Ada L."
        assert row["decision_latency_ms"] == 1234
        assert row["decided_at"] is not None
        assert row["resolved_at"] is None  # approved is NOT terminal

        # Terminal edge stamps resolved_at (from the injectable clock).
        fake_clock.advance(5)
        assert store.transition_paused("r-meta", PauseStatus.APPROVED, PauseStatus.COMMITTED)
        row = _paused_row(db, "r-meta")
        assert row["resolved_at"] is not None
        assert row["status"] == PauseStatus.COMMITTED.value
        # Decision metadata survives the terminal edge untouched.
        assert row["decided_by"] == "usr_abc"
    finally:
        store.close()


def test_transition_audit_rides_in_the_cas_transaction(store: PostgresStore, db: Engine) -> None:
    """Same-xmin proof: the pause CAS UPDATE and its chained audit INSERT are
    physically one transaction; a fenced CAS appends nothing."""
    _save(store, key="k-txn", run_id="r-txn")
    event = AuditEvent(
        event_type="pause_transition",
        run_id="r-txn",
        action_type=ACTION,
        payload={"from_status": "proposed", "to_status": "approved"},
    )
    assert store.transition_paused(
        "r-txn",
        PauseStatus.PROPOSED,
        PauseStatus.APPROVED,
        decision=ApprovalDecision(decision=HumanDecision.APPROVED),
        audit=event,
    )
    with db.connect() as conn:
        pause_xmin = conn.execute(
            text("SELECT xmin::text FROM paused_runs WHERE run_id = 'r-txn'")
        ).scalar_one()
        audit_xmin = conn.execute(
            text(
                "SELECT xmin::text FROM audit_events"
                " WHERE event_type = 'pause_transition' AND run_id = 'r-txn'"
            )
        ).scalar_one()
    assert audit_xmin == pause_xmin

    # A fenced repeat appends NOTHING (no false statement on the chain).
    head_before = store.audit_head()
    assert head_before is not None
    assert not store.transition_paused(
        "r-txn",
        PauseStatus.PROPOSED,
        PauseStatus.APPROVED,
        decision=ApprovalDecision(decision=HumanDecision.APPROVED),
        audit=event,
    )
    head_after = store.audit_head()
    assert head_after is not None and head_after.seq == head_before.seq
    verify_chain(store)


def test_transition_accepts_multiple_audit_events_atomically(
    store: PostgresStore, db: Engine
) -> None:
    """A terminal transition can carry both its pause_transition record and the
    terminal action_event in ONE transaction (the apply_decision reject path)."""
    _save(store, key="k-multi", run_id="r-multi")
    assert store.transition_paused(
        "r-multi",
        PauseStatus.PROPOSED,
        PauseStatus.REJECTED,
        decision=ApprovalDecision(decision=HumanDecision.REJECTED),
    )
    events = (
        AuditEvent(
            event_type="pause_transition",
            run_id="r-multi",
            action_type=ACTION,
            payload={"from_status": "rejected", "to_status": "aborted"},
        ),
        AuditEvent(
            event_type="marker",
            run_id="r-multi",
            action_type=ACTION,
            payload={"kind": "second-event"},
        ),
    )
    assert store.transition_paused(
        "r-multi", PauseStatus.REJECTED, PauseStatus.ABORTED, audit=events
    )
    with db.connect() as conn:
        xmins = conn.execute(
            text("SELECT DISTINCT xmin::text FROM audit_events WHERE run_id = 'r-multi'")
        ).all()
    assert len(xmins) == 1  # both events in one transaction
    verify_chain(store)


# ---------------------------------------------------------------------------
# stale_approved_paused: the sweep scan.
# ---------------------------------------------------------------------------


def test_stale_approved_scan_finds_only_stale_approved_rows(
    db: Engine, database_url: str, fake_clock: FakeClock
) -> None:
    from airlock.store.postgres import PostgresStore

    store = PostgresStore(database_url, now_fn=fake_clock)
    try:
        # One of each: proposed (never swept), fresh approved, stale approved,
        # committed (terminal).
        for run_id, key in [
            ("r-prop", "k-s-prop"),
            ("r-fresh", "k-s-fresh"),
            ("r-stale", "k-s-stale"),
            ("r-done", "k-s-done"),
        ]:
            _save(store, key=key, run_id=run_id)
        approve = ApprovalDecision(decision=HumanDecision.APPROVED, decided_at=fake_clock())
        for run_id in ("r-fresh", "r-stale", "r-done"):
            assert store.transition_paused(
                run_id, PauseStatus.PROPOSED, PauseStatus.APPROVED, decision=approve
            )
        assert store.transition_paused("r-done", PauseStatus.APPROVED, PauseStatus.COMMITTED)

        # Make r-stale's decision old; r-fresh keeps a recent decided_at.
        with db.begin() as conn:
            conn.execute(
                text(
                    "UPDATE paused_runs SET decided_at = decided_at - interval '1 hour'"
                    " WHERE run_id = 'r-stale'"
                )
            )
        stale = store.stale_approved_paused(timedelta(seconds=60))
        assert [run.run_id for run in stale] == ["r-stale"]
        # Proposed rows are NEVER in the sweep: no TTL expiry in v1 (ADR-4).
        assert all(run.status is PauseStatus.APPROVED for run in stale)
    finally:
        store.close()
