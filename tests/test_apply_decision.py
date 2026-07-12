"""``apply_decision`` — the ensure-committed core (PLAN.md 4.3, ADR-4).

Scenario 5 (sequential half — the barrier-raced half lives in
``test_pause_concurrency.py``), scenario 8 (stale approval), the no-op paths
(zero writes, proven via xmin + chain-head equality), the reserved
``edited_args`` field, the ``state_version`` gate, and the
approved-but-uncommitted redelivery that pins "a lost CAS is NOT a no-op".
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

import pytest
from sqlalchemy import text

from airlock.audit import verify_chain
from airlock.effects import Effect
from airlock.errors import AirlockError, StateVersionError, UnknownApprovalRef
from airlock.pause import (
    STATE_VERSION,
    apply_decision,
    build_serialized_state,
)
from airlock.registry import Registry
from airlock.types import (
    ApprovalDecision,
    HumanDecision,
    LedgerState,
    Money,
    PauseStatus,
    Reversibility,
)
from tests.conftest import EffectsLog, FakeClock

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore

pytestmark = pytest.mark.matrix

ACTION = "apply.refund"

APPROVE = ApprovalDecision(decision=HumanDecision.APPROVED, decided_by="usr_ok")
REJECT = ApprovalDecision(decision=HumanDecision.REJECTED, decided_by="usr_no")


def _as_obj(payload: Any) -> Any:
    """JSONB (Postgres) returns a dict; TEXT (SQLite) returns a JSON string."""
    import json as _json

    return _json.loads(payload) if isinstance(payload, str) else payload


def _persist_pause(
    store: PostgresStore,
    *,
    key: str,
    arg_map: dict[str, Any] | None = None,
    precondition_snapshot: dict[str, Any] | None = None,
    action_type: str = ACTION,
) -> str:
    """Persist a proposed pause the way the GATE path does; return approval_ref."""
    ref = str(uuid.uuid4())
    state = build_serialized_state(
        arg_map if arg_map is not None else {"invoice": key},
        reversibility=Reversibility.IRREVERSIBLE,
        cost=Money(amount="120.00", currency="USD"),
        blast_radius=None,
        precondition_snapshot=precondition_snapshot,
    )
    claim = store.save_paused(
        run_id=f"run_{ref[:8]}",
        idempotency_key=key,
        approval_ref=ref,
        action_type=action_type,
        serialized_state=state,
    )
    assert claim.created
    return ref


def _registry(
    effects: EffectsLog,
    key: str,
    *,
    preconditions: Any = None,
    action_type: str = ACTION,
) -> Registry:
    reg = Registry()

    def execute(downstream_key: str | None, **_: Any) -> Any:
        effects.log(key)
        return {"refund_id": f"re_{key}"}

    reg.register(action_type, Effect(key_param="idempotency_key"), execute, preconditions)
    return reg


def _action_events(db: Engine, key: str) -> list[dict[str, Any]]:
    with db.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT payload_json FROM audit_events WHERE event_type = 'action_event'"
                    " AND payload_json->>'idempotency_key' = :key ORDER BY seq"
                ),
                {"key": key},
            )
            .scalars()
            .all()
        )
    return [_as_obj(r) for r in rows]


def _pause_transitions(db: Engine, ref: str) -> list[dict[str, Any]]:
    with db.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT payload_json FROM audit_events"
                    " WHERE event_type = 'pause_transition'"
                    " AND payload_json->>'approval_ref' = :ref ORDER BY seq"
                ),
                {"ref": ref},
            )
            .scalars()
            .all()
        )
    return [_as_obj(r) for r in rows]


# ---------------------------------------------------------------------------
# The approve path.
# ---------------------------------------------------------------------------


def test_approve_commits_exactly_once_with_full_evidence(
    store: PostgresStore, db: Engine, effects: EffectsLog
) -> None:
    key = "k-apply-ok"
    ref = _persist_pause(store, key=key)
    outcome = apply_decision(store, ref, APPROVE, registry=_registry(effects, key))

    assert outcome.applied
    assert outcome.status is PauseStatus.COMMITTED
    assert outcome.ledger_state is LedgerState.COMMITTED
    assert outcome.result == {"refund_id": f"re_{key}"}
    assert outcome.human_decision is HumanDecision.APPROVED
    assert effects.count(key) == 1

    run = store.load_paused_by_ref(ref)
    assert run is not None
    assert run.status is PauseStatus.COMMITTED
    assert run.decided_by == "usr_ok"
    assert run.decided_at is not None and run.resolved_at is not None
    assert run.decision_latency_ms is not None and run.decision_latency_ms >= 0

    # Exactly ONE terminal action_event, carrying the human half (PLAN.md 6.3).
    events = _action_events(db, key)
    assert len(events) == 1
    payload = events[0]
    assert payload["policy_decision"] == "gate"
    assert payload["outcome"] == "committed"
    assert payload["human_decision"] == "approved"
    assert payload["decided_by"] == "usr_ok"
    assert isinstance(payload["decision_latency_ms"], int)
    # Money amounts are canonical decimal strings ("120.00" normalizes to "120").
    assert payload["cost"] == {"amount": "120", "currency": "USD"}
    assert payload["run_id"] == run.run_id

    # The status edges are chained: proposed->approved, approved->committed.
    edges = [(p["from_status"], p["to_status"]) for p in _pause_transitions(db, ref)]
    assert edges == [("proposed", "approved"), ("approved", "committed")]
    verify_chain(store)


def test_scenario_5_sequential_double_delivery_is_one_effect_one_event(
    store: PostgresStore, db: Engine, effects: EffectsLog
) -> None:
    """The same approval applied twice sequentially: one effect, one terminal
    transition, BOTH calls return the recorded success (SPEC scenario 5)."""
    key = "k-apply-dup"
    ref = _persist_pause(store, key=key)
    reg = _registry(effects, key)

    first = apply_decision(store, ref, APPROVE, registry=reg)
    second = apply_decision(store, ref, APPROVE, registry=reg)

    assert first.applied and first.status is PauseStatus.COMMITTED
    assert second.status is PauseStatus.COMMITTED
    assert not second.applied  # pure read-back
    assert second.result == first.result
    assert effects.count(key) == 1
    assert len(_action_events(db, key)) == 1
    edges = [(p["from_status"], p["to_status"]) for p in _pause_transitions(db, ref)]
    assert edges == [("proposed", "approved"), ("approved", "committed")]
    verify_chain(store)


def test_lost_cas_still_drives_to_commit(
    store: PostgresStore, db: Engine, effects: EffectsLog
) -> None:
    """PLAN.md 4.3 / settled decision 3: 'already approved but never committed'
    (the crash-between-CAS-and-commit shape, staged here via a bare store CAS)
    must still drive to commit on the next delivery — a lost CAS is NOT a no-op."""
    key = "k-apply-lostcas"
    ref = _persist_pause(store, key=key)
    run = store.load_paused_by_ref(ref)
    assert run is not None
    # Another applier's CAS landed... and then it crashed before commit_once.
    assert store.transition_paused(
        run.run_id, PauseStatus.PROPOSED, PauseStatus.APPROVED, decision=APPROVE
    )
    assert effects.count(key) == 0  # nothing committed yet — the dangerous window

    # Redelivery: OUR decision CAS loses, but the run is driven to committed.
    outcome = apply_decision(store, ref, APPROVE, registry=_registry(effects, key))
    assert outcome.status is PauseStatus.COMMITTED
    assert outcome.applied  # we performed the ledger commit + terminal edge
    assert effects.count(key) == 1
    assert len(_action_events(db, key)) == 1
    verify_chain(store)


def test_sweep_mode_decision_none_drives_approved_to_committed(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """decision=None (the reconciler sweep's mode) ensures-committed a stranded
    approved run without inventing anything."""
    key = "k-apply-sweep"
    ref = _persist_pause(store, key=key)
    run = store.load_paused_by_ref(ref)
    assert run is not None
    assert store.transition_paused(
        run.run_id, PauseStatus.PROPOSED, PauseStatus.APPROVED, decision=APPROVE
    )
    outcome = apply_decision(store, ref, None, registry=_registry(effects, key))
    assert outcome.status is PauseStatus.COMMITTED
    assert effects.count(key) == 1


def test_decision_none_on_proposed_is_untouched(store: PostgresStore, effects: EffectsLog) -> None:
    """No decision recorded, none supplied: nothing to drive — a decision is
    never invented (and there is no TTL that could expire it)."""
    key = "k-apply-none"
    ref = _persist_pause(store, key=key)
    outcome = apply_decision(store, ref, None, registry=_registry(effects, key))
    assert outcome.status is PauseStatus.PROPOSED
    assert not outcome.applied
    assert effects.count(key) == 0
    run = store.load_paused_by_ref(ref)
    assert run is not None and run.status is PauseStatus.PROPOSED


# ---------------------------------------------------------------------------
# The reject path.
# ---------------------------------------------------------------------------


def test_reject_aborts_without_touching_the_ledger(
    store: PostgresStore, db: Engine, effects: EffectsLog
) -> None:
    key = "k-apply-rej"
    ref = _persist_pause(store, key=key)
    outcome = apply_decision(store, ref, REJECT, registry=_registry(effects, key))

    assert outcome.applied
    assert outcome.status is PauseStatus.ABORTED
    assert outcome.human_decision is HumanDecision.REJECTED
    assert outcome.ledger_state is None  # a rejection never claims the ledger
    assert effects.count(key) == 0
    with db.connect() as conn:
        claimed = conn.execute(
            text("SELECT count(*) FROM commit_records WHERE idempotency_key = :k"), {"k": key}
        ).scalar_one()
    assert claimed == 0

    events = _action_events(db, key)
    assert len(events) == 1
    assert events[0]["outcome"] == "aborted"
    assert events[0]["human_decision"] == "rejected"
    assert events[0]["policy_decision"] == "gate"
    edges = [(p["from_status"], p["to_status"]) for p in _pause_transitions(db, ref)]
    assert edges == [("proposed", "rejected"), ("rejected", "aborted")]
    verify_chain(store)


def test_duplicate_reject_returns_recorded_outcome_without_second_event(
    store: PostgresStore, db: Engine, effects: EffectsLog
) -> None:
    key = "k-apply-rej-dup"
    ref = _persist_pause(store, key=key)
    reg = _registry(effects, key)
    apply_decision(store, ref, REJECT, registry=reg)
    again = apply_decision(store, ref, REJECT, registry=reg)
    assert again.status is PauseStatus.ABORTED
    assert not again.applied
    assert len(_action_events(db, key)) == 1
    verify_chain(store)


REJECT_WITH_CODE = ApprovalDecision(
    decision=HumanDecision.REJECTED,
    decided_by="usr_no",
    reason="please attach the signed invoice",
    reason_code="needs_more_info",
)


def test_reject_with_code_persists_reason_code_and_surfaces_it(
    store: PostgresStore, db: Engine, effects: EffectsLog
) -> None:
    """A rejection carrying reason_code (P3.9) is persisted on the row AND
    surfaced on the DecisionOutcome (the whole inbound path)."""
    key = "k-apply-rej-code"
    ref = _persist_pause(store, key=key)
    outcome = apply_decision(store, ref, REJECT_WITH_CODE, registry=_registry(effects, key))

    assert outcome.status is PauseStatus.ABORTED
    assert outcome.human_decision is HumanDecision.REJECTED
    # Surfaced on the outcome (→ ApprovalRejected.reason_code in @guard).
    assert outcome.reason_code == "needs_more_info"
    assert outcome.reason == "please attach the signed invoice"
    # Persisted on the paused_runs row (not only in memory).
    run = store.load_paused_by_ref(ref)
    assert run is not None
    assert run.reason_code == "needs_more_info"
    assert run.reason == "please attach the signed invoice"
    verify_chain(store)


def test_approval_leaves_reason_code_none(store: PostgresStore, effects: EffectsLog) -> None:
    """An approval (no rejection) carries no reason_code — it stays None."""
    key = "k-apply-appr-nocode"
    ref = _persist_pause(store, key=key)
    outcome = apply_decision(store, ref, APPROVE, registry=_registry(effects, key))
    assert outcome.status is PauseStatus.COMMITTED
    assert outcome.reason_code is None
    assert outcome.reason is None
    run = store.load_paused_by_ref(ref)
    assert run is not None and run.reason_code is None and run.reason is None


def test_fresh_process_resume_surfaces_persisted_reason_code(
    store: PostgresStore, backend: Any, effects: EffectsLog
) -> None:
    """A FRESH process (new store over the same DB) that rehydrates by
    approval_ref still surfaces the persisted reason_code — it does not live
    only in the in-memory ApprovalDecision (P3.9)."""
    key = "k-apply-rej-code-resume"
    ref = _persist_pause(store, key=key)
    # "Process 1" records the rejection (persists reason_code on the row).
    apply_decision(store, ref, REJECT_WITH_CODE, registry=_registry(effects, key))

    # "Process 2": a brand-new store object over the same database, driving the
    # already-recorded decision home with NO fresh decision (redelivery / sweep).
    fresh = backend.make_store()
    try:
        outcome = apply_decision(fresh, ref, None, registry=_registry(effects, key))
    finally:
        fresh.close()
    assert outcome.status is PauseStatus.ABORTED
    assert outcome.human_decision is HumanDecision.REJECTED
    assert outcome.reason_code == "needs_more_info"  # surfaced from the row, fresh process
    assert outcome.reason == "please attach the signed invoice"
    assert not outcome.applied  # the terminal outcome was merely read back


def test_conflicting_decisions_first_writer_wins(store: PostgresStore, effects: EffectsLog) -> None:
    """Approve lands first; a late reject cannot flip it — it returns the
    recorded committed outcome (the ADR-4 DAG has no approved->rejected edge)."""
    key = "k-apply-conflict"
    ref = _persist_pause(store, key=key)
    reg = _registry(effects, key)
    first = apply_decision(store, ref, APPROVE, registry=reg)
    late = apply_decision(store, ref, REJECT, registry=reg)
    assert first.status is PauseStatus.COMMITTED
    assert late.status is PauseStatus.COMMITTED  # the recorded outcome, not a flip
    assert late.human_decision is HumanDecision.APPROVED
    assert not late.applied
    assert effects.count(key) == 1


# ---------------------------------------------------------------------------
# Scenario 8 — stale approval: preconditions re-validated at commit time.
# ---------------------------------------------------------------------------


def test_scenario_8_stale_approval_aborts_with_both_snapshots(
    store: PostgresStore, db: Engine, effects: EffectsLog
) -> None:
    """Precondition snapshot at propose time; the world changes; the approval
    arrives -> re-validation fails -> aborted, ZERO effects, and the chained
    record carries precondition_failed with BOTH snapshots."""
    key = "k-apply-stale"
    world = {"balance": 500}

    def precondition_ok(**_: Any) -> bool:
        return world["balance"] >= 120

    ref = _persist_pause(
        store,
        key=key,
        precondition_snapshot={"held": True, "checked_at": "2026-07-07T00:00:00.000000Z"},
    )
    reg = _registry(effects, key, preconditions=precondition_ok)

    world["balance"] = 10  # the world changed between propose and approve

    outcome = apply_decision(store, ref, APPROVE, registry=reg)
    assert outcome.status is PauseStatus.ABORTED
    assert outcome.ledger_state is LedgerState.ABORTED
    assert outcome.human_decision is HumanDecision.APPROVED  # approved, then aborted
    assert effects.count(key) == 0

    # The terminal action_event: gate + approved + aborted.
    events = _action_events(db, key)
    assert len(events) == 1
    assert events[0]["outcome"] == "aborted"
    assert events[0]["human_decision"] == "approved"

    # The chained pause record carries precondition_failed with BOTH snapshots.
    edges = _pause_transitions(db, ref)
    terminal = edges[-1]
    assert (terminal["from_status"], terminal["to_status"]) == ("approved", "aborted")
    detail = terminal["detail"]
    assert detail["reason"] == "precondition_failed"
    assert detail["precondition_snapshot"] == {
        "held": True,
        "checked_at": "2026-07-07T00:00:00.000000Z",
    }
    assert detail["precondition_recheck"]["held"] is False
    assert detail["ledger_state"] == "aborted"
    verify_chain(store)


# ---------------------------------------------------------------------------
# No-op paths: committed/aborted rows -> recorded outcome, ZERO writes.
# ---------------------------------------------------------------------------


def _row_snapshot(db: Engine, ref: str) -> tuple[str, Any]:
    """A write-detector snapshot of the paused row.

    On Postgres, ``xmin`` (the row's writing txid) changes iff ANY write touched
    the row, so it is the strongest no-write proof. SQLite has no xmin; the
    equivalent proof is full-row equality (every column identical before/after)
    plus the chain-head seq being unchanged (checked by the caller) — together
    they prove no write occurred.
    """
    if db.dialect.name == "sqlite":
        with db.connect() as conn:
            row = (
                conn.execute(
                    text("SELECT * FROM paused_runs WHERE approval_ref = :ref"),
                    {"ref": ref},
                )
                .mappings()
                .one()
            )
        return "", dict(row)
    with db.connect() as conn:
        row = (
            conn.execute(
                text(
                    "SELECT xmin::text AS x, * FROM paused_runs"
                    " WHERE approval_ref = CAST(:ref AS UUID)"
                ),
                {"ref": ref},
            )
            .mappings()
            .one()
        )
    return row["x"], dict(row)


@pytest.mark.parametrize("final", ["committed", "aborted"])
def test_noop_on_resolved_run_performs_zero_writes(
    store: PostgresStore, db: Engine, effects: EffectsLog, final: str
) -> None:
    key = f"k-apply-noop-{final}"
    ref = _persist_pause(store, key=key)
    reg = _registry(effects, key)
    decision = APPROVE if final == "committed" else REJECT
    apply_decision(store, ref, decision, registry=reg)

    xmin_before, row_before = _row_snapshot(db, ref)
    head_before = store.audit_head()
    assert head_before is not None

    replay = apply_decision(store, ref, decision, registry=reg)
    assert replay.status is PauseStatus(final)
    assert not replay.applied

    xmin_after, row_after = _row_snapshot(db, ref)
    assert xmin_after == xmin_before  # the row was not written AT ALL
    assert row_after == row_before
    head_after = store.audit_head()
    assert head_after is not None
    assert head_after.seq == head_before.seq  # and no audit row was appended
    assert effects.count(key) == (1 if final == "committed" else 0)


# ---------------------------------------------------------------------------
# Refusals: unknown ref, unknown state_version, reserved edited_args,
# unregistered action_type.
# ---------------------------------------------------------------------------


def test_unknown_approval_ref_raises(store: PostgresStore, effects: EffectsLog) -> None:
    ghost = str(uuid.uuid4())
    with pytest.raises(UnknownApprovalRef) as excinfo:
        apply_decision(store, ghost, APPROVE, registry=Registry())
    assert excinfo.value.approval_ref == ghost


def test_unknown_state_version_is_refused_loudly(
    store: PostgresStore, db: Engine, effects: EffectsLog
) -> None:
    """A fixture row with a FUTURE state_version is refused (never misparsed),
    the run is untouched, and no effect runs — the scenario-6 version gate."""
    key = "k-apply-version"
    ref = _persist_pause(store, key=key)
    ver_sql = (
        "UPDATE paused_runs SET state_version = :v WHERE approval_ref = :ref"
        if db.dialect.name == "sqlite"
        else "UPDATE paused_runs SET state_version = :v WHERE approval_ref = CAST(:ref AS UUID)"
    )
    with db.begin() as conn:
        conn.execute(text(ver_sql), {"v": STATE_VERSION + 1, "ref": ref})
    with pytest.raises(StateVersionError) as excinfo:
        apply_decision(store, ref, APPROVE, registry=_registry(effects, key))
    assert excinfo.value.found == STATE_VERSION + 1
    assert excinfo.value.supported == STATE_VERSION
    assert effects.count(key) == 0
    run = store.load_paused_by_ref(ref)
    assert run is not None and run.status is PauseStatus.PROPOSED  # untouched


def test_edited_args_is_reserved_and_refused_at_construction() -> None:
    with pytest.raises(NotImplementedError, match="edit-before-approve"):
        ApprovalDecision(
            decision=HumanDecision.APPROVED,
            edited_args={"amount": "1.00"},  # type: ignore[arg-type]
        )


def test_unregistered_action_type_cannot_resume(store: PostgresStore, effects: EffectsLog) -> None:
    """An approved run whose action_type has no registration raises loudly and
    stays approved — guessing the execute would run the wrong code."""
    key = "k-apply-unreg"
    ref = _persist_pause(store, key=key)
    with pytest.raises(AirlockError, match="no registration"):
        apply_decision(store, ref, APPROVE, registry=Registry())
    run = store.load_paused_by_ref(ref)
    assert run is not None
    assert run.status is PauseStatus.APPROVED  # decision recorded; commit pending
    assert effects.count(key) == 0
    # Once the module is importable/registered, the SAME delivery resumes it.
    outcome = apply_decision(store, ref, APPROVE, registry=_registry(effects, key))
    assert outcome.status is PauseStatus.COMMITTED
    assert effects.count(key) == 1


# ---------------------------------------------------------------------------
# Decision metadata: latency verbatim vs. locally computed.
# ---------------------------------------------------------------------------


def test_latency_recorded_verbatim_when_supplied(
    clock_store: PostgresStore, fake_clock: FakeClock, effects: EffectsLog
) -> None:
    key = "k-apply-lat-verbatim"
    ref = _persist_pause(clock_store, key=key)
    decision = ApprovalDecision(
        decision=HumanDecision.APPROVED, decided_by="usr_cp", decision_latency_ms=98765
    )
    apply_decision(clock_store, ref, decision, registry=_registry(effects, key), now_fn=fake_clock)
    run = clock_store.load_paused_by_ref(ref)
    assert run is not None
    assert run.decision_latency_ms == 98765  # verbatim (PLAN.md 6.2)


def test_latency_computed_from_sdk_clock_pair_when_absent(
    clock_store: PostgresStore, fake_clock: FakeClock, effects: EffectsLog
) -> None:
    key = "k-apply-lat-local"
    ref = _persist_pause(clock_store, key=key)  # created_at = T0
    fake_clock.advance(5)  # the human takes 5 seconds
    apply_decision(clock_store, ref, APPROVE, registry=_registry(effects, key), now_fn=fake_clock)
    run = clock_store.load_paused_by_ref(ref)
    assert run is not None
    assert run.decision_latency_ms == 5000  # same clock pair, no skew
