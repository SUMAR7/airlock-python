"""The reconciler ``paused_runs`` sweep (P2.3, PLAN.md 4.2/4.3).

The crash-between-approve-CAS-and-commit window (settled decision 3): a run that
a human APPROVED but whose ``commit_once`` never landed sits ``approved``
forever unless something re-drives it. :func:`airlock.reconcile.reconcile_paused`
scans stale approved rows and drives each through ``apply_decision`` (decision
=None, ensure-committed). Covered here with the fake clock (advance, never
sleep) and effects_log ground truth:

- a stranded approved run is driven to committed with exactly one effect;
- a stranded approved run whose preconditions now fail aborts (scenario 8),
  zero effects;
- proposed rows are NEVER swept (no TTL in v1, ADR-4);
- a fresh (not-yet-stale) approval is not swept;
- an unregistered action_type is recorded (error) and LEFT approved for a later
  pass — the sweep never aborts mid-scan;
- the sweep is idempotent: a second pass over an already-committed run is a
  no-op (zero new effects).
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from airlock.effects import Effect
from airlock.pause import build_serialized_state
from airlock.reconcile import reconcile_paused
from airlock.registry import Registry
from airlock.types import (
    ApprovalDecision,
    HumanDecision,
    Money,
    PauseStatus,
    Reversibility,
)

if TYPE_CHECKING:
    from airlock.store.postgres import PostgresStore
    from tests.conftest import EffectsLog, FakeClock

ACTION = "sweep.refund"
OLDER_THAN = timedelta(seconds=60)


def _persist_approved(
    store: PostgresStore,
    fake_clock: FakeClock,
    *,
    key: str,
    precondition_snapshot: dict[str, Any] | None = None,
) -> str:
    """Persist a run and drive it to APPROVED (the stranded state), no commit."""
    ref = str(uuid.uuid4())
    state = build_serialized_state(
        {"invoice": key},
        reversibility=Reversibility.IRREVERSIBLE,
        cost=Money(amount="42.00", currency="USD"),
        blast_radius=None,
        precondition_snapshot=precondition_snapshot,
    )
    claim = store.save_paused(
        run_id=f"run_{ref[:8]}",
        idempotency_key=key,
        approval_ref=ref,
        action_type=ACTION,
        serialized_state=state,
    )
    assert claim.created
    assert store.transition_paused(
        claim.run.run_id,
        PauseStatus.PROPOSED,
        PauseStatus.APPROVED,
        decision=ApprovalDecision(decision=HumanDecision.APPROVED, decided_at=fake_clock()),
    )
    return ref


def _registry(effects: EffectsLog, key: str, *, preconditions: Any = None) -> Registry:
    reg = Registry()

    def execute(downstream_key: str | None, **_: Any) -> Any:
        effects.log(key)
        return {"refund_id": f"re_{key}"}

    reg.register(ACTION, Effect(key_param="idempotency_key"), execute, preconditions)
    return reg


def test_stale_approved_run_is_driven_to_committed_once(
    clock_store: PostgresStore, fake_clock: FakeClock, effects: EffectsLog
) -> None:
    key = "k-sweep-commit"
    ref = _persist_approved(clock_store, fake_clock, key=key)
    fake_clock.advance(120)  # past OLDER_THAN → stale

    report = reconcile_paused(
        clock_store, older_than=OLDER_THAN, registry=_registry(effects, key), now_fn=fake_clock
    )
    assert report.count("committed") == 1
    assert effects.count(key) == 1
    run = clock_store.load_paused_by_ref(ref)
    assert run is not None and run.status is PauseStatus.COMMITTED


def test_sweep_is_idempotent_second_pass_no_new_effect(
    clock_store: PostgresStore, fake_clock: FakeClock, effects: EffectsLog
) -> None:
    key = "k-sweep-idem"
    _persist_approved(clock_store, fake_clock, key=key)
    fake_clock.advance(120)
    reg = _registry(effects, key)
    reconcile_paused(clock_store, older_than=OLDER_THAN, registry=reg, now_fn=fake_clock)
    # Second pass: the row is committed (terminal) — not in the approved scan.
    second = reconcile_paused(clock_store, older_than=OLDER_THAN, registry=reg, now_fn=fake_clock)
    assert second.total == 0
    assert effects.count(key) == 1


def test_stale_approval_with_failed_precondition_aborts_zero_effects(
    clock_store: PostgresStore, fake_clock: FakeClock, effects: EffectsLog
) -> None:
    key = "k-sweep-stale"
    world = {"ok": True}

    def precond(**_: Any) -> bool:
        return world["ok"]

    ref = _persist_approved(
        clock_store,
        fake_clock,
        key=key,
        precondition_snapshot={"held": True, "checked_at": "2026-07-07T00:00:00.000000Z"},
    )
    fake_clock.advance(120)
    world["ok"] = False  # the world changed after approval

    report = reconcile_paused(
        clock_store,
        older_than=OLDER_THAN,
        registry=_registry(effects, key, preconditions=precond),
        now_fn=fake_clock,
    )
    assert report.count("aborted") == 1
    assert effects.count(key) == 0
    run = clock_store.load_paused_by_ref(ref)
    assert run is not None and run.status is PauseStatus.ABORTED


def test_proposed_and_fresh_rows_are_never_swept(
    clock_store: PostgresStore, fake_clock: FakeClock, effects: EffectsLog
) -> None:
    # A proposed run (never decided) and a freshly-approved run (not yet stale).
    proposed_ref = str(uuid.uuid4())
    state = build_serialized_state(
        {"invoice": "prop"},
        reversibility=Reversibility.IRREVERSIBLE,
        cost=None,
        blast_radius=None,
        precondition_snapshot=None,
    )
    clock_store.save_paused(
        run_id="run_prop",
        idempotency_key="k-sweep-prop",
        approval_ref=proposed_ref,
        action_type=ACTION,
        serialized_state=state,
    )
    fresh_ref = _persist_approved(clock_store, fake_clock, key="k-sweep-fresh")
    fake_clock.advance(30)  # < OLDER_THAN: the fresh approval is not stale

    report = reconcile_paused(
        clock_store,
        older_than=OLDER_THAN,
        registry=_registry(effects, "k-sweep-fresh"),
        now_fn=fake_clock,
    )
    assert report.total == 0
    assert clock_store.load_paused_by_ref(proposed_ref).status is PauseStatus.PROPOSED  # type: ignore[union-attr]
    assert clock_store.load_paused_by_ref(fresh_ref).status is PauseStatus.APPROVED  # type: ignore[union-attr]


def test_unregistered_action_is_recorded_and_left_approved(
    clock_store: PostgresStore, fake_clock: FakeClock, effects: EffectsLog
) -> None:
    """An approved run whose action_type is not registered in THIS process is
    recorded (error) and left approved — the next sweep (with the module
    imported) resolves it. The sweep never aborts mid-scan on one bad row."""
    ref = _persist_approved(clock_store, fake_clock, key="k-sweep-unreg")
    fake_clock.advance(120)

    report = reconcile_paused(
        clock_store, older_than=OLDER_THAN, registry=Registry(), now_fn=fake_clock
    )
    assert report.count("error") == 1
    assert "no registration" in (report.actions[0].detail or "")
    run = clock_store.load_paused_by_ref(ref)
    assert run is not None and run.status is PauseStatus.APPROVED  # still resumable
