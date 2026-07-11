"""SPEC.md scenario 5 (double delivery) — the barrier-raced half (P2.3).

The sequential half lives in ``test_apply_decision.py``; here the SAME approval
is applied from two threads released simultaneously by a Barrier, each with its
OWN PostgresStore (two independent appliers — the shape of a webhook delivered
twice, or a waiting agent racing a webhook receiver). The commit ledger's
``ON CONFLICT`` and the pause CAS are the concurrency guards: exactly one side
effect ever happens (``effects_log`` ground truth), exactly one terminal
``action_event`` is appended, and BOTH calls return the recorded committed
outcome. Synchronization is a Barrier + a Queue — never ``time.sleep``.
"""

from __future__ import annotations

import threading
import uuid
from typing import TYPE_CHECKING, Any

import pytest
from sqlalchemy import text

from airlock.audit import verify_chain
from airlock.effects import Effect
from airlock.pause import apply_decision, build_serialized_state
from airlock.store import from_url
from airlock.registry import Registry
from airlock.types import (
    ApprovalDecision,
    HumanDecision,
    Money,
    PauseStatus,
    Reversibility,
)

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore
    from tests.conftest import EffectsLog

pytestmark = pytest.mark.matrix

ACTION = "race.refund"
DEADLINE = 120.0


def _shared_registry(effects: EffectsLog, key: str) -> Registry:
    """One registry both threads use; execute logs the ground-truth effect."""
    reg = Registry()

    def execute(downstream_key: str | None, **_: Any) -> Any:
        effects.log(key)
        return {"refund_id": f"re_{key}"}

    reg.register(ACTION, Effect(key_param="idempotency_key"), execute)
    return reg


@pytest.mark.concurrency
def test_scenario_5_barrier_raced_double_delivery_one_effect(
    store: PostgresStore, db: Engine, effects: EffectsLog, store_dsn: str
) -> None:
    key = "k-race-approve"
    ref = str(uuid.uuid4())
    state = build_serialized_state(
        {"invoice": key},
        reversibility=Reversibility.IRREVERSIBLE,
        cost=Money(amount="99.00", currency="USD"),
        blast_radius=None,
        precondition_snapshot=None,
    )
    claim = store.save_paused(
        run_id=f"run_{ref[:8]}",
        idempotency_key=key,
        approval_ref=ref,
        action_type=ACTION,
        serialized_state=state,
    )
    assert claim.created

    registry = _shared_registry(effects, key)
    decision = ApprovalDecision(decision=HumanDecision.APPROVED, decided_by="usr_race")
    barrier = threading.Barrier(2)
    outcomes: list[Any] = []
    errors: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        worker_store = from_url(store_dsn)
        try:
            barrier.wait(timeout=DEADLINE)  # both fire together
            outcome = apply_decision(worker_store, ref, decision, registry=registry)
            with lock:
                outcomes.append(outcome)
        except Exception as exc:
            with lock:
                errors.append(repr(exc))
        finally:
            worker_store.close()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=DEADLINE)

    assert not errors, f"worker errors: {errors}"
    assert len(outcomes) == 2

    # Exactly one side effect; BOTH calls report the committed outcome.
    assert effects.count(key) == 1
    assert all(o.status is PauseStatus.COMMITTED for o in outcomes)
    results = {tuple(sorted(o.result.items())) for o in outcomes}
    assert len(results) == 1  # identical recorded result

    # At least one applier performed durable work. (Which call performs which
    # edge is genuinely nondeterministic under the race — one may win
    # proposed→approved while the other wins approved→committed — so both can
    # report applied=True. The load-bearing invariants are one effect, one
    # event, one committed row: a double-transition would show as a second
    # effect or a second event, which the assertions below forbid.)
    assert any(o.applied for o in outcomes)

    # Exactly one terminal action_event and one committed ledger row; chain OK.
    with db.connect() as conn:
        events = conn.execute(
            text(
                "SELECT count(*) FROM audit_events WHERE event_type = 'action_event'"
                " AND payload_json->>'idempotency_key' = :k"
            ),
            {"k": key},
        ).scalar_one()
        ledger = conn.execute(
            text("SELECT state FROM commit_records WHERE idempotency_key = :k"), {"k": key}
        ).scalar_one()
    assert events == 1
    assert ledger == "committed"
    verify_chain(store)


@pytest.mark.concurrency
def test_scenario_5_barrier_raced_conflicting_decisions_one_wins(
    store: PostgresStore, db: Engine, effects: EffectsLog, store_dsn: str
) -> None:
    """One thread approves, one rejects, released together: the ADR-4 DAG has no
    approved↔rejected flip, so whichever CAS lands first wins and BOTH threads
    converge on that recorded terminal outcome — never a double transition."""
    key = "k-race-conflict"
    ref = str(uuid.uuid4())
    state = build_serialized_state(
        {"invoice": key},
        reversibility=Reversibility.IRREVERSIBLE,
        cost=None,
        blast_radius=None,
        precondition_snapshot=None,
    )
    store.save_paused(
        run_id=f"run_{ref[:8]}",
        idempotency_key=key,
        approval_ref=ref,
        action_type=ACTION,
        serialized_state=state,
    )
    registry = _shared_registry(effects, key)
    barrier = threading.Barrier(2)
    outcomes: list[Any] = []
    errors: list[str] = []
    lock = threading.Lock()

    def worker(decision: ApprovalDecision) -> None:
        worker_store = from_url(store_dsn)
        try:
            barrier.wait(timeout=DEADLINE)
            outcome = apply_decision(worker_store, ref, decision, registry=registry)
            with lock:
                outcomes.append(outcome)
        except Exception as exc:
            with lock:
                errors.append(repr(exc))
        finally:
            worker_store.close()

    threads = [
        threading.Thread(target=worker, args=(ApprovalDecision(decision=HumanDecision.APPROVED),)),
        threading.Thread(target=worker, args=(ApprovalDecision(decision=HumanDecision.REJECTED),)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=DEADLINE)

    assert not errors, f"worker errors: {errors}"
    # Both threads converge on ONE terminal status (committed if approve won,
    # aborted if reject won) — never a split.
    statuses = {o.status for o in outcomes}
    assert len(statuses) == 1
    status = statuses.pop()
    assert status in (PauseStatus.COMMITTED, PauseStatus.ABORTED)
    # Effect count matches the winner: exactly one on commit, zero on reject.
    assert effects.count(key) == (1 if status is PauseStatus.COMMITTED else 0)
    verify_chain(store)
