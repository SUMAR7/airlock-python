"""Durable pause under process death (P2.3): SPEC scenario 6 + the
after_approve_cas_before_commit crashpoint (PLAN.md 10, settled decision 3).

Spawn subprocesses drive REAL product code to a boundary and die via
``os._exit`` (SIGKILL-equivalent), then a FRESH process proves the pause
survived and resolves exactly once. Ground truth is the ``effects_log``
autocommit table; the fake clock (advance, never sleep) drives the sweep.
"""

from __future__ import annotations

import json
import multiprocessing
import uuid
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from airlock.audit import verify_chain
from airlock.pause import STATE_VERSION, apply_decision, build_serialized_state
from airlock.reconcile import reconcile_paused
from airlock.registry import registry as default_registry
from airlock.types import (
    ApprovalDecision,
    HumanDecision,
    PauseStatus,
    Reversibility,
)
from tests import _pause_harness as harness
from tests._pause_harness import CRASH_EXIT_CODE, GATE_ACTION, effect_key

if TYPE_CHECKING:
    from pathlib import Path

    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore
    from tests.conftest import EffectsLog, FakeClock

pytestmark = pytest.mark.crash

DEADLINE = 120.0
OLDER_THAN = timedelta(seconds=60)


def _spawn(target: object, **kwargs: object) -> int:
    ctx = multiprocessing.get_context("spawn")
    proc = ctx.Process(target=target, kwargs=kwargs, daemon=True)  # type: ignore[arg-type]
    proc.start()
    proc.join(timeout=DEADLINE)
    assert not proc.is_alive(), "crash subprocess did not exit"
    return proc.exitcode  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Scenario 6 — approval arrives after a restart.
# ---------------------------------------------------------------------------


def test_scenario_6_gate_crash_then_fresh_process_resumes_once(
    store: PostgresStore, db: Engine, effects: EffectsLog, database_url: str, tmp_path: Path
) -> None:
    """A subprocess GATES the real @guard tool and os._exit's inside
    transport.send — AFTER the pause is persisted. A FRESH process (this one)
    rehydrates by approval_ref via the registry and applies the approval,
    committing exactly once; serialized_state byte-fidelity is asserted."""
    out = tmp_path / "ref.json"
    invoice = "inv_restart"

    exitcode = _spawn(
        harness.run_gate_and_crash_on_send, dsn=database_url, out_path=str(out), invoice=invoice
    )
    assert exitcode == CRASH_EXIT_CODE, f"expected os._exit({CRASH_EXIT_CODE}), got {exitcode}"

    info = json.loads(out.read_text(encoding="utf-8"))
    ref = info["approval_ref"]

    # The pause is durably persisted (survived process death), still proposed,
    # and no effect ran (the gate never executes the tool).
    run = store.load_paused_by_ref(ref)
    assert run is not None
    assert run.status is PauseStatus.PROPOSED
    assert run.run_id == info["run_id"]
    assert run.state_version == STATE_VERSION
    # serialized_state byte-fidelity: the arg_map is exactly the canonical call.
    assert run.serialized_state["arg_map"] == {"invoice": invoice}
    assert effects.count(effect_key(invoice)) == 0

    # FRESH process resume: importing the harness registered the tool in THIS
    # process's default registry, so apply_decision can rebuild the call.
    import os

    os.environ["AIRLOCK_TEST_DSN"] = database_url
    assert GATE_ACTION in default_registry
    outcome = apply_decision(
        store, ref, ApprovalDecision(decision=HumanDecision.APPROVED, decided_by="usr_fresh")
    )
    assert outcome.status is PauseStatus.COMMITTED
    assert effects.count(effect_key(invoice)) == 1

    # A re-delivered approval commits nothing more (scenario 5 across the restart).
    again = apply_decision(store, ref, ApprovalDecision(decision=HumanDecision.APPROVED))
    assert again.status is PauseStatus.COMMITTED and not again.applied
    assert effects.count(effect_key(invoice)) == 1
    verify_chain(store)


def test_scenario_6_unknown_state_version_is_refused_loudly(
    store: PostgresStore, db: Engine, effects: EffectsLog
) -> None:
    """A persisted pause carrying a FUTURE state_version is refused (never
    misparsed) — the fresh process cannot silently execute a different action
    than the human approved."""
    key = "k-restart-ver"
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
        action_type=GATE_ACTION,
        serialized_state=state,
        state_version=STATE_VERSION + 1,  # a version this SDK does not understand
    )
    from airlock.errors import StateVersionError

    with pytest.raises(StateVersionError) as excinfo:
        apply_decision(store, ref, ApprovalDecision(decision=HumanDecision.APPROVED))
    assert excinfo.value.found == STATE_VERSION + 1
    run = store.load_paused_by_ref(ref)
    assert run is not None and run.status is PauseStatus.PROPOSED  # untouched


# ---------------------------------------------------------------------------
# after_approve_cas_before_commit — ensure-committed (settled decision 3).
# ---------------------------------------------------------------------------


def _persist_and_capture_ref(store: PostgresStore, key: str, invoice: str) -> str:
    ref = str(uuid.uuid4())
    state = build_serialized_state(
        {"invoice": invoice},
        reversibility=Reversibility.IRREVERSIBLE,
        cost=None,
        blast_radius=None,
        precondition_snapshot=None,
    )
    claim = store.save_paused(
        run_id=f"run_{ref[:8]}",
        idempotency_key=key,
        approval_ref=ref,
        action_type=GATE_ACTION,
        serialized_state=state,
    )
    assert claim.created
    return ref


def test_after_approve_cas_before_commit_redelivery_drives_to_committed(
    store: PostgresStore, db: Engine, effects: EffectsLog, database_url: str
) -> None:
    """A subprocess applies APPROVE and crashes right after the proposed→approved
    CAS commits, before commit_once. Durable state: approved, ledger empty, no
    effect. A REDELIVERY drives it to committed with exactly one effect — a lost
    CAS is not a no-op (the ensure-committed proof)."""
    import os

    os.environ["AIRLOCK_TEST_DSN"] = database_url
    invoice = "inv_cas"
    key = "k-cas-redeliver"
    ref = _persist_and_capture_ref(store, key, invoice)

    exitcode = _spawn(harness.run_apply_crash_after_cas, dsn=database_url, approval_ref=ref)
    assert exitcode == CRASH_EXIT_CODE

    # Durable window: approved, but nothing committed and no effect fired.
    run = store.load_paused_by_ref(ref)
    assert run is not None and run.status is PauseStatus.APPROVED
    with db.connect() as conn:
        ledger = conn.execute(
            text("SELECT count(*) FROM commit_records WHERE idempotency_key = :k"), {"k": key}
        ).scalar_one()
    assert ledger == 0
    assert effects.count(effect_key(invoice)) == 0

    # Redelivery of the SAME approval drives the stranded run home, exactly once.
    outcome = apply_decision(store, ref, ApprovalDecision(decision=HumanDecision.APPROVED))
    assert outcome.status is PauseStatus.COMMITTED
    assert effects.count(effect_key(invoice)) == 1
    verify_chain(store)


def test_after_approve_cas_before_commit_sweep_drives_to_committed(
    clock_store: PostgresStore,
    fake_clock: FakeClock,
    db: Engine,
    effects: EffectsLog,
    database_url: str,
) -> None:
    """The SAME crash window, closed by the reconciler sweep instead of a
    redelivery: no approval ever arrives again, but reconcile_paused finds the
    stale approved row and ensures-committed it (one effect)."""
    import os

    os.environ["AIRLOCK_TEST_DSN"] = database_url
    invoice = "inv_cas_sweep"
    key = "k-cas-sweep"
    # Persist + approve on the fake-clock store (decided_at = T0), then crash the
    # commit in a subprocess (the subprocess uses a real clock, but only touches
    # the ledger, which it never reaches — it dies right after the approve CAS).
    ref = _persist_and_capture_ref(clock_store, key, invoice)
    exitcode = _spawn(harness.run_apply_crash_after_cas, dsn=database_url, approval_ref=ref)
    assert exitcode == CRASH_EXIT_CODE
    assert effects.count(effect_key(invoice)) == 0

    # The subprocess stamped decided_at from its own real clock; rebase it onto
    # the fake-clock timeline so advancing the clock makes the row stale.
    with db.begin() as conn:
        conn.execute(
            text("UPDATE paused_runs SET decided_at = :t WHERE approval_ref = CAST(:r AS UUID)"),
            {"t": fake_clock(), "r": ref},
        )
    fake_clock.advance(120)  # past OLDER_THAN → stale approved

    report = reconcile_paused(clock_store, older_than=OLDER_THAN, now_fn=fake_clock)
    assert report.count("committed") == 1
    assert effects.count(effect_key(invoice)) == 1
    run = clock_store.load_paused_by_ref(ref)
    assert run is not None and run.status is PauseStatus.COMMITTED
    verify_chain(clock_store)
