"""The Phase-2 Definition of Done, verbatim, as ONE test (P2.3 — the MVP).

SPEC.md Phase 2 DoD: "a gated action pauses durably, survives a restart, resumes
once on approval, audit chain verifies." PLAN.md P2.3 row: "gated action pauses
durably, survives restart, resumes exactly once under double-delivered approval,
chain verifies."

The flow, end to end, exercising the REAL wiring:

1. a @guard-gated action is invoked in a SUBPROCESS (gate_wait=False) → it
   durably persists the paused_runs row and the process exits cleanly (a deploy
   / worker shutdown with the pause outstanding);
2. a FRESH process (this test) rehydrates by approval_ref;
3. the approval is delivered through the ConsoleApprovalTransport file — the
   line is written TWICE to prove idempotence (a double-delivered approval);
4. BOTH delivered approvals are resumed → the side effect commits EXACTLY ONCE
   (effects_log ground truth), the ledger row is committed, the pause is
   committed;
5. verify_chain passes end to end.
"""

from __future__ import annotations

import io
import json
import multiprocessing
from typing import TYPE_CHECKING

from sqlalchemy import text

from airlock import init
from airlock.audit import verify_chain
from airlock.registry import registry as default_registry
from airlock.transport.console import ConsoleApprovalTransport
from airlock.types import HumanDecision, PauseStatus
from tests import _pause_harness as harness
from tests._pause_harness import GATE_ACTION, effect_key

if TYPE_CHECKING:
    from pathlib import Path

    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore
    from tests.conftest import EffectsLog

DEADLINE = 120.0


def _spawn(target: object, **kwargs: object) -> int:
    ctx = multiprocessing.get_context("spawn")
    proc = ctx.Process(target=target, kwargs=kwargs, daemon=True)  # type: ignore[arg-type]
    proc.start()
    proc.join(timeout=DEADLINE)
    assert not proc.is_alive(), "gate subprocess did not exit"
    return proc.exitcode  # type: ignore[return-value]


def test_mvp_phase2_dod_end_to_end(
    store: PostgresStore, db: Engine, effects: EffectsLog, database_url: str, tmp_path: Path
) -> None:
    import os

    os.environ["AIRLOCK_TEST_DSN"] = database_url
    approvals = tmp_path / "approvals.jsonl"
    ref_out = tmp_path / "ref.json"
    invoice = "inv_mvp"

    # (1) Gate in a subprocess; it pauses durably and exits cleanly (the deploy).
    exitcode = _spawn(
        harness.run_gate_console_and_exit,
        dsn=database_url,
        approvals_path=str(approvals),
        ref_out_path=str(ref_out),
        invoice=invoice,
    )
    assert exitcode == 0, f"gate subprocess exited {exitcode}, expected a clean 0"
    ref = json.loads(ref_out.read_text(encoding="utf-8"))["approval_ref"]

    # (2) Fresh process: the pause survived the restart, still proposed, no effect.
    run = store.load_paused_by_ref(ref)
    assert run is not None
    assert run.status is PauseStatus.PROPOSED
    assert run.serialized_state["arg_map"] == {"invoice": invoice}
    assert effects.count(effect_key(invoice)) == 0
    assert GATE_ACTION in default_registry  # importing the harness registered it here

    # (3) Deliver the approval through the console file — TWICE (double delivery).
    transport = ConsoleApprovalTransport(approvals, out=io.StringIO())
    transport.record_decision(ref, HumanDecision.APPROVED, decided_by="usr_mvp")
    transport.record_decision(ref, HumanDecision.APPROVED, decided_by="usr_mvp")

    # (4) The fresh runtime resumes BOTH deliveries; exactly one effect commits.
    airlock = init(store=store, transport=transport, gate_wait=False)
    committed_count = 0
    for _ in range(2):  # process both delivered approvals
        decision = transport.wait(ref, timeout=0.0)
        assert decision is not None and decision.decision is HumanDecision.APPROVED
        outcome = airlock.resume(ref, decision)
        assert outcome.status is PauseStatus.COMMITTED
        committed_count += 1
    assert committed_count == 2  # both deliveries resolved to committed...
    assert effects.count(effect_key(invoice)) == 1  # ...but the effect fired ONCE

    # Ledger + pause are committed, and exactly one terminal action_event exists.
    with db.connect() as conn:
        ledger = conn.execute(
            text("SELECT state FROM commit_records WHERE action_type = :a"), {"a": GATE_ACTION}
        ).scalar_one()
        pause_status = conn.execute(
            text("SELECT status FROM paused_runs WHERE approval_ref = CAST(:r AS UUID)"),
            {"r": ref},
        ).scalar_one()
        events = conn.execute(
            text(
                "SELECT count(*) FROM audit_events WHERE event_type = 'action_event'"
                " AND action_type = :a"
            ),
            {"a": GATE_ACTION},
        ).scalar_one()
    assert ledger == "committed"
    assert pause_status == "committed"
    assert events == 1

    # (5) The hash-chained audit trail verifies end to end.
    verify_chain(store)
