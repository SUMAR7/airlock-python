"""@guard GATE → durable pause → resume, end to end (P2.3, deliverable B).

Drives the REAL wiring: a GATE decision persists a paused_runs row, delivers it
through a ConsoleApprovalTransport, and either waits inline (an auto-approving
transport writes the decision on send, so wait() finds it on the first scan —
no threads, no sleep) or raises ActionPending for an out-of-band Airlock.resume.
Effect ground truth is the effects_log autocommit table.

Covers:
- inline approve: commit exactly once, returns the tool result, one action_event;
- inline reject: ApprovalRejected, zero effects;
- gate_wait=False → ActionPending; Airlock.resume(ref, decision) commits once;
- re-gate after reject: attaches to the SAME run, surfaces the rejection (no new
  run, no effect); a distinguishing arg opens a NEW run;
- re-gate of a committed run: returns the recorded result, no second effect;
- resume with an unknown state_version is refused loudly (scenario 6 gate);
- scenario 8 through the decorator: preconditions fail at commit → aborted.
"""

from __future__ import annotations

import io
from typing import TYPE_CHECKING, Any

import pytest
from sqlalchemy import text

from airlock import guard, init
from airlock.effects import Effect
from airlock.errors import ActionPending, ApprovalRejected, PreconditionFailed, StateVersionError
from airlock.transport.console import ConsoleApprovalTransport
from airlock.types import HumanDecision, Money, PauseStatus, Reversibility

if TYPE_CHECKING:
    from pathlib import Path

    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore
    from tests.conftest import EffectsLog

pytestmark = pytest.mark.usefixtures("guard_isolation")


class _AutoDecideTransport(ConsoleApprovalTransport):
    """A ConsoleApprovalTransport that records a preset decision on send().

    Simulates an instant human: send() writes the decision line to the same file
    wait() polls, so the inline gate wait finds it on the FIRST scan — exercising
    the real console file read path with no threads and no sleeping.
    """

    def __init__(
        self,
        path: Path,
        decision: HumanDecision,
        *,
        reason: str | None = None,
        reason_code: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(path, out=io.StringIO(), **kwargs)
        self._decision = decision
        self._reason = reason
        self._reason_code = reason_code

    def send(self, request: Any) -> Any:
        receipt = super().send(request)
        self.record_decision(
            request.approval_ref,
            self._decision,
            decided_by="usr_auto",
            reason=self._reason,
            reason_code=self._reason_code,
        )
        return receipt


def _gated_refund(effects: EffectsLog, preconditions: Any = None):  # type: ignore[no-untyped-def]
    @guard(
        "gate.refund",
        cost=Money(amount="120.00", currency="USD"),
        reversibility=Reversibility.IRREVERSIBLE,
        effect=Effect(key_param="idempotency_key"),
        preconditions=preconditions,
    )
    def do_refund(invoice: str, *, idempotency_key: str | None = None) -> dict[str, Any]:
        effects.log(invoice)
        return {"refunded": invoice, "dk": idempotency_key}

    return do_refund


def _action_event_count(db: Engine, action_type: str) -> int:
    with db.connect() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT count(*) FROM audit_events WHERE event_type = 'action_event'"
                    " AND action_type = :a"
                ),
                {"a": action_type},
            ).scalar_one()
        )


# ---------------------------------------------------------------------------
# Inline wait: approve / reject.
# ---------------------------------------------------------------------------


def test_gate_inline_approve_commits_once_and_returns_result(
    store: PostgresStore, effects: EffectsLog, db: Engine, tmp_path: Path
) -> None:
    transport = _AutoDecideTransport(tmp_path / "ap.jsonl", HumanDecision.APPROVED)
    init(store=store, policy=None, transport=transport)  # default Policy() = GATE
    do_refund = _gated_refund(effects)

    result = do_refund("inv_1")
    assert result["refunded"] == "inv_1"
    assert effects.count("inv_1") == 1

    with db.connect() as conn:
        pause = conn.execute(
            text("SELECT status FROM paused_runs WHERE action_type = 'gate.refund'")
        ).scalar_one()
        ledger = conn.execute(
            text("SELECT state FROM commit_records WHERE action_type = 'gate.refund'")
        ).scalar_one()
    assert pause == "committed"
    assert ledger == "committed"
    assert _action_event_count(db, "gate.refund") == 1  # exactly one terminal event


def test_gate_inline_reject_raises_and_runs_nothing(
    store: PostgresStore, effects: EffectsLog, db: Engine, tmp_path: Path
) -> None:
    transport = _AutoDecideTransport(tmp_path / "ap.jsonl", HumanDecision.REJECTED)
    init(store=store, transport=transport)
    do_refund = _gated_refund(effects)

    with pytest.raises(ApprovalRejected) as excinfo:
        do_refund("inv_r")
    assert excinfo.value.action_type == "gate.refund"
    assert excinfo.value.decided_by == "usr_auto"
    assert effects.count("inv_r") == 0
    # No ledger row is ever claimed for a rejection.
    with db.connect() as conn:
        ledger = conn.execute(
            text("SELECT count(*) FROM commit_records WHERE action_type = 'gate.refund'")
        ).scalar_one()
    assert ledger == 0


def test_gate_inline_reject_surfaces_reason_code_on_the_exception(
    store: PostgresStore, effects: EffectsLog, db: Engine, tmp_path: Path
) -> None:
    """The reviewer's chosen code flows all the way through: wire/transport →
    ApprovalDecision → persisted on paused_runs → ApprovalRejected.reason_code
    (P3.9). The offered reject_reasons are integrator-authored on @guard."""
    transport = _AutoDecideTransport(
        tmp_path / "ap.jsonl",
        HumanDecision.REJECTED,
        reason="please attach the signed invoice",
        reason_code="needs_more_info",
    )
    init(store=store, transport=transport)

    @guard(
        "gate.refund",
        cost=Money(amount="120.00", currency="USD"),
        reversibility=Reversibility.IRREVERSIBLE,
        effect=Effect(key_param="idempotency_key"),
        reject_reasons={
            "needs_more_info": "Needs more information",
            "not_authorized": "Not authorized for this amount",
        },
    )
    def do_refund(invoice: str, *, idempotency_key: str | None = None) -> dict[str, Any]:
        effects.log(invoice)  # pragma: no cover — gated, rejected, never runs
        return {"refunded": invoice}

    with pytest.raises(ApprovalRejected) as excinfo:
        do_refund("inv_rc")
    assert excinfo.value.reason_code == "needs_more_info"
    assert excinfo.value.reason == "please attach the signed invoice"
    assert excinfo.value.decided_by == "usr_auto"
    assert effects.count("inv_rc") == 0
    # And it is durably on the row (a fresh-process resume would surface it too).
    run = store.load_paused_by_ref(excinfo.value.approval_ref)
    assert run is not None and run.reason_code == "needs_more_info"


def test_gate_inline_dedupes_a_retry(
    store: PostgresStore, effects: EffectsLog, db: Engine, tmp_path: Path
) -> None:
    """A second call with the same args re-gates, attaches to the committed run,
    and returns the recorded result with NO second effect (collide-and-dedupe)."""
    transport = _AutoDecideTransport(tmp_path / "ap.jsonl", HumanDecision.APPROVED)
    init(store=store, transport=transport)
    do_refund = _gated_refund(effects)

    first = do_refund("inv_dup")
    second = do_refund("inv_dup")
    assert second == first
    assert effects.count("inv_dup") == 1
    with db.connect() as conn:
        runs = conn.execute(
            text("SELECT count(*) FROM paused_runs WHERE action_type = 'gate.refund'")
        ).scalar_one()
    assert runs == 1  # attached to the same run, not a second


# ---------------------------------------------------------------------------
# Async: gate_wait=False → ActionPending → Airlock.resume.
# ---------------------------------------------------------------------------


def test_gate_wait_false_then_resume_commits_once(
    store: PostgresStore, effects: EffectsLog, db: Engine, tmp_path: Path
) -> None:
    transport = ConsoleApprovalTransport(tmp_path / "ap.jsonl", out=io.StringIO())
    airlock = init(store=store, transport=transport, gate_wait=False)
    do_refund = _gated_refund(effects)

    with pytest.raises(ActionPending) as excinfo:
        do_refund("inv_async")
    ref = excinfo.value.approval_ref
    assert ref is not None
    assert effects.count("inv_async") == 0

    # Out of band: a human decides; resume drives it home exactly once.
    outcome = airlock.resume(ref, HumanDecision.APPROVED)
    assert outcome.status is PauseStatus.COMMITTED
    assert effects.count("inv_async") == 1
    # A duplicate resume is a no-op (scenario 5 through resume).
    again = airlock.resume(ref, HumanDecision.APPROVED)
    assert again.status is PauseStatus.COMMITTED and not again.applied
    assert effects.count("inv_async") == 1


def test_resume_none_drives_a_previously_approved_run(
    store: PostgresStore, effects: EffectsLog, tmp_path: Path
) -> None:
    """resume(ref) with no decision drives an already-approved run home
    (the ensure-committed / sweep mode) without inventing a decision."""
    transport = ConsoleApprovalTransport(tmp_path / "ap.jsonl", out=io.StringIO())
    airlock = init(store=store, transport=transport, gate_wait=False)
    do_refund = _gated_refund(effects)
    with pytest.raises(ActionPending) as excinfo:
        do_refund("inv_n")
    ref = excinfo.value.approval_ref
    assert ref is not None
    # Record the approval on the pause row but do not commit (staged crash window).
    run = store.load_paused_by_ref(ref)
    assert run is not None
    from airlock.types import ApprovalDecision

    store.transition_paused(
        run.run_id,
        PauseStatus.PROPOSED,
        PauseStatus.APPROVED,
        decision=ApprovalDecision(decision=HumanDecision.APPROVED),
    )
    outcome = airlock.resume(ref, None)  # ensure-committed
    assert outcome.status is PauseStatus.COMMITTED
    assert effects.count("inv_n") == 1


# ---------------------------------------------------------------------------
# Re-gate semantics.
# ---------------------------------------------------------------------------


def test_regate_after_reject_surfaces_rejection_no_new_run(
    store: PostgresStore, effects: EffectsLog, db: Engine, tmp_path: Path
) -> None:
    transport = _AutoDecideTransport(tmp_path / "ap.jsonl", HumanDecision.REJECTED)
    init(store=store, transport=transport)
    do_refund = _gated_refund(effects)

    with pytest.raises(ApprovalRejected):
        do_refund("inv_rg")
    # Re-gate with identical args: attaches to the SAME (aborted) run and
    # surfaces the recorded rejection — no new run, no effect.
    with pytest.raises(ApprovalRejected):
        do_refund("inv_rg")
    assert effects.count("inv_rg") == 0
    with db.connect() as conn:
        runs = conn.execute(
            text("SELECT count(*) FROM paused_runs WHERE action_type = 'gate.refund'")
        ).scalar_one()
    assert runs == 1  # a deliberate second attempt needs a distinguishing arg


def test_regate_with_distinguishing_arg_opens_a_new_run(
    store: PostgresStore, effects: EffectsLog, db: Engine, tmp_path: Path
) -> None:
    transport = _AutoDecideTransport(tmp_path / "ap.jsonl", HumanDecision.REJECTED)
    init(store=store, transport=transport)
    do_refund = _gated_refund(effects)
    with pytest.raises(ApprovalRejected):
        do_refund("inv_a")
    with pytest.raises(ApprovalRejected):
        do_refund("inv_b")  # different arg → different key → new run
    with db.connect() as conn:
        runs = conn.execute(
            text("SELECT count(*) FROM paused_runs WHERE action_type = 'gate.refund'")
        ).scalar_one()
    assert runs == 2


# ---------------------------------------------------------------------------
# Scenario 8 through the decorator + the state_version gate.
# ---------------------------------------------------------------------------


def test_gate_precondition_failure_aborts(
    store: PostgresStore, effects: EffectsLog, tmp_path: Path
) -> None:
    world = {"ok": True}
    transport = _AutoDecideTransport(tmp_path / "ap.jsonl", HumanDecision.APPROVED)
    init(store=store, transport=transport)

    def precond(invoice: str, **_: Any) -> bool:
        return world["ok"]

    do_refund = _gated_refund(effects, preconditions=precond)
    world["ok"] = False  # the world changed before approval lands
    with pytest.raises(PreconditionFailed):
        do_refund("inv_p")
    assert effects.count("inv_p") == 0


def test_resume_refuses_unknown_state_version_loudly(
    store: PostgresStore, effects: EffectsLog, db: Engine, tmp_path: Path
) -> None:
    transport = ConsoleApprovalTransport(tmp_path / "ap.jsonl", out=io.StringIO())
    airlock = init(store=store, transport=transport, gate_wait=False)
    do_refund = _gated_refund(effects)
    with pytest.raises(ActionPending) as excinfo:
        do_refund("inv_ver")
    ref = excinfo.value.approval_ref
    assert ref is not None
    with db.begin() as conn:
        conn.execute(
            text("UPDATE paused_runs SET state_version = 99 WHERE approval_ref = CAST(:r AS UUID)"),
            {"r": ref},
        )
    with pytest.raises(StateVersionError) as ver:
        airlock.resume(ref, HumanDecision.APPROVED)
    assert ver.value.found == 99
    assert effects.count("inv_ver") == 0
