"""Subprocess harness for the durable-pause crash tests (P2.3, deliverable D).

Kept in ``tests/`` so no ``src/`` product code learns about crashpoints (the
scope fence the commit crashpoint harness already honors). Two crash shapes,
both driving REAL product code to a boundary and dying via ``os._exit`` in a
spawn subprocess (SIGKILL-equivalent: skips ``finally``/``atexit``, drops the DB
connection mid-transaction):

- **gate-then-crash (scenario 6):** run the REAL ``@guard`` GATE path with a
  transport that ``os._exit``es *inside* ``send`` — AFTER the ``paused_runs``
  row is durably persisted (``@guard`` persists before any transport call) — and
  writes the SDK-minted ``approval_ref`` out first so a FRESH process can
  rehydrate and resume. Proves the pause survives process death (an approval
  arriving after a deploy/restart resumes from persisted state).

- **after_approve_cas_before_commit:** a Store wrapper that ``os._exit``es right
  after the ``proposed -> approved`` CAS commits but BEFORE ``commit_once`` runs
  — the exact window PLAN.md 10 (settled decision 3) says must never strand an
  approval. The parent proves redelivery / the sweep drives it to committed with
  exactly one effect (ensure-committed).

The guarded tool is defined at MODULE level so importing this module registers
it in BOTH the subprocess and the parent (``@guard`` decoration is the only
registration side effect) — the fresh process can therefore rebuild the call
from the bare paused row. The effect is logged to ``effects_log`` on a separate
autocommit connection (ground truth), keyed by the DSN in ``AIRLOCK_TEST_DSN``.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
from typing import Any

from airlock import guard, init
from airlock.effects import Effect
from airlock.errors import ActionPending
from airlock.policy import Policy
from airlock.store.postgres import PostgresStore
from airlock.transport import PauseRequest, SendReceipt
from airlock.transport.console import ConsoleApprovalTransport
from airlock.types import (
    ApprovalDecision,
    AuditEvent,
    Decision,
    HumanDecision,
    Money,
    PauseStatus,
    Reversibility,
)
from tests._harness import EffectLogger

GATE_ACTION = "pause.harness.refund"
CRASH_EXIT_CODE = 137


def effect_key(invoice: str) -> str:
    """The stable effects_log key for one invoice (parent counts against it)."""
    return f"{GATE_ACTION}:{invoice}"


def _dsn() -> str:
    return os.environ["AIRLOCK_TEST_DSN"]


@guard(
    GATE_ACTION,
    cost=Money(amount="77.00", currency="USD"),
    reversibility=Reversibility.IRREVERSIBLE,
    effect=Effect(key_param="idempotency_key"),
)
def harness_refund(invoice: str, *, idempotency_key: str | None = None) -> dict[str, Any]:
    """The guarded tool. Its effect is the ground-truth effects_log row."""
    EffectLogger(_dsn()).log(effect_key(invoice))
    return {"refunded": invoice, "dk": idempotency_key}


class _CrashOnSendTransport:
    """A transport that writes the approval_ref then ``os._exit``es inside send.

    The durable pause is already persisted by the time ``send`` is called
    (``@guard`` persists first), so this leaves a durably-``proposed`` run whose
    ``approval_ref`` the parent reads back from ``out_path`` — the fresh process
    then rehydrates and resumes it.
    """

    def __init__(self, out_path: str) -> None:
        self._out_path = out_path

    def send(self, request: PauseRequest) -> SendReceipt:
        with open(self._out_path, "w", encoding="utf-8") as handle:
            json.dump({"approval_ref": request.approval_ref, "run_id": request.run_id}, handle)
        os._exit(CRASH_EXIT_CODE)  # pause durable; die before returning

    def wait(self, approval_ref: str, timeout: float) -> ApprovalDecision | None:
        raise AssertionError("gate_wait=False: wait must never be called")  # pragma: no cover


class _CrashAfterApproveCAS(PostgresStore):
    """A Store that ``os._exit``es right after the proposed→approved CAS lands.

    The crash falls in the after_approve_cas_before_commit window: the approve
    CAS (and its chained audit) are durably committed, but ``commit_once`` never
    runs — the ledger is untouched and no effect fired. Redelivery or the sweep
    must drive it to committed exactly once.
    """

    def transition_paused(
        self,
        run_id: str,
        from_status: PauseStatus,
        to_status: PauseStatus,
        *,
        decision: ApprovalDecision | None = None,
        audit: AuditEvent | tuple[AuditEvent, ...] | None = None,
    ) -> bool:
        won = super().transition_paused(
            run_id, from_status, to_status, decision=decision, audit=audit
        )
        if won and from_status is PauseStatus.PROPOSED and to_status is PauseStatus.APPROVED:
            os._exit(CRASH_EXIT_CODE)  # approve CAS durable; die before commit_once
        return won


def run_gate_and_crash_on_send(dsn: str, out_path: str, invoice: str) -> None:
    """Subprocess target: gate the harness tool, crashing inside transport.send."""
    os.environ["AIRLOCK_TEST_DSN"] = dsn
    store = PostgresStore(dsn)
    init(
        store=store,
        policy=Policy(default=Decision.GATE),
        transport=_CrashOnSendTransport(out_path),
        gate_wait=False,
    )
    harness_refund(invoice)  # persist pause → send → os._exit inside send
    os._exit(0)  # pragma: no cover — unreachable when the crash fires


def run_gate_console_and_exit(
    dsn: str, approvals_path: str, ref_out_path: str, invoice: str
) -> None:
    """Subprocess target (MVP e2e): gate through a ConsoleApprovalTransport with
    gate_wait=False, write the SDK-minted approval_ref out, and exit CLEANLY.

    Models a worker that durably paused a gated action and then ended (a deploy).
    The pause survives; the fresh process resumes it from the console file.
    """
    os.environ["AIRLOCK_TEST_DSN"] = dsn
    store = PostgresStore(dsn)
    init(
        store=store,
        policy=Policy(default=Decision.GATE),
        transport=ConsoleApprovalTransport(approvals_path, out=io.StringIO()),
        gate_wait=False,
    )
    try:
        harness_refund(invoice)
    except ActionPending as pending:
        Path(ref_out_path).write_text(
            json.dumps({"approval_ref": pending.approval_ref, "run_id": pending.run_id}),
            encoding="utf-8",
        )
        return  # clean exit 0 — the process "deployed away" with the pause durable
    raise AssertionError("a gated action must raise ActionPending under gate_wait=False")


def run_apply_crash_after_cas(dsn: str, approval_ref: str) -> None:
    """Subprocess target: apply APPROVE, crashing after the approve CAS commits."""
    os.environ["AIRLOCK_TEST_DSN"] = dsn
    from airlock.pause import apply_decision

    store = _CrashAfterApproveCAS(dsn)
    apply_decision(
        store,
        approval_ref,
        ApprovalDecision(decision=HumanDecision.APPROVED, decided_by="usr_crash"),
    )
    os._exit(0)  # pragma: no cover — unreachable when the crash fires
