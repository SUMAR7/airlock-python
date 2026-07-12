"""The hosted-gate demo: a human in the loop, with rich context and coded reasons.

Run it::

    python demo.py

Some actions are too risky to auto-commit. Airlock **gates** them: the run is
durably paused, a human is shown *what* they are approving, and the side effect
runs only if — and exactly once after — they approve. This demo tells that story
two ways against the file-backed ``ConsoleApprovalTransport`` (no server, no
network), showing the two features layered on top of a plain gate:

- **Reviewer context** (``@guard(summary=…, context=…)``) — the reviewer sees an
  integrator-authored one-liner and a curated key/value panel. The raw tool args
  (here a card number) never auto-transit: you choose exactly what is exposed.
- **Reject reason codes** (``@guard(reject_reasons=…)``) — the action offers a
  set of structured codes; a reviewer who rejects picks one, and it comes back on
  ``ApprovalRejected.reason_code`` so the agent can *branch* on it.

**ACT 1 — APPROVED.** The agent proposes a payout, a reviewer approves it, and
the payout commits **exactly once** — even when the decision is delivered twice.

**ACT 2 — REJECTED.** The agent proposes another payout, a reviewer rejects it
with a code, and the agent reacts to the code as control flow. No money moves.

Determinism: the transport is driven with ``gate_timeout=0.0`` so every wait
scans the approvals file exactly once and never sleeps — the whole demo is a
straight line with no clocks and no network.
"""

from __future__ import annotations

from pathlib import Path
from typing import NamedTuple

import airlock
from airlock import Decision, Effect, Money, Policy, Reversibility, Rule
from airlock.store.sqlite import SqliteStore
from airlock.transport.console import ConsoleApprovalTransport

#: SQLite dev-store + approvals-file artifacts this demo creates in the cwd.
_DB_FILES = ("airlock.db", "airlock.db-wal", "airlock.db-shm")
_APPROVALS_FILE = "hosted-gated-approvals.jsonl"

#: An in-memory "bank" so we can COUNT the real side effects (a payout is money
#: moving; the whole point is that it happens at most, and exactly, once).
paid_out: list[str] = []


@airlock.guard(
    "payout.send",
    cost=Money(amount="4200.00", currency="USD"),
    reversibility=Reversibility.IRREVERSIBLE,
    # A downstream idempotency key => real exactly-once (not at-most-once): the
    # ledger AND the provider both dedupe, so a re-delivered approval is safe.
    effect=Effect(key_param="idempotency_key"),
    # What the reviewer READS — an integrator-authored one-liner of the args:
    summary=lambda vendor, amount_cents, **_: (
        f"Pay {vendor} ${amount_cents / 100:,.2f}"
    ),
    # ...and a curated context panel. NOTE what is NOT here: the card number the
    # tool receives never auto-transits — the reviewer sees only what we expose.
    context=lambda vendor, amount_cents, **_: {
        "vendor": vendor,
        "amount": f"${amount_cents / 100:,.2f}",
        "category": "vendor payout",
    },
    # The structured codes THIS action offers a reviewer who rejects:
    reject_reasons={
        "unverified_vendor": "Vendor bank details not verified",
        "over_budget": "Over this month's payout budget",
        "needs_more_info": "Needs more information",
    },
)
def send_payout(
    vendor: str, amount_cents: int, *, card_number: str, idempotency_key: str | None = None
) -> dict[str, str | int]:
    """Send a vendor payout (the guarded, money-moving tool).

    ``card_number`` is a sensitive arg the tool needs but the reviewer must NOT
    see — and by construction never does: ``@guard`` only transits ``summary`` /
    ``context``, never the raw args.
    """
    paid_out.append(vendor)  # the real side effect
    return {"vendor": vendor, "amount_cents": amount_cents}


def _fresh_runtime() -> tuple[airlock.Airlock, ConsoleApprovalTransport]:
    """Wire a zero-config runtime that gates everything, scanning once (no sleep)."""
    transport = ConsoleApprovalTransport(_APPROVALS_FILE)
    handle = airlock.init(
        policy=Policy(rules=[Rule(match="payout.*", decision=Decision.GATE)]),
        transport=transport,
        gate_wait=True,
        gate_timeout=0.0,  # scan the approvals file once; never block
    )
    return handle, transport


class ApproveResult(NamedTuple):
    """What ACT 1 produced — enough for the test to assert exactly-once."""

    result: dict[str, str | int]
    payouts: int
    reviewer_saw: str
    handle: airlock.Airlock


def act1_approved() -> ApproveResult:
    """ACT 1: propose → a reviewer approves → commit exactly once (even twice-delivered)."""
    import io

    paid_out.clear()

    # A capturing transport so we can SHOW what the reviewer was delivered.
    seen = io.StringIO()
    transport = ConsoleApprovalTransport(_APPROVALS_FILE, out=seen)
    handle = airlock.init(
        policy=Policy(rules=[Rule(match="payout.*", decision=Decision.GATE)]),
        transport=transport,
        gate_wait=True,
        gate_timeout=0.0,  # scan the approvals file once; never block
    )

    # 1) The agent proposes the payout; with no decision yet it durably pauses.
    ref = None
    try:
        send_payout("acme-cloud", 420_000, card_number="4111-1111-1111-1111")
    except airlock.ActionPending as pending:
        ref = pending.approval_ref
    assert ref is not None

    # 2) A reviewer approves it (scripted by appending a decision line).
    transport.record_decision(ref, "approved", decided_by="usr_reviewer")

    # 3) The agent retries the SAME action: it re-attaches, sees the approval, and
    #    the payout commits and returns its result.
    result = send_payout("acme-cloud", 420_000, card_number="4111-1111-1111-1111")

    # 4) The decision is delivered AGAIN (a duplicate webhook / a second retry):
    #    the ledger short-circuits it — the recorded result comes back, the
    #    payout does NOT run a second time.
    again = send_payout("acme-cloud", 420_000, card_number="4111-1111-1111-1111")
    assert again == result

    return ApproveResult(
        result=result, payouts=len(paid_out), reviewer_saw=seen.getvalue(), handle=handle
    )


class RejectResult(NamedTuple):
    """What ACT 2 produced — enough for the test to assert the coded rejection."""

    reason_code: str | None
    reason: str | None
    handled: str
    payouts: int
    handle: airlock.Airlock


def act2_rejected() -> RejectResult:
    """ACT 2: propose → a reviewer rejects with a code → the agent branches on it."""
    paid_out.clear()
    handle, transport = _fresh_runtime()

    # 1) Propose a DIFFERENT payout (distinct args => distinct ledger key).
    ref = None
    try:
        send_payout("shady-llc", 990_000, card_number="4222-2222-2222-2222")
    except airlock.ActionPending as pending:
        ref = pending.approval_ref
    assert ref is not None

    # 2) A reviewer REJECTS, choosing one of the offered codes + a free-text note.
    transport.record_decision(
        ref, "rejected", reason_code="unverified_vendor", reason="bank details not on file"
    )

    # 3) The agent retries: the rejection comes back as CONTROL FLOW. Branch on it.
    handled = "unknown"
    reason_code: str | None = None
    reason: str | None = None
    try:
        send_payout("shady-llc", 990_000, card_number="4222-2222-2222-2222")
    except airlock.ApprovalRejected as rej:
        reason_code, reason = rej.reason_code, rej.reason
        if rej.reason_code == "needs_more_info":
            handled = "resubmit with more detail"
        elif rej.reason_code == "unverified_vendor":
            handled = "route to vendor onboarding"
        elif rej.reason_code == "over_budget":
            handled = "defer to next cycle"

    return RejectResult(
        reason_code=reason_code,
        reason=reason,
        handled=handled,
        payouts=len(paid_out),
        handle=handle,
    )


def cleanup(handle: airlock.Airlock | None = None) -> None:
    """Close the dev store and delete the artifacts so re-runs start clean."""
    if handle is not None and isinstance(handle.store, SqliteStore):
        handle.store.close()
    for name in (*_DB_FILES, _APPROVALS_FILE):
        path = Path(name)
        if path.exists():
            path.unlink()


def main() -> None:
    print("=" * 70)
    print("Airlock — the hosted-gate demo (reviewer context + reject reason codes)")
    print("=" * 70)

    print("\nACT 1 — APPROVED")
    print("-" * 70)
    approve = act1_approved()
    print("The agent proposes a payout. Here is exactly what the reviewer saw:\n")
    print(approve.reviewer_saw.rstrip())
    print("\n  (note: the card number 4111-... is NOWHERE above — raw args never transit)")
    print("  A reviewer approves; the agent retries and the payout commits.")
    print(f"  payouts actually sent: {approve.payouts}  ->  {approve.result}")
    print("  ✅ Committed exactly once — even though the approval was delivered twice.")
    cleanup(approve.handle)

    print("\nACT 2 — REJECTED")
    print("-" * 70)
    reject = act2_rejected()
    print("The agent proposes another payout; the reviewer REJECTS with a code.")
    print(f"  reason_code = {reject.reason_code!r}   reason = {reject.reason!r}")
    print(f"  the agent branched on the code -> {reject.handled!r}")
    print(f"  payouts actually sent: {reject.payouts}")
    print("  ✅ A rejection is control flow, not a dead end — and no money moved.")
    cleanup(reject.handle)

    print("\nSee README.md for the walkthrough and the API references.")


if __name__ == "__main__":
    main()
