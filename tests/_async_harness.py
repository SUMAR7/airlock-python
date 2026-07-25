"""Subprocess harness for the ASYNC durable-pause + crash tests (ASYNC-DESIGN.md
P2/P3). Mirrors ``tests/_pause_harness.py``, but the guarded tools are
``async def``.

These are the two promises that decide whether async support is honest at all,
and both must hold from a process with **no event loop**:

- **P2 durable pause** — an async gated action pauses durably, and a *fresh*,
  *synchronous* process (a webhook receiver / poller, after a deploy or restart)
  resumes it and the effect runs exactly once.
- **P3 crash recovery** — an async effect dies mid-``await`` and a *synchronous*
  cron reconciler (``python -m airlock reconcile``, no loop anywhere) drives it
  to exactly one real-world effect.

The tools are defined at MODULE level so importing this module registers them in
both the subprocess and the parent — a fresh process can then rebuild the call
from the bare persisted row (``@guard`` decoration is the only registration side
effect). The effect is logged to ``effects_log`` on a separate autocommit
connection (ground truth), keyed by the DSN in ``AIRLOCK_TEST_DSN``.

Deliberately: the child ``asyncio.run(...)``s the tool (real async caller), while
the parent's resume/reconcile is plain sync code. That asymmetry IS the test.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from airlock import guard, init
from airlock.effects import Effect
from airlock.errors import ActionPending
from airlock.policy import Policy, Rule
from airlock.store import from_url
from airlock.types import Decision, Money, Reversibility, Verification
from tests._harness import EffectLogger

GATE_ACTION = "async.harness.payout"
AUTO_ACTION = "async.harness.charge"
VERIFY_ACTION = "async.harness.verified"
CRASH_EXIT_CODE = 137


def effect_key(action: str, ref: str) -> str:
    """The stable effects_log key the parent counts against."""
    return f"{action}:{ref}"


def _dsn() -> str:
    return os.environ["AIRLOCK_TEST_DSN"]


def _log(action: str, ref: str) -> None:
    EffectLogger(_dsn()).log(effect_key(action, ref))


# --- the guarded ASYNC tools (module level => registered on import) ---------


@guard(
    GATE_ACTION,
    cost=Money(amount="5000.00", currency="USD"),
    reversibility=Reversibility.IRREVERSIBLE,
    effect=Effect(key_param="idempotency_key"),
)
async def harness_payout(vendor: str, *, idempotency_key: str | None = None) -> dict[str, Any]:
    """A GATE'd async effect: must not run until a human approves."""
    await asyncio.sleep(0)
    _log(GATE_ACTION, vendor)
    return {"paid": vendor, "dk": idempotency_key}


@guard(AUTO_ACTION, effect=Effect(key_param="idempotency_key"))
async def harness_charge(order: str, *, idempotency_key: str | None = None) -> dict[str, Any]:
    """An AUTO async effect used for the crash/recovery case. Crashes mid-flight
    when AIRLOCK_CRASH_AFTER_EFFECT is set — AFTER the effect landed but BEFORE
    finalize, the window that would otherwise double-charge."""
    await asyncio.sleep(0)
    _log(AUTO_ACTION, order)
    if os.environ.get("AIRLOCK_CRASH_AFTER_EFFECT") == "1":
        os._exit(CRASH_EXIT_CODE)
    return {"charged": order, "dk": idempotency_key}


async def _async_probe(order: str, **_: object) -> tuple[Verification, Any]:
    """An ASYNC post-verify probe: did the effect land? Ground truth is the
    effects_log row, so the answer is real, not simulated."""
    await asyncio.sleep(0)
    present = EffectLogger(_dsn()).count(effect_key(VERIFY_ACTION, order)) > 0
    return (Verification.PRESENT if present else Verification.ABSENT), {"order": order}


@guard(VERIFY_ACTION, effect=Effect(verify=_async_probe))  # verify-ONLY: no key_param
async def harness_verified(order: str) -> dict[str, Any]:
    """A verify-only async effect: recovery MUST consult the async probe (there is
    no downstream key to make a blind retry safe)."""
    await asyncio.sleep(0)
    if os.environ.get("AIRLOCK_CRASH_BEFORE_EFFECT") == "1":
        os._exit(CRASH_EXIT_CODE)
    _log(VERIFY_ACTION, order)
    if os.environ.get("AIRLOCK_CRASH_AFTER_EFFECT") == "1":
        os._exit(CRASH_EXIT_CODE)
    return {"done": order}


def _init(dsn: str, *, gate: bool = False, reconcile_after_zero: bool = False) -> Any:
    from datetime import timedelta

    decision = Decision.GATE if gate else Decision.AUTO
    return init(
        store=from_url(dsn),
        policy=Policy(rules=[Rule(match="async.harness.*", decision=decision)]),
        gate_wait=False,  # pause durably and hand back the ref; never block
        reconcile_after=timedelta(seconds=0) if reconcile_after_zero else None,
    )


# --- subprocess entry points ------------------------------------------------


def run_gate_and_exit(dsn: str, out_path: str, vendor: str) -> None:
    """P2 child: drive the REAL async GATE path so the paused row is durably
    persisted, write the approval_ref out, and exit cleanly. The effect must NOT
    have run. The parent then resumes from a fresh, synchronous process."""
    os.environ["AIRLOCK_TEST_DSN"] = dsn
    _init(dsn, gate=True)
    ref = None
    try:
        asyncio.run(harness_payout(vendor))
    except ActionPending as pending:
        ref = pending.approval_ref
    Path(out_path).write_text(json.dumps({"approval_ref": ref}))


def run_auto_and_crash(dsn: str, order: str) -> None:
    """P3 child: an AUTO async effect that lands and then dies before finalize."""
    os.environ["AIRLOCK_TEST_DSN"] = dsn
    os.environ["AIRLOCK_CRASH_AFTER_EFFECT"] = "1"
    _init(dsn, reconcile_after_zero=True)
    asyncio.run(harness_charge(order))


def run_verified_and_crash(dsn: str, order: str, *, before: bool) -> None:
    """P3 child for the verify-only path: crash BEFORE or AFTER the effect, so
    the parent's sync reconciler must ask the ASYNC probe what really happened."""
    os.environ["AIRLOCK_TEST_DSN"] = dsn
    os.environ["AIRLOCK_CRASH_BEFORE_EFFECT" if before else "AIRLOCK_CRASH_AFTER_EFFECT"] = "1"
    _init(dsn, reconcile_after_zero=True)
    asyncio.run(harness_verified(order))
