"""ASYNC durable pause + crash recovery (ASYNC-DESIGN.md P2/P3) — the two
promises that decide whether async support is honest.

Async that only worked on the AUTO path would mean *"exactly-once, except when a
human approves it, or after a crash"*. So both of these run the recovery from a
**fresh, synchronous process with no event loop** — a webhook receiver, a cron
reconciler — because that is where a real deployment resumes work:

- **P2** gated async action -> durable pause (0 effects) -> SYNC resume in a new
  process -> exactly one effect; a redelivered approval is a safe no-op.
- **P3** async effect dies mid-``await`` -> SYNC reconciler -> exactly one
  real-world effect, including the verify-only path where recovery must consult
  an **async** probe to find out what happened.

Ground truth is the ``effects_log`` autocommit table, so an effect that landed is
visible even though the process that caused it died without finalizing.
"""

from __future__ import annotations

import json
import multiprocessing
import uuid
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from airlock.audit import verify_chain
from airlock.pause import apply_decision
from airlock.reconcile import reconcile
from airlock.registry import registry as default_registry
from airlock.types import ApprovalDecision, HumanDecision, LedgerState, PauseStatus
from tests import _async_harness as harness
from tests._async_harness import (
    AUTO_ACTION,
    CRASH_EXIT_CODE,
    GATE_ACTION,
    VERIFY_ACTION,
    effect_key,
)

if TYPE_CHECKING:
    from pathlib import Path

    from airlock.store.postgres import PostgresStore
    from tests.conftest import EffectsLog

pytestmark = [pytest.mark.crash, pytest.mark.matrix]

DEADLINE = 120.0
ZERO = timedelta(seconds=0)


@pytest.fixture(autouse=True)
def _parent_dsn(store_dsn: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """The PARENT resumes/reconciles in-process, so re-executing the guarded tool
    needs the same ground-truth DSN the subprocess used (the harness reads it from
    the environment, exactly as tests/_pause_harness.py does)."""
    monkeypatch.setenv("AIRLOCK_TEST_DSN", store_dsn)


def _spawn(target: object, **kwargs: object) -> int:
    """Run ``target`` in a spawn subprocess and return its exit code."""
    ctx = multiprocessing.get_context("spawn")
    proc = ctx.Process(target=target, kwargs=kwargs, daemon=True)  # type: ignore[arg-type]
    proc.start()
    proc.join(timeout=DEADLINE)
    assert not proc.is_alive(), "subprocess did not exit"
    return proc.exitcode  # type: ignore[return-value]


# --- P2: durable pause, resumed from a SYNC process -------------------------


def test_async_gated_action_pauses_durably_and_resumes_exactly_once(
    store: PostgresStore, store_dsn: str, effects: EffectsLog, tmp_path: Path
) -> None:
    """P2: the whole promise, end to end, across a process boundary.

    The child runs the REAL async GATE path (``asyncio.run``) so the paused row is
    durably persisted, then exits WITHOUT executing. This parent — plain
    synchronous code, no event loop — applies the human decision and the async
    effect runs exactly once. Then a REDELIVERED approval must change nothing.
    """
    vendor = f"acme_{uuid.uuid4().hex[:8]}"
    out = tmp_path / "ref.json"

    assert _spawn(harness.run_gate_and_exit, dsn=store_dsn, out_path=str(out), vendor=vendor) == 0
    approval_ref = json.loads(out.read_text())["approval_ref"]
    assert approval_ref, "the gated async action did not durably pause"
    assert effects.count(effect_key(GATE_ACTION, vendor)) == 0, (
        "GATE executed the async effect before a human decided — the fail-safe broke"
    )

    # A human approves. Resume from THIS synchronous process (no loop anywhere):
    # exactly what a webhook receiver or a backstop poller does after a restart.
    approved = ApprovalDecision(decision=HumanDecision.APPROVED, decided_by="usr_sync_receiver")
    outcome = apply_decision(store, approval_ref, approved, registry=default_registry)
    assert outcome.status is PauseStatus.COMMITTED
    assert effects.count(effect_key(GATE_ACTION, vendor)) == 1, (
        "the SYNC resume did not run the async effect exactly once"
    )

    # At-least-once delivery: the same approval arrives again. Safe no-op.
    again = apply_decision(store, approval_ref, approved, registry=default_registry)
    assert again.applied is False
    assert effects.count(effect_key(GATE_ACTION, vendor)) == 1, "redelivery re-ran the effect"

    verify_chain(store)


# --- P3: crash mid-await, recovered by a SYNC reconciler --------------------


def test_async_effect_crashed_mid_await_recovers_to_exactly_one_effect(
    store: PostgresStore, store_dsn: str, effects: EffectsLog
) -> None:
    """P3: the async effect landed, then the process died before finalize. A
    SYNCHRONOUS reconciler (no event loop) must resolve it to exactly one effect.

    The downstream key makes the retry safe, so the guarantee here is
    ``DOWNSTREAM_IDEMPOTENT``: what must NOT happen is a second *logical* effect
    escaping the ledger's accounting.
    """
    order = f"ord_{uuid.uuid4().hex[:8]}"
    key = effect_key(AUTO_ACTION, order)

    assert _spawn(harness.run_auto_and_crash, dsn=store_dsn, order=order) == CRASH_EXIT_CODE
    assert effects.count(key) == 1, "the child should have landed the effect once before dying"

    report = reconcile(store, registry=default_registry, older_than=ZERO)
    assert report.actions, "the reconciler found nothing to recover"
    detail = [(a.guarantee.value, a.outcome.value, a.detail) for a in report.actions]

    row = store.load(next(iter(a.key for a in report.actions)))
    assert row is not None and row.state is LedgerState.COMMITTED, (
        f"the crashed async run was left unresolved: {detail}"
    )
    verify_chain(store)


@pytest.mark.parametrize(
    ("crash_before", "expected_effects", "expected_state"),
    [
        pytest.param(False, 1, LedgerState.COMMITTED, id="effect-landed-probe-says-PRESENT"),
        pytest.param(True, 0, LedgerState.ABORTED, id="effect-missing-probe-says-ABSENT"),
    ],
)
def test_async_verify_probe_decides_recovery_from_a_sync_reconciler(
    store: PostgresStore,
    store_dsn: str,
    effects: EffectsLog,
    crash_before: bool,
    expected_effects: int,
    expected_state: LedgerState,
) -> None:
    """G9 at the recovery site: a verify-ONLY async effect has no downstream key,
    so a blind retry is unsafe — recovery MUST ask the ASYNC probe what happened,
    from a synchronous reconciler with no event loop.

    - crashed AFTER the effect  -> probe PRESENT -> committed, NOT re-run.
    - crashed BEFORE the effect -> probe ABSENT  -> aborted (no phantom effect).

    Asserting the TERMINAL LEDGER STATE is what makes this test meaningful. A
    probe that cannot run at all degrades to ``UNKNOWN`` (correct fail-safe: the
    row is left ``executing`` and escalated) — and that leaves the effect COUNT
    identical to a probe that answered. Only the durable state distinguishes
    "the async probe ran and decided" from "the async probe never ran", so a
    count-only assertion would silently pass if the bridge were broken.
    """
    order = f"job_{uuid.uuid4().hex[:8]}"
    key = effect_key(VERIFY_ACTION, order)

    code = _spawn(harness.run_verified_and_crash, dsn=store_dsn, order=order, before=crash_before)
    assert code == CRASH_EXIT_CODE

    report = reconcile(store, registry=default_registry, older_than=ZERO)
    assert report.actions, "the reconciler found no crashed run to recover"
    detail = [(a.guarantee.value, a.outcome.value, a.detail) for a in report.actions]

    row = store.load(report.actions[0].key)
    actual = None if row is None else row.state
    assert actual is expected_state, (
        f"the ASYNC verify probe did not decide recovery (state={actual}, "
        f"expected {expected_state}); reconciler said: {detail}"
    )
    assert effects.count(key) == expected_effects, (
        f"async verify-first recovery produced {effects.count(key)} effects, "
        f"expected {expected_effects}"
    )
    verify_chain(store)
