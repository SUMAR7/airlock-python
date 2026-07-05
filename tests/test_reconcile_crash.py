"""Crash-injection: kill the real ``commit_once`` flow at every named boundary.

SPEC scenarios 3 & 4 under true SIGKILL-equivalent crashes. A spawn subprocess
drives the REAL :func:`airlock.commit.commit_once` (via the consolidated
:mod:`tests._harness`) and dies via ``os._exit`` at a named crashpoint —
deterministic like a mock, real like SIGKILL: ``os._exit`` skips
``finally``/``atexit`` and the DB connection dies mid-transaction, so the last
DURABLE state is whatever committed before the crash. The parent then advances
a fake clock past the reconcile timeout, runs one reconcile pass, and asserts
the row recovers with ``effect_count`` never exceeding 1 (I1) — the prime
directive under crashes.

Before P1.4 this file staged the flow by hand and covered three boundaries;
now every boundary in :data:`tests._harness.CRASHPOINTS` is exercised through
the real primitive, and the harness is shared with P2.3.

Determinism substrate (PLAN.md 7): the crash is ``os._exit`` in a spawn
subprocess (never a timer); "past the reconcile timeout" is produced by
advancing the store's injectable ``now_fn`` (never ``time.sleep``). Side-effect
ground truth is the ``effects_log`` autocommit table, asserted from a fresh
connection.
"""

from __future__ import annotations

import multiprocessing
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest

from airlock.effects import Effect
from airlock.reconcile import OnAbsent, Outcome, reconcile
from airlock.registry import Registry
from airlock.types import Guarantee, LedgerState, Verification
from tests._harness import (
    CRASH_EXIT_CODE,
    CRASHPOINTS,
    effect_applied_at_crash,
    expected_state_after_crash,
    rebase_last_attempt,
    run_commit_to_crashpoint,
)
from tests.conftest import EffectsLog, FakeClock, read_row

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore

CRASH_ACTION = "crash.refund"
DEADLINE = 60.0
OLDER_THAN = timedelta(seconds=60)


def _spawn_crash(dsn: str, key: str, crashpoint: str, guarantee: Guarantee) -> int:
    """Run the crash worker in a spawn subprocess; return its exit code."""
    ctx = multiprocessing.get_context("spawn")
    proc = ctx.Process(
        target=run_commit_to_crashpoint,
        kwargs={
            "dsn": dsn,
            "key": key,
            "action_type": CRASH_ACTION,
            "crashpoint": crashpoint,
            "guarantee": guarantee,
        },
        daemon=True,
    )
    proc.start()
    proc.join(timeout=DEADLINE)
    assert not proc.is_alive(), f"crash worker for {crashpoint!r} did not exit"
    return proc.exitcode  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# The durable-state contract: each boundary lands the ledger in a known state,
# with a known effect count — driven through the real commit_once.
# ---------------------------------------------------------------------------


@pytest.mark.crash
@pytest.mark.parametrize("crashpoint", CRASHPOINTS)
def test_crash_leaves_expected_durable_state(
    db: Engine,
    database_url: str,
    effects: EffectsLog,
    crashpoint: str,
) -> None:
    """A kill at each boundary leaves the documented durable state + effect count.

    This pins the harness contract the recovery tests build on: pending &
    effect-free before the executing marker; executing with the effect applied
    from after_effect on; committed after the finalize write lands.
    """
    key = f"k-crash-state-{crashpoint}"
    exitcode = _spawn_crash(database_url, key, crashpoint, Guarantee.VERIFIABLE)
    assert exitcode == CRASH_EXIT_CODE, (
        f"expected os._exit({CRASH_EXIT_CODE}) at {crashpoint!r}, got {exitcode} "
        "(a clean 0 means the crashpoint never fired)"
    )

    row = read_row(db, key)
    expected = expected_state_after_crash(crashpoint)
    assert row.state == expected.value, f"{crashpoint!r} should leave state {expected.value!r}"

    expected_effects = 1 if effect_applied_at_crash(crashpoint) else 0
    assert effects.count(key) == expected_effects, (
        f"{crashpoint!r}: effect_count must be {expected_effects}"
    )
    # Only after_finalize_write set committed_at (its finalize committed).
    if expected is LedgerState.COMMITTED:
        assert row.committed_at is not None
    else:
        assert row.committed_at is None


# ---------------------------------------------------------------------------
# SPEC scenario 3 — crash left the row executing with the effect applied; a
# VERIFIABLE probe answering PRESENT recovers 'committed' WITHOUT re-executing.
# ---------------------------------------------------------------------------

# The boundaries that leave state=executing WITH the effect already applied.
_EXECUTING_WITH_EFFECT = [
    cp
    for cp in CRASHPOINTS
    if expected_state_after_crash(cp) is LedgerState.EXECUTING and effect_applied_at_crash(cp)
]


@pytest.mark.crash
@pytest.mark.parametrize("crashpoint", _EXECUTING_WITH_EFFECT)
def test_scenario_3_executing_with_effect_probe_present_recovers_committed(
    db: Engine,
    database_url: str,
    effects: EffectsLog,
    clock_store: PostgresStore,
    fake_clock: FakeClock,
    crashpoint: str,
) -> None:
    """after_effect / after_verify / before_finalize_write: the effect landed and
    the row is executing. Verify PRESENT -> committed, effect_count stays 1
    (never re-executed), recovery evidence recorded."""
    key = f"k-crash-s3-{crashpoint}"
    assert _spawn_crash(database_url, key, crashpoint, Guarantee.VERIFIABLE) == CRASH_EXIT_CODE

    row = read_row(db, key)
    assert row.state == LedgerState.EXECUTING.value
    assert effects.count(key) == 1
    rebase_last_attempt(db, key, fake_clock())

    probe_calls: list[dict[str, Any]] = []

    def verify(**arg_map: Any) -> tuple[Verification, dict[str, str]]:
        probe_calls.append(arg_map)
        return Verification.PRESENT, {"refund_id": f"re_{key}"}

    reg = Registry()
    reg.register(
        CRASH_ACTION,
        Effect(verify=verify),
        lambda dk, **_: pytest.fail("recovery of a present-verifiable row must not re-execute"),
    )

    fake_clock.advance(300)
    report = reconcile(clock_store, older_than=OLDER_THAN, now_fn=fake_clock, registry=reg)

    assert report.count(Outcome.COMMITTED) == 1
    assert probe_calls == [{"invoice": key}]  # probe got the rehydrated arg_map
    assert effects.count(key) == 1  # STILL exactly one effect (I1)

    recovered = read_row(db, key)
    assert recovered.state == LedgerState.COMMITTED.value
    assert recovered.result_json == {"refund_id": f"re_{key}"}
    assert recovered.committed_at is not None
    assert recovered.attempts == 2  # recovered under the bumped epoch
    assert recovered.error_json["reconciled"] == "committed"


# ---------------------------------------------------------------------------
# SPEC scenario 4 — crash before effect (after_claim / after_executing_mark).
# ---------------------------------------------------------------------------


@pytest.mark.crash
@pytest.mark.parametrize("crashpoint", ["after_claim", "after_executing_mark"])
def test_scenario_4_crash_before_effect_retry_gives_exactly_one_effect(
    db: Engine,
    database_url: str,
    effects: EffectsLog,
    clock_store: PostgresStore,
    fake_clock: FakeClock,
    crashpoint: str,
) -> None:
    """Crash before the effect: after_claim leaves 'pending' (provably
    effect-free), after_executing_mark leaves 'executing' with zero effects.

    - pending -> on_absent=RETRY re-validates preconditions and re-runs execute
      (probe PRESENT) -> exactly one effect, committed.
    - executing-with-no-effect -> the probe answers ABSENT (nothing landed), so
      recovery treats it as effect-free and retries -> exactly one effect.
    """
    key = f"k-crash-s4-{crashpoint}"
    assert _spawn_crash(database_url, key, crashpoint, Guarantee.VERIFIABLE) == CRASH_EXIT_CODE

    row = read_row(db, key)
    assert row.state == expected_state_after_crash(crashpoint).value
    assert effects.count(key) == 0  # provably effect-free
    rebase_last_attempt(db, key, fake_clock())

    def execute(downstream_key: str | None, **_: Any) -> Any:
        effects.log(key)
        return {"refund_id": "re_retry"}

    # Probe answers ABSENT until the retry logs the effect (mirrors reality: the
    # crash left nothing downstream). For the pending row the probe is not even
    # consulted before retry; for the executing row it proves absence first.
    def verify(**_: Any) -> tuple[Verification, None]:
        return (Verification.PRESENT if effects.count(key) else Verification.ABSENT), None

    reg = Registry()
    reg.register(CRASH_ACTION, Effect(verify=verify), execute)

    fake_clock.advance(300)
    report = reconcile(
        clock_store,
        older_than=OLDER_THAN,
        on_absent=OnAbsent.RETRY,
        now_fn=fake_clock,
        registry=reg,
    )
    assert report.count(Outcome.RETRIED_COMMITTED) == 1
    assert effects.count(key) == 1  # exactly one effect, applied during recovery
    recovered = read_row(db, key)
    assert recovered.state == LedgerState.COMMITTED.value
    assert recovered.attempts > 1


# ---------------------------------------------------------------------------
# after_finalize_write — the finalize COMMITTED before the crash: the reconciler
# never sees it (terminal rows are not stale-in-flight), and a duplicate call
# returns the recorded outcome (scenario 1 across a crash).
# ---------------------------------------------------------------------------


@pytest.mark.crash
def test_crash_after_finalize_write_is_already_terminal(
    db: Engine,
    database_url: str,
    effects: EffectsLog,
    clock_store: PostgresStore,
    fake_clock: FakeClock,
) -> None:
    """after_finalize_write: the finalize durably committed, the process died
    before returning. The ledger is already terminal (committed) with one
    effect; a reconcile pass finds nothing to do (terminal rows are not
    stale-in-flight), so the crash is fully recovered by the durable finalize
    alone."""
    key = "k-crash-after-finalize"
    assert (
        _spawn_crash(database_url, key, "after_finalize_write", Guarantee.VERIFIABLE)
        == CRASH_EXIT_CODE
    )

    row = read_row(db, key)
    assert row.state == LedgerState.COMMITTED.value
    assert row.committed_at is not None
    assert effects.count(key) == 1
    rebase_last_attempt(db, key, fake_clock())

    reg = Registry()
    reg.register(
        CRASH_ACTION,
        Effect(verify=lambda **_: (Verification.PRESENT, None)),
        lambda dk, **_: pytest.fail("a committed row must never be recovered/re-executed"),
    )
    fake_clock.advance(300)
    report = reconcile(clock_store, older_than=OLDER_THAN, now_fn=fake_clock, registry=reg)
    assert report.total == 0  # terminal rows are invisible to the sweep
    assert effects.count(key) == 1
    assert read_row(db, key).state == LedgerState.COMMITTED.value
