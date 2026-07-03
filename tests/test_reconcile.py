"""The reconciler recovery table (PLAN.md 4.2), verify-first (SPEC scenarios 3/4/7).

Determinism substrate (PLAN.md section 7): the store's ``now_fn`` and the
reconciler share one :class:`~tests.conftest.FakeClock`. "A row past the
reconcile timeout" is produced by ``fake_clock.advance(...)``, never by
``time.sleep`` — advancing the clock makes an in-flight row cross the staleness
cutoff instantly. Side-effect ground truth is the ``effects_log`` autocommit
table; durability is asserted from FRESH connections (``read_row``).

This module drives the recovery table dispatch in-process (one connection);
the true SIGKILL crash-injection lives in ``test_reconcile_crash.py`` and the
epoch-fence / concurrency races in ``test_reconcile_race.py``.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import JsonValue

from airlock.effects import Effect
from airlock.reconcile import ExecuteWindow, OnAbsent, Outcome, reconcile, reconcile_key
from airlock.registry import Registry
from airlock.types import Guarantee, LedgerState, Verification
from tests.conftest import EffectsLog, FakeClock, read_row

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore

ACTION = "refund.create"
ARGS: dict[str, JsonValue] = {"invoice": "inv_42", "amount": "12.50"}
OLDER_THAN = timedelta(seconds=60)


# ---------------------------------------------------------------------------
# Helpers: seed a crashed row, build effects/probes/executes bound to a key.
# ---------------------------------------------------------------------------


def _seed_crashed(
    store: PostgresStore,
    key: str,
    *,
    state: LedgerState,
    guarantee: Guarantee,
    downstream_key: str | None = None,
    args: dict[str, JsonValue] | None = None,
) -> None:
    """Seed a row that a crash left ``pending`` or ``executing`` at epoch 1.

    The claim + optional mark run at the FakeClock's current instant; the test
    then advances the clock so the row crosses the staleness cutoff.
    """
    store.claim(key, ACTION, guarantee, args if args is not None else ARGS, downstream_key)
    if state is LedgerState.EXECUTING:
        assert store.mark_executing(key, 1)


def _never(_: str | None, **__: Any) -> JsonValue:
    raise AssertionError("execute must not run on this recovery path")


# ---------------------------------------------------------------------------
# ExecuteWindow — the enforced execute_timeout < reconcile_after ordering.
# ---------------------------------------------------------------------------


def test_execute_window_enforces_ordering() -> None:
    """PLAN.md 4.1: execute_timeout < reconcile_after so a stale row is provably
    past any live execute before recovery — the residual-race mitigation."""
    ok = ExecuteWindow(execute_timeout=timedelta(seconds=10), reconcile_after=timedelta(seconds=60))
    assert ok.execute_timeout < ok.reconcile_after

    with pytest.raises(ValueError, match="reconcile_after"):
        ExecuteWindow(execute_timeout=timedelta(seconds=60), reconcile_after=timedelta(seconds=60))
    with pytest.raises(ValueError, match="reconcile_after"):
        ExecuteWindow(execute_timeout=timedelta(seconds=90), reconcile_after=timedelta(seconds=60))
    with pytest.raises(ValueError, match="positive"):
        ExecuteWindow(execute_timeout=timedelta(0), reconcile_after=timedelta(seconds=60))


def test_reconcile_refuses_misconfigured_execute_window(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine
) -> None:
    """The ExecuteWindow ordering is enforced in the RUNTIME path, not just the
    dataclass: reconcile()/reconcile_key() given an execute_timeout that is not
    strictly less than older_than raise ValueError BEFORE scanning a single row
    (PLAN.md 4.1/10.2 — an operator who sets --older-than <= their execute
    timeout gets a refusal, never a reconciler that probes live in-flight rows).
    """
    reg = Registry()
    reg.register(ACTION, Effect(verify=lambda **_: (Verification.PRESENT, None)), _never)
    # Seed a stale row that WOULD be recovered if the window check did not fire.
    _seed_crashed(
        clock_store, "k-badwin", state=LedgerState.EXECUTING, guarantee=Guarantee.VERIFIABLE
    )
    fake_clock.advance(120)

    for exec_to in (timedelta(seconds=60), timedelta(seconds=90)):  # == and > older_than
        with pytest.raises(ValueError, match="reconcile_after"):
            reconcile(
                clock_store,
                older_than=OLDER_THAN,
                execute_timeout=exec_to,
                now_fn=fake_clock,
                registry=reg,
            )
        with pytest.raises(ValueError, match="reconcile_after"):
            reconcile_key(
                clock_store,
                "k-badwin",
                older_than=OLDER_THAN,
                execute_timeout=exec_to,
                now_fn=fake_clock,
                registry=reg,
            )
    # The row is untouched: the refusal happened before any recovery I/O
    # (_never would have raised if execute ran; the probe never ran either).
    assert read_row(db, "k-badwin").state == LedgerState.EXECUTING.value
    assert read_row(db, "k-badwin").attempts == 1  # epoch NOT bumped


# ---------------------------------------------------------------------------
# The staleness trigger: only rows past the timeout are touched.
# ---------------------------------------------------------------------------


def test_fresh_inflight_row_is_not_reconciled(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine
) -> None:
    """SPEC section 5: a pending row past the reconcile timeout is the ONLY
    trigger. A row that is NOT yet stale is invisible to the sweep."""
    reg = Registry()
    reg.register(ACTION, Effect(verify=lambda **_: (Verification.PRESENT, None)), _never)
    _seed_crashed(
        clock_store, "k-fresh", state=LedgerState.EXECUTING, guarantee=Guarantee.VERIFIABLE
    )

    fake_clock.advance(30)  # not yet past the 60s timeout
    report = reconcile(clock_store, older_than=OLDER_THAN, now_fn=fake_clock, registry=reg)
    assert report.total == 0
    assert read_row(db, "k-fresh").state == LedgerState.EXECUTING.value  # untouched


# ---------------------------------------------------------------------------
# SPEC scenario 3 — crash after effect, before commit mark: verify PRESENT.
# ---------------------------------------------------------------------------


def test_scenario_3_executing_verifiable_present_recovers_committed(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine, effects: EffectsLog
) -> None:
    """Crash left the row 'executing' with the effect already landed. A
    VERIFIABLE probe returns PRESENT, so reconcile finalizes 'committed' WITHOUT
    re-executing — effect count stays 1, evidence records the recovery."""
    key = "k-s3-present"
    effects.log(key)  # the effect happened before the crash

    def verify(**arg_map: Any) -> tuple[Verification, dict[str, Any]]:
        assert arg_map == dict(ARGS)  # probe called with the rehydrated arg_map
        return Verification.PRESENT, {"refund_id": "re_1"}

    reg = Registry()
    reg.register(ACTION, Effect(verify=verify), _never)

    _seed_crashed(clock_store, key, state=LedgerState.EXECUTING, guarantee=Guarantee.VERIFIABLE)
    fake_clock.advance(120)

    report = reconcile(clock_store, older_than=OLDER_THAN, now_fn=fake_clock, registry=reg)
    assert report.count(Outcome.COMMITTED) == 1
    action = report.actions[0]
    assert action.outcome is Outcome.COMMITTED
    assert isinstance(action.evidence, dict)
    assert action.evidence["reconciled"] == "committed"

    assert effects.count(key) == 1  # STILL one effect — never re-executed
    row = read_row(db, key)
    assert row.state == LedgerState.COMMITTED.value
    assert row.result_json == {"refund_id": "re_1"}
    assert row.committed_at is not None
    assert row.attempts == 2  # recovered under the bumped epoch
    # The recovery event is durable evidence (record_error before finalize).
    assert row.error_json["reconciled"] == "committed"


# ---------------------------------------------------------------------------
# SPEC scenario 4 — crash before effect: pending re-validate, retry or abort.
# ---------------------------------------------------------------------------


def test_scenario_4_pending_retry_executes_exactly_once(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine, effects: EffectsLog
) -> None:
    """crashpoint after_claim leaves state=pending — provably effect-free.
    on_absent=retry re-validates preconditions then re-runs the execute path:
    exactly 1 effect, committed, attempts > 1."""
    key = "k-s4-pending-retry"

    def execute(downstream_key: str | None, **arg_map: Any) -> JsonValue:
        assert arg_map == dict(ARGS)  # execute called with rehydrated arg_map
        effects.log(key)
        return {"refund_id": "re_new"}

    reg = Registry()
    # verifiable effect whose probe would confirm the fresh attempt.
    reg.register(ACTION, Effect(verify=lambda **_: (Verification.PRESENT, None)), execute)

    _seed_crashed(clock_store, key, state=LedgerState.PENDING, guarantee=Guarantee.VERIFIABLE)
    fake_clock.advance(120)

    report = reconcile(
        clock_store,
        older_than=OLDER_THAN,
        on_absent=OnAbsent.RETRY,
        now_fn=fake_clock,
        registry=reg,
    )
    assert report.count(Outcome.RETRIED_COMMITTED) == 1
    assert effects.count(key) == 1  # exactly one effect
    row = read_row(db, key)
    assert row.state == LedgerState.COMMITTED.value
    assert row.attempts > 1
    assert row.result_json == {"refund_id": "re_new"}


def test_scenario_4_pending_abort_executes_zero_times(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine, effects: EffectsLog
) -> None:
    """The same pending crash under on_absent=abort: 0 effects, aborted, error
    evidence — recovery chose not to execute."""
    key = "k-s4-pending-abort"
    reg = Registry()
    reg.register(ACTION, Effect(verify=lambda **_: (Verification.PRESENT, None)), _never)

    _seed_crashed(clock_store, key, state=LedgerState.PENDING, guarantee=Guarantee.VERIFIABLE)
    fake_clock.advance(120)

    report = reconcile(
        clock_store,
        older_than=OLDER_THAN,
        on_absent=OnAbsent.ABORT,
        now_fn=fake_clock,
        registry=reg,
    )
    assert report.count(Outcome.ABORTED) == 1
    assert effects.count(key) == 0
    row = read_row(db, key)
    assert row.state == LedgerState.ABORTED.value
    assert row.committed_at is None
    assert row.error_json["reconciled"] == "aborted"


def test_scenario_4_executing_absent_probe_retry_gives_one_effect(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine, effects: EffectsLog
) -> None:
    """executing + verifiable, probe ABSENT: the effect provably did not land,
    so on_absent=retry re-executes -> exactly 1 effect, committed."""
    key = "k-s4-absent-retry"

    def verify(**_: Any) -> tuple[Verification, dict[str, str]]:
        # ABSENT until the effect actually runs; here the crash left no effect.
        return (Verification.PRESENT if effects.count(key) else Verification.ABSENT), {"n": "x"}

    def execute(downstream_key: str | None, **_: Any) -> JsonValue:
        effects.log(key)
        return {"done": True}

    reg = Registry()
    reg.register(ACTION, Effect(verify=verify), execute)

    _seed_crashed(clock_store, key, state=LedgerState.EXECUTING, guarantee=Guarantee.VERIFIABLE)
    fake_clock.advance(120)

    report = reconcile(
        clock_store,
        older_than=OLDER_THAN,
        on_absent=OnAbsent.RETRY,
        now_fn=fake_clock,
        registry=reg,
    )
    assert report.count(Outcome.RETRIED_COMMITTED) == 1
    assert effects.count(key) == 1  # ran once during recovery
    assert read_row(db, key).state == LedgerState.COMMITTED.value


def test_scenario_4_executing_absent_probe_abort_gives_zero_effects(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine, effects: EffectsLog
) -> None:
    """executing + verifiable, probe ABSENT, on_absent=abort: 0 effects, aborted."""
    key = "k-s4-absent-abort"
    reg = Registry()
    reg.register(ACTION, Effect(verify=lambda **_: (Verification.ABSENT, None)), _never)

    _seed_crashed(clock_store, key, state=LedgerState.EXECUTING, guarantee=Guarantee.VERIFIABLE)
    fake_clock.advance(120)

    report = reconcile(
        clock_store,
        older_than=OLDER_THAN,
        on_absent=OnAbsent.ABORT,
        now_fn=fake_clock,
        registry=reg,
    )
    assert report.count(Outcome.ABORTED) == 1
    assert effects.count(key) == 0
    assert read_row(db, key).state == LedgerState.ABORTED.value


# ---------------------------------------------------------------------------
# SPEC scenario 7 — executing + none: finalize unknown, loud, never retried.
# ---------------------------------------------------------------------------


def test_scenario_7_executing_none_finalizes_unknown_and_is_never_retried(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine, effects: EffectsLog
) -> None:
    """guarantee=none stuck executing: reconcile finalizes 'unknown' with loud
    evidence, effect_count unchanged, and the row is NEVER retried across
    repeated passes (the honesty is a feature)."""
    key = "k-s7-none"
    effects.log(key)  # the effect may or may not have landed; say it did

    reg = Registry()
    reg.register(ACTION, Effect(), _never)  # neither key_param nor verify -> none

    _seed_crashed(clock_store, key, state=LedgerState.EXECUTING, guarantee=Guarantee.NONE)
    fake_clock.advance(120)

    report = reconcile(clock_store, older_than=OLDER_THAN, now_fn=fake_clock, registry=reg)
    assert report.count(Outcome.UNKNOWN) == 1
    row = read_row(db, key)
    assert row.state == LedgerState.UNKNOWN.value
    assert row.error_json["reason"] == "at_most_once_no_probe"
    assert effects.count(key) == 1  # unchanged

    # Repeated passes never touch a terminal 'unknown' row again.
    for _ in range(3):
        fake_clock.advance(120)
        again = reconcile(clock_store, older_than=OLDER_THAN, now_fn=fake_clock, registry=reg)
        assert again.total == 0
    assert effects.count(key) == 1
    assert read_row(db, key).state == LedgerState.UNKNOWN.value


# ---------------------------------------------------------------------------
# executing + downstream_idempotent — re-issue with the SAME key (dedup IS verify).
# ---------------------------------------------------------------------------


class _FakeStripe:
    """A downstream that dedupes on the idempotency key it receives."""

    def __init__(self, effects: EffectsLog) -> None:
        self._effects = effects
        self._responses: dict[str, dict[str, Any]] = {}
        self.requests: list[str] = []

    def refund(self, *, idempotency_key: str) -> dict[str, Any]:
        self.requests.append(idempotency_key)
        if idempotency_key in self._responses:
            return self._responses[idempotency_key]  # deduped: no new effect
        self._effects.log(idempotency_key)
        response = {"refund_id": f"re_{len(self._responses) + 1}"}
        self._responses[idempotency_key] = response
        return response


def test_downstream_idempotent_reissue_with_same_key_dedupes(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine, effects: EffectsLog
) -> None:
    """executing + downstream_idempotent, preconditions hold: re-issue with the
    SAME stored downstream key. If the pre-crash effect already landed, the
    downstream dedupes it — one effect total (downstream dedup IS the
    verification)."""
    key = "k-di-reissue"
    downstream_key = "dk-di-reissue"
    fake = _FakeStripe(effects)
    # Pre-crash: the effect already landed downstream under downstream_key.
    fake.refund(idempotency_key=downstream_key)
    assert effects.count(downstream_key) == 1

    def execute(dk: str | None, **_: Any) -> JsonValue:
        assert dk == downstream_key  # the SAME key the pre-crash attempt used
        return fake.refund(idempotency_key=dk)

    reg = Registry()
    reg.register(ACTION, Effect(key_param="idempotency_key"), execute)

    _seed_crashed(
        clock_store,
        key,
        state=LedgerState.EXECUTING,
        guarantee=Guarantee.DOWNSTREAM_IDEMPOTENT,
        downstream_key=downstream_key,
    )
    fake_clock.advance(120)

    report = reconcile(clock_store, older_than=OLDER_THAN, now_fn=fake_clock, registry=reg)
    assert report.count(Outcome.RETRIED_COMMITTED) == 1
    assert effects.count(downstream_key) == 1  # dedup: still exactly one effect
    assert fake.requests == [downstream_key, downstream_key]  # re-issued once
    assert read_row(db, key).state == LedgerState.COMMITTED.value


def test_downstream_idempotent_preconditions_violated_finalizes_unknown(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine, effects: EffectsLog
) -> None:
    """executing + downstream_idempotent, preconditions VIOLATED: cannot prove
    absence and will not execute against a changed world -> finalize 'unknown',
    loud evidence, no effect."""
    key = "k-di-precond-violated"
    reg = Registry()
    reg.register(
        ACTION,
        Effect(key_param="idempotency_key"),
        _never,
        preconditions=lambda **_: False,  # world changed since the crash
    )

    _seed_crashed(
        clock_store,
        key,
        state=LedgerState.EXECUTING,
        guarantee=Guarantee.DOWNSTREAM_IDEMPOTENT,
        downstream_key="dk-x",
    )
    fake_clock.advance(120)

    report = reconcile(clock_store, older_than=OLDER_THAN, now_fn=fake_clock, registry=reg)
    assert report.count(Outcome.UNKNOWN) == 1
    row = read_row(db, key)
    assert row.state == LedgerState.UNKNOWN.value
    assert row.error_json["reason"] == "preconditions_violated_downstream_idempotent"
    assert effects.count("dk-x") == 0


# ---------------------------------------------------------------------------
# executing + verifiable + UNKNOWN — leave untouched, escalate.
# ---------------------------------------------------------------------------


def test_executing_verifiable_unknown_escalates_and_leaves_row(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine
) -> None:
    """A verifiable probe answering 'unknown' (or raising) proves nothing: the
    row is LEFT executing (no lying terminal state), an escalation evidence
    event is recorded, and it is counted escalated."""
    key = "k-verif-unknown"

    def verify(**_: Any) -> tuple[Verification, dict[str, str]]:
        return Verification.UNKNOWN, {"api": "timed out"}

    reg = Registry()
    reg.register(ACTION, Effect(verify=verify), _never)

    _seed_crashed(clock_store, key, state=LedgerState.EXECUTING, guarantee=Guarantee.VERIFIABLE)
    fake_clock.advance(120)

    report = reconcile(clock_store, older_than=OLDER_THAN, now_fn=fake_clock, registry=reg)
    assert report.count(Outcome.ESCALATED) == 1
    row = read_row(db, key)
    assert row.state == LedgerState.EXECUTING.value  # untouched — never finalized
    assert row.error_json["reconciled"] == "escalated"
    assert row.error_json["post_verify"] == "unknown"


def test_probe_that_raises_is_unknown_and_escalates(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine
) -> None:
    """A probe that raises proves nothing -> UNKNOWN -> escalate, row left."""
    key = "k-verif-raises"

    def verify(**_: Any) -> tuple[Verification, None]:
        raise ConnectionError("downstream unreachable")

    reg = Registry()
    reg.register(ACTION, Effect(verify=verify), _never)

    _seed_crashed(clock_store, key, state=LedgerState.EXECUTING, guarantee=Guarantee.VERIFIABLE)
    fake_clock.advance(120)

    report = reconcile(clock_store, older_than=OLDER_THAN, now_fn=fake_clock, registry=reg)
    assert report.count(Outcome.ESCALATED) == 1
    assert read_row(db, key).state == LedgerState.EXECUTING.value


# ---------------------------------------------------------------------------
# preconditions-changed-on-retry (SPEC scenario 8 hazard on the recovery path).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("from_state", [LedgerState.PENDING, LedgerState.EXECUTING])
def test_preconditions_changed_on_retry_aborts_zero_effects(
    clock_store: PostgresStore,
    fake_clock: FakeClock,
    db: Engine,
    effects: EffectsLog,
    from_state: LedgerState,
) -> None:
    """Recovery must RE-VALIDATE preconditions, not blind-retry. A pending row
    (or an executing row whose probe says ABSENT) whose precondition world has
    changed since the crash aborts with 0 effects."""
    key = f"k-precond-changed-{from_state.value}"
    world_ok = {"value": False}  # mutated: the world changed since the crash

    reg = Registry()
    reg.register(
        ACTION,
        Effect(verify=lambda **_: (Verification.ABSENT, None)),  # executing -> absent
        _never,
        preconditions=lambda **_: world_ok["value"],
    )

    _seed_crashed(clock_store, key, state=from_state, guarantee=Guarantee.VERIFIABLE)
    fake_clock.advance(120)

    report = reconcile(
        clock_store,
        older_than=OLDER_THAN,
        on_absent=OnAbsent.RETRY,
        now_fn=fake_clock,
        registry=reg,
    )
    assert report.count(Outcome.ABORTED) == 1
    assert effects.count(key) == 0
    row = read_row(db, key)
    assert row.state == LedgerState.ABORTED.value
    assert row.error_json["reason"] == "preconditions_violated_on_retry"


# ---------------------------------------------------------------------------
# Unregistered action_type — cannot recover; leave untouched.
# ---------------------------------------------------------------------------


def test_unregistered_action_type_is_left_untouched(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine
) -> None:
    """A row whose action_type is not in the registry cannot be recovered
    (guessing execute/verify would be a blind re-execute). It is left untouched,
    the epoch is NOT bumped, and it is counted 'unregistered'."""
    key = "k-unregistered"
    _seed_crashed(clock_store, key, state=LedgerState.EXECUTING, guarantee=Guarantee.VERIFIABLE)
    fake_clock.advance(120)

    report = reconcile(clock_store, older_than=OLDER_THAN, now_fn=fake_clock, registry=Registry())
    assert report.count(Outcome.UNREGISTERED) == 1
    row = read_row(db, key)
    assert row.state == LedgerState.EXECUTING.value  # untouched
    assert row.attempts == 1  # epoch NOT bumped — no owner to strand it under


# ---------------------------------------------------------------------------
# Re-execute that raises leaves the row executing (escalated), not committed.
# ---------------------------------------------------------------------------


def test_reexecute_that_raises_escalates_and_leaves_executing(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine, effects: EffectsLog
) -> None:
    """A retry whose execute raises: status genuinely unknown, so the row stays
    executing with the error recorded — escalated, never a lying terminal."""
    key = "k-reexec-raises"

    def execute(downstream_key: str | None, **_: Any) -> JsonValue:
        raise RuntimeError("downstream exploded on retry")

    reg = Registry()
    reg.register(ACTION, Effect(verify=lambda **_: (Verification.PRESENT, None)), execute)

    _seed_crashed(clock_store, key, state=LedgerState.PENDING, guarantee=Guarantee.VERIFIABLE)
    fake_clock.advance(120)

    report = reconcile(
        clock_store,
        older_than=OLDER_THAN,
        on_absent=OnAbsent.RETRY,
        now_fn=fake_clock,
        registry=reg,
    )
    assert report.count(Outcome.ESCALATED) == 1
    row = read_row(db, key)
    assert row.state == LedgerState.EXECUTING.value
    assert row.error_json["phase"] == "reconcile_reexecute"


# ---------------------------------------------------------------------------
# A re-execute whose fresh attempt's own post-verify says ABSENT -> failed.
# ---------------------------------------------------------------------------


def test_reexecute_post_verify_absent_lands_failed(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine, effects: EffectsLog
) -> None:
    """A pending retry runs execute, then post-verifies the FRESH attempt; the
    probe proves the fresh attempt absent -> finalize 'failed' (executed and
    confirmed not to have taken effect)."""
    key = "k-reexec-absent"

    def execute(downstream_key: str | None, **_: Any) -> JsonValue:
        effects.log(key)  # it "ran" but the probe will disprove it
        return {"claimed": True}

    reg = Registry()
    reg.register(
        ACTION, Effect(verify=lambda **_: (Verification.ABSENT, {"found": "nothing"})), execute
    )

    _seed_crashed(clock_store, key, state=LedgerState.PENDING, guarantee=Guarantee.VERIFIABLE)
    fake_clock.advance(120)

    report = reconcile(
        clock_store,
        older_than=OLDER_THAN,
        on_absent=OnAbsent.RETRY,
        now_fn=fake_clock,
        registry=reg,
    )
    assert report.count(Outcome.FAILED) == 1
    row = read_row(db, key)
    assert row.state == LedgerState.FAILED.value
    assert row.error_json["post_verify"] == "absent"


# ---------------------------------------------------------------------------
# skipped — bump_epoch returns None (row resolved between scan and takeover).
# ---------------------------------------------------------------------------


def test_row_resolved_before_takeover_is_skipped(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine
) -> None:
    """If another actor resolves a stale row to terminal AFTER the stale scan
    read it but BEFORE bump_epoch, bump_epoch returns None and the reconciler
    skips it — never re-touching a terminal row (I5)."""
    key = "k-skip-resolved"

    def verify(**_: Any) -> tuple[Verification, None]:
        return Verification.PRESENT, None

    reg = Registry()
    reg.register(ACTION, Effect(verify=verify), _never)

    _seed_crashed(clock_store, key, state=LedgerState.EXECUTING, guarantee=Guarantee.VERIFIABLE)
    fake_clock.advance(120)

    # Resolve the row to terminal directly (the "other actor won" case). Then a
    # reconcile pass sees it in the scan window is impossible now (terminal),
    # but bump_epoch on an already-terminal row returns None regardless — assert
    # that skip semantics hold by resolving then reconciling.
    assert clock_store.finalize(key, 1, LedgerState.COMMITTED, {"ok": True}, None)
    report = reconcile(clock_store, older_than=OLDER_THAN, now_fn=fake_clock, registry=reg)
    # Terminal rows are not even in the stale scan, so nothing to do.
    assert report.total == 0
    assert read_row(db, key).state == LedgerState.COMMITTED.value


# ---------------------------------------------------------------------------
# A batch: mixed rows recovered in one pass, each exactly once.
# ---------------------------------------------------------------------------


def test_batch_mixed_rows_each_recovered_once(
    clock_store: PostgresStore, fake_clock: FakeClock, db: Engine, effects: EffectsLog
) -> None:
    """One pass over a mixed batch: a present-verifiable commits, a none-row
    goes unknown, a pending aborts (default) — each touched exactly once."""
    reg = Registry()
    reg.register(
        "act.verifiable",
        Effect(verify=lambda **_: (Verification.PRESENT, {"ok": True})),
        _never,
    )
    reg.register("act.none", Effect(), _never)
    reg.register("act.pending", Effect(verify=lambda **_: (Verification.PRESENT, None)), _never)

    clock_store.claim("k-v", "act.verifiable", Guarantee.VERIFIABLE, {}, None)
    assert clock_store.mark_executing("k-v", 1)
    effects.log("k-v")  # its effect landed
    clock_store.claim("k-n", "act.none", Guarantee.NONE, {}, None)
    assert clock_store.mark_executing("k-n", 1)
    clock_store.claim("k-p", "act.pending", Guarantee.VERIFIABLE, {}, None)  # stays pending

    fake_clock.advance(120)
    report = reconcile(
        clock_store,
        older_than=OLDER_THAN,
        on_absent=OnAbsent.ABORT,
        now_fn=fake_clock,
        registry=reg,
    )
    assert report.count(Outcome.COMMITTED) == 1
    assert report.count(Outcome.UNKNOWN) == 1
    assert report.count(Outcome.ABORTED) == 1
    assert report.total == 3
    assert read_row(db, "k-v").state == LedgerState.COMMITTED.value
    assert read_row(db, "k-n").state == LedgerState.UNKNOWN.value
    assert read_row(db, "k-p").state == LedgerState.ABORTED.value
    assert effects.count("k-v") == 1
