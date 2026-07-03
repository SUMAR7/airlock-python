"""The named slow-owner-vs-reconciler epoch-fence race tests (PLAN.md 7 + P1.3 DoD).

These are the tests the P1.3 DoD names verbatim ("slow-owner race test passes")
and that PLAN.md 7 requires: REAL mid-execute overlap — a live owner blocked
INSIDE ``execute`` while a reconciler bumps the epoch, probes, and retries — not
the serialized dead-owner crash tests (``test_reconcile_crash.py``) or the
single-connection CAS-rowcount checks (``test_store_postgres.py``). They prove
the property the whole PR rests on: the takeover fence makes verify-first
recovery safe against a slow-but-alive owner, so ``effect_count == 1`` holds
under genuine concurrency (SPEC scenarios 3/4, prime directive).

Two actors, real overlap, one process (so a ``threading.Event`` can gate the
owner precisely — a subprocess would need a pipe/semaphore for the same barrier;
a thread suffices because the overlap we exercise is at the DATABASE, and the
ground truth is the ``effects_log`` autocommit table, not Python state):

- an OWNER thread runs ``commit_once``: claims, marks executing (epoch 1),
  enters ``execute`` and BLOCKS on a shared ``Event`` — a slow downstream call;
- the parent advances the fake clock past ``reconcile_after`` and runs
  ``reconcile`` (a DIFFERENT actor) against the now-stale row: it bumps the
  epoch (fencing the owner), probes/retries, and resolves the row;
- the parent releases the owner's ``Event``; the owner returns from ``execute``
  and attempts to ``finalize`` at its OLD epoch — which is fenced (rowcount 0).

The abandonment mechanism is the real ``execute_timeout`` (PLAN.md 4.1 step 4):
the owner's ``execute`` overruns a small REAL timeout while blocked on the Event,
so ``commit_once`` abandons it and returns control BEFORE the reconciler runs —
that is what guarantees the owner is out of ``execute`` when the row becomes
recover-eligible. The Event is never set during the window, so the overrun is
deterministic (never a "did it finish first" flake). Staleness is still produced
by advancing the fake clock, never ``time.sleep``.
"""

from __future__ import annotations

import threading
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import JsonValue

from airlock.commit import commit_once
from airlock.effects import Effect
from airlock.errors import ExecuteTimeout
from airlock.reconcile import OnAbsent, Outcome, reconcile
from airlock.registry import Registry
from airlock.types import Guarantee, LedgerState, Verification
from tests.conftest import EffectsLog, FakeClock, read_row

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore

ACTION = "refund.create"
ARGS: dict[str, JsonValue] = {"invoice": "inv_race", "amount": "12.50"}
OLDER_THAN = timedelta(seconds=60)
# A small REAL timeout: the owner blocks on the (never-set-in-window) Event, so
# execute deterministically overruns this and is abandoned. This is wall-clock
# by design (the abandonment is a real timeout); it is NOT test timing of a
# race — the Event guarantees the overrun happens.
EXECUTE_TIMEOUT = timedelta(seconds=0.3)


class _OwnerResult:
    """Captures what the owner thread's ``commit_once`` did (outcome or error)."""

    def __init__(self) -> None:
        self.outcome: Any = None
        self.error: BaseException | None = None
        self.entered_execute = threading.Event()


@pytest.mark.race
def test_slow_owner_blocked_in_execute_is_fenced_and_effect_stays_one(
    clock_store: PostgresStore,
    fake_clock: FakeClock,
    db: Engine,
    effects: EffectsLog,
    database_url: str,
) -> None:
    """downstream_idempotent, REAL overlap: the owner logs its effect then blocks
    inside execute; the reconciler re-issues with the SAME downstream key while
    the owner is still alive; downstream dedup keeps effect_count == 1 and the
    owner is fenced (its epoch-1 finalize matches 0 rows).

    This is the exact residual-race window PLAN.md 10.2 names — a slow owner
    mid-execute overlapping a reconciler — and the assertion the DoD requires:
    exactly one effect under genuine concurrency."""
    key = "k-race-di"
    downstream_key = "dk-race-di"
    # map_key makes the downstream key distinct from the ledger key AND is what
    # commit_once passes to execute / stores in commit_records.downstream_key /
    # the reconciler re-issues with (stored == sent, PLAN.md 3.4).
    di_effect = Effect(key_param="idempotency_key", map_key=lambda _k: downstream_key)
    release = threading.Event()
    owner = _OwnerResult()

    # A downstream that dedupes on the idempotency key (FakeStripe-style): the
    # SECOND refund with the same key logs NO new effect. Ground truth is the
    # effects_log autocommit table (a raw effect is one log row).
    responses: dict[str, dict[str, Any]] = {}
    responses_lock = threading.Lock()

    def downstream_refund(idempotency_key: str) -> dict[str, Any]:
        with responses_lock:
            if idempotency_key in responses:
                return responses[idempotency_key]  # deduped — no new effect
            effects.log(idempotency_key)
            resp = {"refund_id": f"re_{len(responses) + 1}"}
            responses[idempotency_key] = resp
            return resp

    def owner_execute(dk: str | None) -> JsonValue:
        assert dk == downstream_key
        result = downstream_refund(dk)  # the effect lands (logged once)
        owner.entered_execute.set()  # signal: the effect is in, we're now "slow"
        release.wait()  # block INSIDE execute until the parent releases
        return result

    def reconcile_execute(dk: str | None, **_: Any) -> JsonValue:
        # The reconciler re-issues with the SAME downstream key -> deduped.
        assert dk == downstream_key
        return downstream_refund(dk)

    def run_owner() -> None:
        try:
            owner.outcome = commit_once(
                clock_store,
                key=key,
                action_type=ACTION,
                execute=owner_execute,
                effect=di_effect,
                args_json=ARGS,
                reconcile_after=OLDER_THAN,
                execute_timeout=EXECUTE_TIMEOUT,
                now_fn=fake_clock,
                wait=False,  # the loser/recovery path is what we exercise, not polling
            )
        except BaseException as exc:  # ExecuteTimeout expected
            owner.error = exc

    owner_thread = threading.Thread(target=run_owner, name="race-owner", daemon=True)
    owner_thread.start()

    # Wait until the owner is provably INSIDE execute with the effect logged.
    assert owner.entered_execute.wait(timeout=30), "owner never entered execute"
    assert effects.count(downstream_key) == 1  # the owner's effect landed once

    # The owner's execute is now blocked on `release`; its commit_once will
    # abandon it once EXECUTE_TIMEOUT of real time elapses (the Event is unset).
    # Join the owner thread: commit_once must return via ExecuteTimeout, proving
    # the owner is OUT of execute before we run the reconciler.
    owner_thread.join(timeout=30)
    assert not owner_thread.is_alive(), "owner commit_once did not abandon execute"
    assert isinstance(owner.error, ExecuteTimeout), f"expected ExecuteTimeout, got {owner.error!r}"

    # The row is still executing at epoch 1 (the owner never finalized).
    assert read_row(db, key).state == LedgerState.EXECUTING.value
    assert read_row(db, key).attempts == 1

    # A DIFFERENT actor (the reconciler) now takes over the stale row. It bumps
    # the epoch (fencing the owner) and re-issues with the same downstream key.
    reg = Registry()
    reg.register(ACTION, di_effect, reconcile_execute)
    fake_clock.advance(120)
    report = reconcile(
        clock_store,
        older_than=OLDER_THAN,
        on_absent=OnAbsent.RETRY,
        execute_timeout=EXECUTE_TIMEOUT,
        now_fn=fake_clock,
        registry=reg,
    )
    assert report.count(Outcome.RETRIED_COMMITTED) == 1

    # THE INVARIANT: exactly one effect, despite a live owner overlapping the
    # reconciler (downstream dedup kept the re-issue from adding a second).
    assert effects.count(downstream_key) == 1

    recovered = read_row(db, key)
    assert recovered.state == LedgerState.COMMITTED.value
    assert recovered.attempts == 2  # the reconciler owns it under the bumped epoch

    # Release the (already-abandoned) owner-execute daemon thread and let it
    # unwind. Its downstream call is deduped, so still one effect; even if the
    # owner tried to finalize at epoch 1 it would be fenced. (owner_thread — the
    # commit_once caller — already exited via ExecuteTimeout; the still-blocked
    # thread is the daemon _run_execute spawned for the abandoned execute.)
    release.set()

    # Prove the fence directly: the original owner at epoch 1 cannot finalize or
    # record — the reconciler at epoch 2 owns resolution (PLAN.md 10 point 2).
    assert not clock_store.finalize(key, 1, LedgerState.COMMITTED, {"owner": "late"}, None)
    assert not clock_store.record_error(key, 1, {"owner": "late"})
    # Still exactly one effect and still committed by the reconciler.
    assert effects.count(downstream_key) == 1
    assert read_row(db, key).state == LedgerState.COMMITTED.value


@pytest.mark.race
def test_slow_owner_verifiable_probe_absent_reconciler_executes_once(
    clock_store: PostgresStore,
    fake_clock: FakeClock,
    db: Engine,
    effects: EffectsLog,
) -> None:
    """verify-only, REAL overlap: the owner blocks inside execute BEFORE its
    effect lands; abandoned via execute_timeout; the reconciler probes ABSENT
    (nothing logged yet) and executes ONCE; the fenced owner cannot finalize.

    This is SPEC scenario 4 under a live-but-fenced owner: the epoch fence plus
    the enforced execute_timeout < reconcile_after ordering yield exactly one
    effect, and the fenced owner's mark_executing/finalize at the old epoch
    return False (rowcount 0)."""
    key = "k-race-verif"
    release = threading.Event()
    owner = _OwnerResult()

    def owner_execute(dk: str | None) -> JsonValue:
        # Enter execute and block BEFORE the effect lands. When abandoned and
        # later released, we STILL do not log — a verify-only downstream call
        # that was abandoned mid-flight did not take effect (the honest model:
        # the effect never reached the downstream because the owner let go).
        owner.entered_execute.set()
        release.wait()
        return {"owner": "unreached-cleanly"}

    def reconcile_execute(dk: str | None, **_: Any) -> JsonValue:
        effects.log(key)  # the reconciler's single, real effect
        return {"refund_id": "re_reconciled"}

    # verify: ABSENT until the reconciler's execute logs the effect, then PRESENT.
    def verify(**_: Any) -> tuple[Verification, dict[str, Any]]:
        landed = effects.count(key) >= 1
        return (Verification.PRESENT if landed else Verification.ABSENT), {"landed": landed}

    def run_owner() -> None:
        try:
            owner.outcome = commit_once(
                clock_store,
                key=key,
                action_type=ACTION,
                execute=owner_execute,
                effect=Effect(verify=verify),
                args_json=ARGS,
                reconcile_after=OLDER_THAN,
                execute_timeout=EXECUTE_TIMEOUT,
                now_fn=fake_clock,
                wait=False,
            )
        except BaseException as exc:
            owner.error = exc

    owner_thread = threading.Thread(target=run_owner, name="race-owner-verif", daemon=True)
    owner_thread.start()
    assert owner.entered_execute.wait(timeout=30), "owner never entered execute"
    assert effects.count(key) == 0  # nothing landed yet

    owner_thread.join(timeout=30)
    assert not owner_thread.is_alive()
    assert isinstance(owner.error, ExecuteTimeout)

    # Row still executing at epoch 1; the owner is out of execute (abandoned).
    assert read_row(db, key).state == LedgerState.EXECUTING.value
    assert read_row(db, key).attempts == 1

    reg = Registry()
    reg.register(ACTION, Effect(verify=verify), reconcile_execute)
    fake_clock.advance(120)
    report = reconcile(
        clock_store,
        older_than=OLDER_THAN,
        on_absent=OnAbsent.RETRY,
        execute_timeout=EXECUTE_TIMEOUT,
        now_fn=fake_clock,
        registry=reg,
    )
    assert report.count(Outcome.RETRIED_COMMITTED) == 1
    assert effects.count(key) == 1  # exactly one effect — the reconciler's

    recovered = read_row(db, key)
    assert recovered.state == LedgerState.COMMITTED.value
    assert recovered.attempts == 2

    # The fenced owner (epoch 1) cannot execute or finalize after takeover.
    assert not clock_store.mark_executing(key, 1)
    assert not clock_store.finalize(key, 1, LedgerState.COMMITTED, {"owner": "late"}, None)
    assert not clock_store.record_error(key, 1, {"owner": "late"})

    release.set()  # let the abandoned owner thread unwind (it logs nothing)
    assert effects.count(key) == 1


@pytest.mark.race
def test_two_reconcilers_recover_a_batch_each_row_exactly_once(
    clock_store: PostgresStore,
    fake_clock: FakeClock,
    db: Engine,
    effects: EffectsLog,
    database_url: str,
) -> None:
    """FOR UPDATE SKIP LOCKED + the epoch fence: two reconcilers released
    together against a batch of stale pending rows recover each row EXACTLY once
    (PLAN.md 7 'each-row-once'; no row double-executed under on_absent=RETRY).

    Whether a row is handed to reconciler A or B by SKIP LOCKED, or both read it
    and only one wins bump_epoch, the fence serializes them: total committed ==
    number of rows, each key's effect logged exactly once — never twice."""
    from airlock.store.postgres import PostgresStore

    n = 8
    # A per-key action_type so each row's execute is unambiguous; ONE shared
    # registry both reconcilers use (each registration re-executes its own key).
    keys = [f"k-2rec-{i}" for i in range(n)]
    actions = [f"race.batch.{i}" for i in range(n)]
    shared_registry = Registry()

    def make_execute(k: str) -> Any:
        def execute(dk: str | None, **_: Any) -> JsonValue:
            effects.log(k)
            return {"key": k}

        return execute

    for k, act in zip(keys, actions, strict=True):
        # pending rows are provably effect-free -> RETRY re-executes once each.
        clock_store.claim(k, act, Guarantee.VERIFIABLE, ARGS, None)
        shared_registry.register(
            act, Effect(verify=lambda **_: (Verification.PRESENT, None)), make_execute(k)
        )

    fake_clock.advance(120)  # all rows now stale past OLDER_THAN

    # Two reconcilers, each on its OWN store (own connection pool), released
    # together against the same stale batch. Both share the fake clock so they
    # scan the same rows; SKIP LOCKED + bump_epoch decide who recovers each.
    store_a = PostgresStore(database_url, now_fn=fake_clock)
    store_b = PostgresStore(database_url, now_fn=fake_clock)
    reports: dict[str, Any] = {}
    start = threading.Barrier(2)

    def run_reconciler(name: str, store: PostgresStore) -> None:
        start.wait()  # release both at once for maximal overlap
        reports[name] = reconcile(
            store,
            older_than=OLDER_THAN,
            on_absent=OnAbsent.RETRY,
            execute_timeout=EXECUTE_TIMEOUT,
            now_fn=fake_clock,
            registry=shared_registry,
        )

    try:
        threads = [
            threading.Thread(target=run_reconciler, args=("a", store_a), name="rec-a"),
            threading.Thread(target=run_reconciler, args=("b", store_b), name="rec-b"),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
            assert not t.is_alive(), "a reconciler thread hung"
    finally:
        store_a.close()
        store_b.close()

    # Every row recovered exactly once: each key's effect logged once, each row
    # committed, and the two reconcilers' RETRIED_COMMITTED tallies sum to n
    # (no row was recovered by BOTH — the fence made the second a skip/no-op).
    for k in keys:
        assert effects.count(k) == 1, f"{k} was executed {effects.count(k)} times (expected 1)"
        assert read_row(db, k).state == LedgerState.COMMITTED.value
        assert read_row(db, k).attempts == 2  # recovered under a single bumped epoch
    total_committed = reports["a"].count(Outcome.RETRIED_COMMITTED) + reports["b"].count(
        Outcome.RETRIED_COMMITTED
    )
    assert total_committed == n
