"""SPEC scenario 3 — crash after effect, before commit mark (crash-injection).

A subprocess worker runs the commit flow and dies via ``os._exit`` mid-flight
at a named crashpoint in ``{after_effect, after_verify, before_finalize_write}``
— deterministic like a mock, real like SIGKILL: ``os._exit`` skips
``finally``/``atexit`` and the DB connection dies mid-transaction, so the last
DURABLE state is whatever committed before the crash. Every one of these
crashpoints lands the row ``state=executing`` with the effect already applied
(``effect_count == 1``).

The parent then advances a fake clock past the reconcile timeout and runs one
reconcile pass with a VERIFIABLE probe that returns PRESENT. Assert: the row
becomes ``committed``, ``effect_count`` is STILL 1 (never re-executed), and the
evidence carries a ``reconciled`` event.

Determinism substrate (PLAN.md section 7): the crash is produced by
``os._exit`` in a spawn subprocess (never a timer); "past the reconcile
timeout" is produced by advancing the store's injectable ``now_fn`` (never
``time.sleep``). Side-effect ground truth is the ``effects_log`` autocommit
table, asserted from a fresh connection.
"""

from __future__ import annotations

import multiprocessing
import os
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest
from sqlalchemy import create_engine, text

from airlock.effects import Effect
from airlock.reconcile import Outcome, reconcile
from airlock.registry import Registry
from airlock.store.postgres import PostgresStore, normalize_postgres_url
from airlock.types import Guarantee, LedgerState, Verification
from tests.conftest import EffectsLog, FakeClock, read_row

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

CRASH_ACTION = "crash.refund"
CRASHPOINTS = ["after_effect", "after_verify", "before_finalize_write"]
DEADLINE = 60.0


def _rebase_last_attempt(engine: Engine, key: str, when: datetime) -> None:
    """Re-stamp a crashed row's last_attempt_at onto the fake clock's timeline.

    The crash subprocess necessarily used its own real clock; the reconciler
    runs on the fake clock. Aligning last_attempt_at to the fake clock keeps the
    staleness trigger deterministic (advance the clock, never sleep). State,
    attempts, and effects are untouched — only the timeline the stale scan reads.
    """
    with engine.begin() as conn:
        rowcount = conn.execute(
            text("UPDATE commit_records SET last_attempt_at = :when WHERE idempotency_key = :key"),
            {"when": when, "key": key},
        ).rowcount
    assert rowcount == 1


def _crash_worker(dsn: str, key: str, crashpoint: str) -> None:
    """Run the commit flow to ``crashpoint``, apply the effect once, then
    ``os._exit`` — leaving the row durably ``executing`` (SIGKILL-equivalent)."""
    engine = create_engine(normalize_postgres_url(dsn))
    effects_engine = create_engine(normalize_postgres_url(dsn), isolation_level="AUTOCOMMIT")
    store = PostgresStore(dsn)

    def log_effect() -> None:
        with effects_engine.connect() as conn:
            conn.execute(
                text("INSERT INTO effects_log (idempotency_key, worker_pid) VALUES (:key, :pid)"),
                {"key": key, "pid": os.getpid()},
            )

    # Steps 1 + 3: claim (own txn) then mark executing (own txn, committed
    # BEFORE the effect). Both are durable before the effect runs.
    store.claim(key, CRASH_ACTION, Guarantee.VERIFIABLE, {"invoice": "inv_crash"}, None)
    store.mark_executing(key, 1)

    # Step 4: the side effect. Exactly one, applied on the autocommit connection
    # so it survives the crash independently of any ledger transaction.
    log_effect()
    if crashpoint == "after_effect":
        os._exit(137)  # died the instant the effect landed; no verify, no finalize

    # Step 5: post-verify (the effect happened, so a real probe would say PRESENT).
    if crashpoint == "after_verify":
        os._exit(137)  # verified but died before writing the terminal state

    if crashpoint == "before_finalize_write":
        os._exit(137)  # about to finalize committed; the write never happens

    # Unreachable for these crashpoints; a real run would finalize here.
    store.finalize(key, 1, LedgerState.COMMITTED, {"refund_id": "re_worker"}, None)
    engine.dispose()
    effects_engine.dispose()
    store.close()


def _crash_after_claim_worker(dsn: str, key: str) -> None:
    """Claim (own txn) then die BEFORE mark_executing — the row stays 'pending'
    (provably effect-free: the executing marker commits before any effect)."""
    store = PostgresStore(dsn)
    store.claim(key, CRASH_ACTION, Guarantee.VERIFIABLE, {"invoice": "inv_pre"}, None)
    os._exit(137)


@pytest.mark.crash
@pytest.mark.parametrize("crashpoint", CRASHPOINTS)
def test_scenario_3_crash_leaves_executing_then_probe_present_recovers(
    db: Engine,
    database_url: str,
    effects: EffectsLog,
    clock_store: PostgresStore,
    fake_clock: FakeClock,
    crashpoint: str,
) -> None:
    key = f"k-crash-{crashpoint}"

    ctx = multiprocessing.get_context("spawn")
    proc = ctx.Process(target=_crash_worker, args=(database_url, key, crashpoint), daemon=True)
    proc.start()
    proc.join(timeout=DEADLINE)
    assert not proc.is_alive(), "crash worker did not exit"
    # os._exit(137) is the crash; a clean 0 would mean the crashpoint never fired.
    assert proc.exitcode == 137, f"expected os._exit(137), got {proc.exitcode}"

    # Post-crash durable state: executing, with exactly one effect applied.
    row = read_row(db, key)
    assert row.state == LedgerState.EXECUTING.value, "crash must leave the row executing"
    assert row.committed_at is None
    assert effects.count(key) == 1

    # The crash worker stamped last_attempt_at from its own (real) clock; the
    # reconciler runs on the fake clock. Re-stamp the row to the fake clock's
    # start instant so the fake-clock staleness check is deterministic — the
    # crash and the timeout stay on the two substrate mechanisms (os._exit and
    # clock advance), never wall time.
    _rebase_last_attempt(db, key, fake_clock())

    # A VERIFIABLE probe that confirms the effect (it really did land).
    probe_calls: list[dict[str, Any]] = []

    def verify(**arg_map: Any) -> tuple[Verification, dict[str, str]]:
        probe_calls.append(arg_map)
        return Verification.PRESENT, {"refund_id": "re_worker"}

    reg = Registry()
    reg.register(
        CRASH_ACTION,
        Effect(verify=verify),
        lambda dk, **_: pytest.fail("recovery of a present-verifiable row must not re-execute"),
    )

    # Advance the fake clock past the reconcile timeout (never time.sleep).
    fake_clock.advance(300)
    report = reconcile(
        clock_store, older_than=timedelta(seconds=60), now_fn=fake_clock, registry=reg
    )

    # Recovered by verification, not re-execution.
    assert report.count(Outcome.COMMITTED) == 1
    assert probe_calls == [{"invoice": "inv_crash"}]  # probe got the rehydrated arg_map
    assert effects.count(key) == 1  # STILL exactly one effect

    recovered = read_row(db, key)
    assert recovered.state == LedgerState.COMMITTED.value
    assert recovered.result_json == {"refund_id": "re_worker"}
    assert recovered.committed_at is not None
    assert recovered.attempts == 2  # recovered under the bumped epoch
    assert recovered.error_json["reconciled"] == "committed"  # recovery evidence


@pytest.mark.crash
def test_scenario_4_crash_before_effect_leaves_pending(
    db: Engine,
    database_url: str,
    effects: EffectsLog,
    clock_store: PostgresStore,
    fake_clock: FakeClock,
) -> None:
    """crashpoint after_claim: the row is durably 'pending' with ZERO effects
    (the executing marker commits before the effect, so pending is provably
    effect-free). Recovery re-validates preconditions and retries -> exactly one
    effect, committed, attempts > 1."""
    key = "k-crash-after-claim"

    ctx = multiprocessing.get_context("spawn")
    proc = ctx.Process(target=_crash_after_claim_worker, args=(database_url, key), daemon=True)
    proc.start()
    proc.join(timeout=DEADLINE)
    assert proc.exitcode == 137

    row = read_row(db, key)
    assert row.state == LedgerState.PENDING.value
    assert effects.count(key) == 0  # provably effect-free
    _rebase_last_attempt(db, key, fake_clock())

    def execute(downstream_key: str | None, **_: Any) -> Any:
        effects.log(key)
        return {"refund_id": "re_retry"}

    reg = Registry()
    reg.register(CRASH_ACTION, Effect(verify=lambda **_: (Verification.PRESENT, None)), execute)

    fake_clock.advance(300)
    from airlock.reconcile import OnAbsent

    report = reconcile(
        clock_store,
        older_than=timedelta(seconds=60),
        on_absent=OnAbsent.RETRY,
        now_fn=fake_clock,
        registry=reg,
    )
    assert report.count(Outcome.RETRIED_COMMITTED) == 1
    assert effects.count(key) == 1  # exactly one effect, applied during recovery
    recovered = read_row(db, key)
    assert recovered.state == LedgerState.COMMITTED.value
    assert recovered.attempts > 1
