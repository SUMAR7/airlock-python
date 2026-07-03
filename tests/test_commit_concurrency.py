"""SPEC.md section 5, row 2: N processes fire the same action concurrently.

Eight multiprocessing *spawn* workers, each with its own DB connections,
released simultaneously by a Barrier against ONE idempotency key. The
winner's effect is gated on a multiprocessing.Event so the losers provably
arrive while the row is in flight: every worker reports its claim outcome the
instant the claim resolves, and the parent releases the winner only after all
eight claim reports are in — so the seven losers deterministically lost to a
NON-terminal (in-flight) row, exercising scenario 2's wait path rather than
scenario 1's terminal-duplicate path. Exactly one side effect (ground truth:
``effects_log`` written on a separate autocommit connection); all eight calls
return the identical committed result.

Synchronization is Barrier/Event/Queue/direct DB assertions only — no
time.sleep.
"""

from __future__ import annotations

import multiprocessing
import os
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import JsonValue
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from airlock.commit import commit_once
from airlock.effects import Effect
from airlock.store.postgres import PostgresStore, normalize_postgres_url
from airlock.types import IN_FLIGHT_LEDGER_STATES, Claim, Guarantee, LedgerState, Verification
from tests.conftest import EffectsLog

if TYPE_CHECKING:
    from multiprocessing.queues import Queue
    from multiprocessing.synchronize import Barrier, Event

WORKERS = 8
KEY = "scenario-2-one-key"
DEADLINE = 60.0  # hard deadline for every wait; a healthy run takes well under a second


def _probe_present(**_: object) -> tuple[Verification, None]:
    """Post-verify probe (module-level: spawn children must pickle by name)."""
    return Verification.PRESENT, None


class _ClaimReportingStore(PostgresStore):
    """PostgresStore that reports each claim outcome the instant it resolves.

    The parent holds the winner gated until all eight reports are in, which
    pins that every loser lost its claim against an IN-FLIGHT row — the
    contention scenario 2 exists to prove, not sequential duplicate handling.
    """

    def __init__(self, dsn: str, reports: Queue[dict[str, Any]]) -> None:
        super().__init__(dsn)
        self._reports = reports

    def claim(
        self,
        key: str,
        action_type: str,
        guarantee: Guarantee,
        args_json: Mapping[str, JsonValue],
        downstream_key: str | None,
    ) -> Claim:
        claim = super().claim(key, action_type, guarantee, args_json, downstream_key)
        self._reports.put({"pid": os.getpid(), "won": claim.won, "state": claim.record.state.value})
        return claim


def _scenario2_worker(
    dsn: str,
    barrier: Barrier,
    winner_inside: Event,
    release: Event,
    claim_reports: Queue[dict[str, Any]],
    results: Queue[dict[str, Any]],
) -> None:
    """One competing client process. Runs in a spawn child."""
    store = _ClaimReportingStore(dsn, claim_reports)
    effects_engine = create_engine(normalize_postgres_url(dsn), isolation_level="AUTOCOMMIT")
    try:

        def execute(downstream_key: str | None) -> dict[str, Any]:
            # Ground truth on the separate autocommit connection: the effect
            # is counted the instant it happens (PLAN.md section 7).
            with effects_engine.connect() as conn:
                conn.execute(
                    text(
                        "INSERT INTO effects_log (idempotency_key, worker_pid) VALUES (:key, :pid)"
                    ),
                    {"key": KEY, "pid": os.getpid()},
                )
            winner_inside.set()
            # Gate: hold the winner mid-effect until the parent has collected
            # every claim report and finished its mid-flight assertions.
            # Timeout is a failsafe, not timing.
            release.wait(timeout=DEADLINE)
            return {"winner_pid": os.getpid()}

        barrier.wait(timeout=DEADLINE)  # all 8 released simultaneously
        outcome = commit_once(
            store,
            key=KEY,
            action_type="test.concurrent_effect",
            execute=execute,
            effect=Effect(verify=_probe_present),
            args_json={"n": 1},
            wait_timeout=DEADLINE,
            poll_interval=0.02,
        )
        results.put({"pid": os.getpid(), "state": outcome.state.value, "result": outcome.result})
    except Exception as exc:
        results.put({"pid": os.getpid(), "error": repr(exc)})
    finally:
        store.close()
        effects_engine.dispose()


@pytest.mark.concurrency
def test_scenario_2_eight_processes_one_effect(
    db: Engine, database_url: str, effects: EffectsLog
) -> None:
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(WORKERS)
    winner_inside = ctx.Event()
    release = ctx.Event()
    claim_reports_queue: Queue[dict[str, Any]] = ctx.Queue()
    results_queue: Queue[dict[str, Any]] = ctx.Queue()

    processes = [
        ctx.Process(
            target=_scenario2_worker,
            args=(
                database_url,
                barrier,
                winner_inside,
                release,
                claim_reports_queue,
                results_queue,
            ),
            daemon=True,
        )
        for _ in range(WORKERS)
    ]
    results: list[dict[str, Any]] = []
    claim_reports: list[dict[str, Any]] = []
    try:
        for process in processes:
            process.start()

        assert winner_inside.wait(timeout=DEADLINE), "no worker ever reached its effect"

        # Every claim resolves while the winner is still gated — collecting
        # all 8 reports BEFORE release makes the losers-lost-to-in-flight
        # assertion below deterministic.
        claim_reports = [claim_reports_queue.get(timeout=DEADLINE) for _ in range(WORKERS)]

        # Mid-flight, while the winner is gated: the executing marker and the
        # single effect are already durable and visible to a fresh connection.
        assert effects.count(KEY) == 1
        with db.connect() as conn:
            mid_state = conn.execute(
                text("SELECT state FROM commit_records WHERE idempotency_key = :key"),
                {"key": KEY},
            ).scalar_one()
        assert mid_state == LedgerState.EXECUTING.value

        release.set()
        results = [results_queue.get(timeout=DEADLINE) for _ in range(WORKERS)]
        for process in processes:
            process.join(timeout=DEADLINE)
    finally:
        release.set()  # never leave children gated
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(timeout=10.0)

    failures = [entry for entry in results if "error" in entry]
    assert not failures, f"worker failures: {failures}"
    assert len(results) == WORKERS

    # All 8 calls returned the identical committed result.
    assert all(entry["state"] == LedgerState.COMMITTED.value for entry in results)
    first_result = results[0]["result"]
    assert all(entry["result"] == first_result for entry in results)
    worker_pids = {entry["pid"] for entry in results}
    assert first_result["winner_pid"] in worker_pids

    # Exactly one worker won the claim; the seven losers all lost against an
    # IN-FLIGHT row ('pending' or 'executing'), never a terminal one — they
    # exercised the scenario-2 wait path, not scenario-1 duplicate handling.
    winners = [entry for entry in claim_reports if entry["won"]]
    losers = [entry for entry in claim_reports if not entry["won"]]
    assert len(winners) == 1, f"claim reports: {claim_reports}"
    assert winners[0]["pid"] == first_result["winner_pid"]
    assert len(losers) == WORKERS - 1
    in_flight = {state.value for state in IN_FLIGHT_LEDGER_STATES}
    assert all(entry["state"] in in_flight for entry in losers), f"claim reports: {claim_reports}"

    # Exactly one side effect, exactly one ledger row, epoch untouched.
    assert effects.count(KEY) == 1
    with db.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT idempotency_key, state, attempts, result_json, committed_at"
                    " FROM commit_records"
                )
            )
            .mappings()
            .all()
        )
    assert len(rows) == 1
    row = rows[0]
    assert row["idempotency_key"] == KEY
    assert row["state"] == LedgerState.COMMITTED.value
    assert row["attempts"] == 1
    assert row["result_json"] == first_result
    assert row["committed_at"] is not None
