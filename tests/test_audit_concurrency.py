"""Concurrent appenders: the chain-head row lock serializes them (PLAN.md 5.1).

Eight multiprocessing *spawn* workers, each with its own connections, released
simultaneously by a Barrier, each appending a burst of audit events. The
SELECT ... FOR UPDATE on the audit_chain_head singleton is THE serialization
point: whatever the interleaving, the result must be ONE linear chain —
gapless seq, intact prev_hash linkage, head matching the last row — and
verify_chain must pass. No worker may observe a duplicate seq (the UNIQUE
constraint is the belt to the lock's braces).

Synchronization is Barrier/Queue only — no time.sleep.
"""

from __future__ import annotations

import itertools
import multiprocessing
import os
from typing import TYPE_CHECKING, Any

import pytest
from sqlalchemy import text

from airlock.audit import verify_chain
from airlock.store import from_url
from airlock.types import AuditEvent

if TYPE_CHECKING:
    from multiprocessing.queues import Queue
    from multiprocessing.synchronize import Barrier

    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore

pytestmark = pytest.mark.matrix

WORKERS = 8
APPENDS_PER_WORKER = 5
# Failsafe only (never test timing): spawn children re-import the world and a
# loaded CI box can be slow to start 8 interpreters.
DEADLINE = 120.0


def _append_worker(
    dsn: str,
    barrier: Barrier,
    results: Queue[dict[str, Any]],
) -> None:
    """One appending process. Runs in a spawn child."""
    store = from_url(dsn)
    try:
        barrier.wait(timeout=DEADLINE)  # all 8 released simultaneously
        seqs: list[int] = []
        for n in range(APPENDS_PER_WORKER):
            row = store.append_audit(
                AuditEvent(
                    event_type="action_event",
                    run_id=f"run_{os.getpid()}_{n}",
                    action_type="test.audit.concurrent",
                    payload={"pid": os.getpid(), "n": n},
                )
            )
            seqs.append(row.seq)
        results.put({"pid": os.getpid(), "seqs": seqs})
    except Exception as exc:
        results.put({"pid": os.getpid(), "error": repr(exc)})
    finally:
        store.close()


@pytest.mark.concurrency
def test_concurrent_appenders_produce_one_linear_verifiable_chain(
    store: PostgresStore, db: Engine, store_dsn: str
) -> None:
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(WORKERS)
    results_queue: Queue[dict[str, Any]] = ctx.Queue()

    processes = [
        ctx.Process(target=_append_worker, args=(store_dsn, barrier, results_queue), daemon=True)
        for _ in range(WORKERS)
    ]
    results: list[dict[str, Any]] = []
    try:
        for process in processes:
            process.start()
        results = [results_queue.get(timeout=DEADLINE) for _ in range(WORKERS)]
        for process in processes:
            process.join(timeout=DEADLINE)
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(timeout=10.0)

    failures = [entry for entry in results if "error" in entry]
    assert not failures, f"worker failures: {failures}"
    assert len(results) == WORKERS

    total = WORKERS * APPENDS_PER_WORKER

    # Every assigned seq is unique and together they are exactly 1..total —
    # gapless, no duplicates, no lost appends (the head lock serialized them).
    all_seqs = sorted(seq for entry in results for seq in entry["seqs"])
    assert all_seqs == list(range(1, total + 1))

    # Each worker's own appends are strictly increasing (its later append
    # always chained after its earlier one).
    for entry in results:
        assert entry["seqs"] == sorted(entry["seqs"])

    # The stored chain is linear: gapless seq, intact prev_hash linkage.
    rows = list(store.iter_audit(0))
    assert [row.seq for row in rows] == list(range(total + 1))  # genesis + total
    for prev, row in itertools.pairwise(rows):
        assert row.prev_hash == prev.row_hash, f"link broken at seq {row.seq}"

    # The head matches the last row, and the whole chain verifies.
    head = store.audit_head()
    assert head is not None
    assert head.seq == total and head.row_hash == rows[-1].row_hash
    report = verify_chain(store)
    assert report.rows_verified == total + 1

    # Belt-and-braces: the DB agrees there are no duplicate seqs.
    with db.connect() as conn:
        duplicate_count = conn.execute(
            text(
                "SELECT count(*) FROM (SELECT seq FROM audit_events"
                " GROUP BY seq HAVING count(*) > 1) d"
            )
        ).scalar_one()
    assert duplicate_count == 0
