"""``Store.close()`` must never pull a connection out from under a live writer.

Closing a ``sqlite3`` connection while ANOTHER thread is executing a statement on
it corrupts memory and **segfaults the interpreter** — it is not a catchable
Python exception, so nothing above notices until the process dies.

That race is reachable in ordinary use, not only in tests:

- ``execute_timeout`` deliberately ABANDONS a worker it cannot interrupt, and
  that worker keeps writing to the ledger afterwards;
- cancelling a guarded ASYNC call likewise leaves its worker finishing the
  commit;
- so a graceful shutdown that closes the store can land exactly there.

``SqliteStore`` therefore registers every read and write, and ``close()`` drains
them — and holds the gate through the whole teardown, so an operation cannot
start while connections are being closed.

Run in a SUBPROCESS on purpose: a regression here is a segfault, which would
take down the whole pytest process and bury the cause. As a subprocess it
surfaces as a clean "expected exit 0, got -11".
"""

from __future__ import annotations

import multiprocessing
import os
import tempfile
import threading
import time
from typing import Any

import pytest

pytestmark = pytest.mark.crash

ROUNDS = 6
ROWS = 300
DEADLINE = 180.0


def _one_round() -> None:
    """One store: hammer writes on a thread, then close underneath them."""
    from airlock.store import from_url
    from airlock.types import Guarantee

    store = from_url(f"sqlite:///{os.path.join(tempfile.mkdtemp(), 'a.db')}")
    keys = [f"k{i:04d}" for i in range(ROWS)]
    for key in keys:
        store.claim(
            key=key,
            action_type="close.race",
            guarantee=Guarantee.DOWNSTREAM_IDEMPOTENT,
            args_json={"k": key},
            downstream_key=key,
        )

    started = threading.Event()

    def writer(store: Any = store, keys: list[str] = keys) -> None:
        started.set()
        for key in keys:
            try:
                store.record_error(key, 1, {"type": "X", "message": "y" * 200})
            except Exception:
                return

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    started.wait(timeout=10)
    # Let the writer get INTO its loop so close() lands mid-statement. A real
    # sleep is correct here — we are deliberately racing the C layer — and this
    # runs in a subprocess, outside the no-time.sleep guard's scope.
    time.sleep(0.002)

    store.close()  # must WAIT for the in-flight write, not sever it
    thread.join(timeout=30)


def _hammer_close_against_writer() -> None:
    for _ in range(ROUNDS):
        _one_round()


def test_closing_the_store_under_a_live_writer_does_not_crash() -> None:
    ctx = multiprocessing.get_context("spawn")
    proc = ctx.Process(target=_hammer_close_against_writer, daemon=True)
    proc.start()
    proc.join(timeout=DEADLINE)

    assert not proc.is_alive(), "the close/write race hung"
    assert proc.exitcode == 0, (
        f"Store.close() raced a live writer: subprocess exited {proc.exitcode} "
        "(-11/139 means SIGSEGV — a connection was closed mid-statement)"
    )
