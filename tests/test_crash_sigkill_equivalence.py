"""Validate the ``os._exit`` == real ``SIGKILL`` assumption (PLAN.md 7).

The crash-injection suite (``test_reconcile_crash.py``, the property machine)
uses ``os._exit(137)`` to model process death: it skips ``finally`` / ``atexit``
/ ``__del__`` and drops the DB connection mid-transaction, which is CHEAP and
DETERMINISTIC. PLAN.md 7 requires "one supplementary true-SIGKILL test per
boundary class validates the equivalence assumption" — this file is it.

Mechanism: the worker reaches a boundary, commits the relevant ledger state,
signals readiness on a ``multiprocessing.Event``, then BLOCKS. The parent waits
for readiness (so the kill lands at a known boundary, deterministically, never
by timing) and sends a real ``SIGKILL``. We then assert the durable ledger
state + effect count match exactly what the ``os._exit`` harness produces for
the same boundary class — proving the two crash mechanisms are
DB-indistinguishable, which is the whole assumption the fast suite rests on.

One test per boundary CLASS (not per named crashpoint — the classes share a
durability outcome, and a real fork+kill per case is far heavier than the
os._exit driver):

- effect-free / pending          (like ``after_claim``)
- executing, no effect           (like ``after_executing_mark``)
- executing, effect applied      (like ``after_effect`` / ``after_verify`` /
                                  ``before_finalize_write``)
- terminal / committed           (like ``after_finalize_write``)
"""

from __future__ import annotations

import multiprocessing
import os
import signal
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import create_engine, text

from airlock.store.postgres import PostgresStore, normalize_postgres_url
from airlock.types import Guarantee, LedgerState
from tests.conftest import EffectsLog, read_row

if TYPE_CHECKING:
    from multiprocessing.synchronize import Event

    from sqlalchemy.engine import Engine

SIGKILL_ACTION = "sigkill.refund"
DEADLINE = 60.0

# Boundary classes: name -> (how far to drive, expected durable state, effect?).
_EFFECT_FREE = "effect_free_pending"
_EXECUTING_NO_EFFECT = "executing_no_effect"
_EXECUTING_WITH_EFFECT = "executing_with_effect"
_TERMINAL = "terminal_committed"

_BOUNDARY_CLASSES = [_EFFECT_FREE, _EXECUTING_NO_EFFECT, _EXECUTING_WITH_EFFECT, _TERMINAL]

_EXPECTED_STATE = {
    _EFFECT_FREE: LedgerState.PENDING,
    _EXECUTING_NO_EFFECT: LedgerState.EXECUTING,
    _EXECUTING_WITH_EFFECT: LedgerState.EXECUTING,
    _TERMINAL: LedgerState.COMMITTED,
}
_EXPECTED_EFFECTS = {
    _EFFECT_FREE: 0,
    _EXECUTING_NO_EFFECT: 0,
    _EXECUTING_WITH_EFFECT: 1,
    _TERMINAL: 1,
}


def _sigkill_worker(dsn: str, key: str, boundary_class: str, ready: Event) -> None:
    """Drive the ledger to ``boundary_class``, commit the state, signal, block.

    Uses the store primitives directly (not ``commit_once``) so the state at the
    kill boundary is unambiguous: each ``store`` call is its own committed
    transaction, so once ``ready`` is set the relevant state is DURABLE and the
    parent's ``SIGKILL`` cannot interrupt it. The final ``wait()`` blocks until
    the parent kills the process — no clean exit path.
    """
    store = PostgresStore(dsn)
    effects_engine = create_engine(normalize_postgres_url(dsn), isolation_level="AUTOCOMMIT")

    def log_effect() -> None:
        with effects_engine.connect() as conn:
            conn.execute(
                text("INSERT INTO effects_log (idempotency_key, worker_pid) VALUES (:key, :pid)"),
                {"key": key, "pid": os.getpid()},
            )

    store.claim(key, SIGKILL_ACTION, Guarantee.VERIFIABLE, {"invoice": key}, None)
    if boundary_class == _EFFECT_FREE:
        ready.set()  # durably 'pending', no effect
        _block_forever()

    store.mark_executing(key, 1)
    if boundary_class == _EXECUTING_NO_EFFECT:
        ready.set()  # durably 'executing', no effect yet
        _block_forever()

    log_effect()  # the side effect
    if boundary_class == _EXECUTING_WITH_EFFECT:
        ready.set()  # durably 'executing' WITH the effect applied
        _block_forever()

    store.finalize(key, 1, LedgerState.COMMITTED, {"refund_id": "re_sig"}, None)
    if boundary_class == _TERMINAL:
        ready.set()  # durably 'committed'
        _block_forever()

    raise AssertionError(f"unknown boundary_class {boundary_class!r}")  # pragma: no cover


def _block_forever() -> None:
    """Block until the parent SIGKILLs us (an Event that is never set)."""
    ctx = multiprocessing.get_context("spawn")
    ctx.Event().wait()  # never returns; the parent kills the process


@pytest.mark.crash
@pytest.mark.parametrize("boundary_class", _BOUNDARY_CLASSES)
def test_real_sigkill_matches_os_exit_durability(
    db: Engine,
    database_url: str,
    effects: EffectsLog,
    boundary_class: str,
) -> None:
    """A real SIGKILL at each boundary class leaves the SAME durable ledger
    state + effect count that the ``os._exit`` harness produces — validating the
    fast suite's SIGKILL-equivalence assumption (PLAN.md 7)."""
    key = f"k-sigkill-{boundary_class}"

    ctx = multiprocessing.get_context("spawn")
    ready = ctx.Event()
    proc = ctx.Process(
        target=_sigkill_worker,
        args=(database_url, key, boundary_class, ready),
        daemon=True,
    )
    proc.start()
    try:
        assert ready.wait(timeout=DEADLINE), "worker never reached its boundary"
        # The boundary state is durable now (each store call committed). Kill
        # the LIVE process with a real SIGKILL — the strongest possible model of
        # process death, uncatchable, no cleanup.
        assert proc.pid is not None
        os.kill(proc.pid, signal.SIGKILL)
        proc.join(timeout=DEADLINE)
        assert not proc.is_alive(), "worker survived SIGKILL"
        assert proc.exitcode == -signal.SIGKILL, (
            f"expected termination by SIGKILL, got exitcode {proc.exitcode}"
        )
    finally:
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=10.0)

    row = read_row(db, key)
    assert row.state == _EXPECTED_STATE[boundary_class].value
    assert effects.count(key) == _EXPECTED_EFFECTS[boundary_class]
    if _EXPECTED_STATE[boundary_class] is LedgerState.COMMITTED:
        assert row.committed_at is not None
    else:
        assert row.committed_at is None
