"""The ownership epoch fence, verified on BOTH store backends (P4.1 matrix).

The store-level fence tests in ``test_store_postgres.py`` are Postgres-only
(they use ``xmin`` / raw SQL). The fence guarantee — a reconciler that takes
over a stale in-flight row (``bump_epoch``) leaves the ORIGINAL owner unable to
``mark_executing`` / ``finalize`` / ``record_error`` at its now-stale epoch —
is a correctness invariant that must hold on SQLite too (single-host, but the
same exactly-once bet, PLAN.md 10 point 2). These matrix tests assert it
directly against both backends so the SQLite leg is not merely proving the
OBSERVABLE effect-count invariant but the underlying fence mechanism.

Staleness is produced by advancing the shared ``FakeClock`` (never
``time.sleep`` — the no-sleep guard governs this file too).
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from airlock.types import Guarantee, LedgerState

if TYPE_CHECKING:
    from airlock.store import Store
    from tests.conftest import FakeClock

pytestmark = pytest.mark.matrix

ACTION = "fence.matrix"
OLDER_THAN = timedelta(seconds=60)


def _stage_stale_executing(clock_store: Store, fake_clock: FakeClock, key: str) -> int:
    """Claim + mark executing at epoch 1, then advance the clock so the row is
    stale; a reconciler takes over via ``bump_epoch`` and returns the new epoch.
    """
    clock_store.claim(key, ACTION, Guarantee.NONE, {}, None)
    assert clock_store.mark_executing(key, 1)
    fake_clock.advance(120)
    new_epoch = clock_store.bump_epoch(key, OLDER_THAN)
    assert new_epoch == 2  # the takeover bumped the epoch; the owner is now fenced
    return int(new_epoch)


def test_finalize_is_fenced_by_epoch_bump(clock_store: Store, fake_clock: FakeClock) -> None:
    key = "k-fence-finalize"
    _stage_stale_executing(clock_store, fake_clock, key)

    # The original owner (epoch 1) cannot finalize after takeover.
    assert not clock_store.finalize(key, 1, LedgerState.COMMITTED, {"ok": True}, None)

    loaded = clock_store.load(key)
    assert loaded is not None
    assert loaded.state is LedgerState.EXECUTING  # no override
    assert loaded.result_json is None
    assert loaded.committed_at is None
    assert loaded.attempts == 2  # the reconciler owns it


def test_mark_executing_is_fenced_by_epoch_bump(
    clock_store: Store, fake_clock: FakeClock
) -> None:
    key = "k-fence-mark"
    _stage_stale_executing(clock_store, fake_clock, key)
    assert not clock_store.mark_executing(key, 1)  # fenced owner cannot re-mark
    loaded = clock_store.load(key)
    assert loaded is not None and loaded.attempts == 2


def test_record_error_is_fenced_by_epoch_bump(clock_store: Store, fake_clock: FakeClock) -> None:
    key = "k-fence-record"
    _stage_stale_executing(clock_store, fake_clock, key)
    assert not clock_store.record_error(key, 1, {"owner": "late"})  # fenced
    loaded = clock_store.load(key)
    assert loaded is not None
    assert loaded.error_json is None  # the fenced owner's evidence was rejected
    assert loaded.attempts == 2


def test_reconciler_epoch_can_finalize(clock_store: Store, fake_clock: FakeClock) -> None:
    """Sanity: the NEW epoch (the reconciler's) is not fenced — it owns the row."""
    key = "k-fence-newepoch"
    new_epoch = _stage_stale_executing(clock_store, fake_clock, key)
    assert clock_store.finalize(key, new_epoch, LedgerState.COMMITTED, {"ok": True}, None)
    loaded = clock_store.load(key)
    assert loaded is not None and loaded.state is LedgerState.COMMITTED
