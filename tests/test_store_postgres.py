"""PostgresStore semantics: claim, CAS transitions, the epoch fence, from_url.

Lost races are detected by guarded-UPDATE rowcount — these tests pin that a
fenced ``mark_executing``/``finalize``/``record_error`` returns False AND
leaves the row untouched.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from airlock.store import from_url
from airlock.store.postgres import PostgresStore, normalize_postgres_url
from airlock.types import Guarantee, LedgerState
from tests.conftest import FakeClock, bump_epoch

ARGS = {"amount": "12.50", "currency": "EUR"}


def test_claim_win_persists_full_row(db: Engine, database_url: str) -> None:
    fixed_now = datetime(2026, 7, 2, 9, 30, 0, tzinfo=UTC)
    store = PostgresStore(database_url, now_fn=lambda: fixed_now)
    try:
        claim = store.claim("k-win", "refund.create", Guarantee.VERIFIABLE, ARGS, "dk-1")
        assert claim.won
        record = claim.record
        assert record.idempotency_key == "k-win"
        assert record.action_type == "refund.create"
        assert record.state is LedgerState.PENDING
        assert record.guarantee is Guarantee.VERIFIABLE
        assert record.args_json == ARGS
        assert record.downstream_key == "dk-1"
        assert record.run_id is None
        assert record.result_json is None
        assert record.error_json is None
        assert record.attempts == 1
        # injectable now_fn (PLAN.md section 7): timestamps are SDK-supplied
        assert record.created_at == fixed_now
        assert record.last_attempt_at == fixed_now
        assert record.committed_at is None
    finally:
        store.close()


def test_duplicate_claim_loses_and_returns_existing(store: PostgresStore) -> None:
    first = store.claim("k-dup", "a.b", Guarantee.NONE, ARGS, None)
    second = store.claim("k-dup", "a.b", Guarantee.NONE, {"other": 1}, None)
    assert first.won
    assert not second.won
    assert second.record.id == first.record.id
    assert second.record.args_json == ARGS  # the winner's args, not the loser's


def test_mark_executing_cas(store: PostgresStore) -> None:
    store.claim("k-exec", "a.b", Guarantee.NONE, {}, None)
    assert store.mark_executing("k-exec", 1)
    loaded = store.load("k-exec")
    assert loaded is not None
    assert loaded.state is LedgerState.EXECUTING
    # not pending anymore -> a second mark is fenced by the state guard
    assert not store.mark_executing("k-exec", 1)


def test_mark_executing_fenced_by_epoch_bump(store: PostgresStore, db: Engine) -> None:
    store.claim("k-fence", "a.b", Guarantee.NONE, {}, None)
    bump_epoch(db, "k-fence")
    assert not store.mark_executing("k-fence", 1)
    loaded = store.load("k-fence")
    assert loaded is not None
    assert loaded.state is LedgerState.PENDING  # untouched
    assert loaded.attempts == 2


def test_finalize_commit_sets_committed_at(db: Engine, database_url: str) -> None:
    fixed_now = datetime(2026, 7, 2, 10, 0, 0, tzinfo=UTC)
    store = PostgresStore(database_url, now_fn=lambda: fixed_now)
    try:
        store.claim("k-fin", "a.b", Guarantee.NONE, {}, None)
        assert store.mark_executing("k-fin", 1)
        assert store.finalize("k-fin", 1, LedgerState.COMMITTED, {"ok": True}, None)
        loaded = store.load("k-fin")
        assert loaded is not None
        assert loaded.state is LedgerState.COMMITTED
        assert loaded.result_json == {"ok": True}
        assert loaded.committed_at == fixed_now
    finally:
        store.close()


def test_finalize_fenced_by_epoch_bump(store: PostgresStore, db: Engine) -> None:
    store.claim("k-fin-fence", "a.b", Guarantee.NONE, {}, None)
    assert store.mark_executing("k-fin-fence", 1)
    bump_epoch(db, "k-fin-fence")
    assert not store.finalize("k-fin-fence", 1, LedgerState.COMMITTED, {"ok": True}, None)
    loaded = store.load("k-fin-fence")
    assert loaded is not None
    assert loaded.state is LedgerState.EXECUTING  # no override
    assert loaded.result_json is None
    assert loaded.committed_at is None


def test_finalize_committed_only_from_executing(store: PostgresStore) -> None:
    """A row that never durably marked executing can never become committed."""
    store.claim("k-skip", "a.b", Guarantee.NONE, {}, None)
    assert not store.finalize("k-skip", 1, LedgerState.COMMITTED, {"ok": True}, None)
    loaded = store.load("k-skip")
    assert loaded is not None
    assert loaded.state is LedgerState.PENDING


def test_finalize_abort_from_pending(store: PostgresStore) -> None:
    """Precondition aborts happen before the executing mark (PLAN 4.1 step 2)."""
    store.claim("k-abort", "a.b", Guarantee.NONE, {}, None)
    assert store.finalize("k-abort", 1, LedgerState.ABORTED, None, None)
    loaded = store.load("k-abort")
    assert loaded is not None
    assert loaded.state is LedgerState.ABORTED
    assert loaded.committed_at is None


@pytest.mark.parametrize("target", [LedgerState.FAILED, LedgerState.UNKNOWN])
def test_finalize_failed_and_unknown_fenced_from_pending(
    store: PostgresStore, target: LedgerState
) -> None:
    """'failed' (executed, confirmed no effect) and 'unknown' (may have
    executed) are both false statements about a pending row, which provably
    never started its effect (PLAN 10 point 1) — the state machine refuses
    them: rowcount 0, row untouched."""
    key = f"k-pending-{target.value}"
    store.claim(key, "a.b", Guarantee.NONE, {}, None)
    assert not store.finalize(key, 1, target, None, None)
    loaded = store.load(key)
    assert loaded is not None
    assert loaded.state is LedgerState.PENDING  # untouched
    assert loaded.result_json is None
    assert loaded.committed_at is None


@pytest.mark.parametrize("target", [LedgerState.ABORTED, LedgerState.FAILED, LedgerState.UNKNOWN])
def test_finalize_non_committed_targets_from_executing(
    store: PostgresStore, target: LedgerState
) -> None:
    """From 'executing' the P1.3 recovery table lands aborted/failed/unknown."""
    key = f"k-exec-{target.value}"
    store.claim(key, "a.b", Guarantee.NONE, {}, None)
    assert store.mark_executing(key, 1)
    assert store.finalize(key, 1, target, None, None)
    loaded = store.load(key)
    assert loaded is not None
    assert loaded.state is target
    assert loaded.committed_at is None


def test_engine_pins_read_committed_despite_hostile_default(database_url: str) -> None:
    """ADR-1 puts the ledger in the customer's Postgres, where
    default_transaction_isolation is theirs. claim()'s loser read-back relies
    on READ COMMITTED per-statement snapshots, so the store pins the level on
    the engine instead of inheriting the cluster GUC."""
    separator = "&" if "?" in database_url else "?"
    hostile_url = (
        f"{database_url}{separator}options=-c%20default_transaction_isolation%3Dserializable"
    )

    # Control: an unpinned engine on this DSN really does inherit SERIALIZABLE.
    unpinned = create_engine(normalize_postgres_url(hostile_url))
    try:
        with unpinned.connect() as conn:
            inherited = conn.execute(text("SHOW transaction_isolation")).scalar_one()
        assert inherited == "serializable"
    finally:
        unpinned.dispose()

    # The store's engine overrides the hostile default on every connection.
    pinned_store = PostgresStore(hostile_url)
    try:
        with pinned_store._engine.connect() as conn:
            pinned = conn.execute(text("SHOW transaction_isolation")).scalar_one()
        assert pinned == "read committed"
    finally:
        pinned_store.close()


def test_finalize_rejects_non_terminal_target(store: PostgresStore) -> None:
    store.claim("k-nonterm", "a.b", Guarantee.NONE, {}, None)
    with pytest.raises(ValueError, match="terminal"):
        store.finalize("k-nonterm", 1, LedgerState.EXECUTING, None, None)


def test_terminal_rows_never_change(store: PostgresStore) -> None:
    """Invariant I5: finalize on an already-terminal row is fenced."""
    store.claim("k-term", "a.b", Guarantee.NONE, {}, None)
    assert store.mark_executing("k-term", 1)
    assert store.finalize("k-term", 1, LedgerState.COMMITTED, {"n": 1}, None)
    assert not store.finalize("k-term", 1, LedgerState.ABORTED, None, None)
    assert not store.mark_executing("k-term", 1)
    loaded = store.load("k-term")
    assert loaded is not None
    assert loaded.state is LedgerState.COMMITTED
    assert loaded.result_json == {"n": 1}


def test_record_error_keeps_row_executing(store: PostgresStore) -> None:
    store.claim("k-err", "a.b", Guarantee.NONE, {}, None)
    assert store.mark_executing("k-err", 1)
    assert store.record_error("k-err", 1, {"type": "Boom", "message": "nope"})
    loaded = store.load("k-err")
    assert loaded is not None
    assert loaded.state is LedgerState.EXECUTING
    assert loaded.error_json == {"type": "Boom", "message": "nope"}


def test_record_error_fenced_by_epoch_bump(store: PostgresStore, db: Engine) -> None:
    store.claim("k-err-fence", "a.b", Guarantee.NONE, {}, None)
    assert store.mark_executing("k-err-fence", 1)
    bump_epoch(db, "k-err-fence")
    assert not store.record_error("k-err-fence", 1, {"type": "Boom", "message": "nope"})
    loaded = store.load("k-err-fence")
    assert loaded is not None
    assert loaded.error_json is None


def test_record_error_lands_on_a_pending_row(store: PostgresStore) -> None:
    """The reconciler records the 'aborted' recovery reason BEFORE the
    pending->aborted finalize, so record_error must land on a PENDING row (it
    only writes error_json, never state) — an executing-only guard would
    silently drop that evidence."""
    store.claim("k-err-pending", "a.b", Guarantee.NONE, {}, None)
    assert store.record_error("k-err-pending", 1, {"reconciled": "aborted"})
    loaded = store.load("k-err-pending")
    assert loaded is not None
    assert loaded.state is LedgerState.PENDING  # state unchanged
    assert loaded.error_json == {"reconciled": "aborted"}


def test_record_error_refused_on_terminal_row(store: PostgresStore) -> None:
    """A resolved row is immutable (I5): a late/fenced record_error is refused."""
    store.claim("k-err-terminal", "a.b", Guarantee.NONE, {}, None)
    assert store.mark_executing("k-err-terminal", 1)
    assert store.finalize("k-err-terminal", 1, LedgerState.COMMITTED, {"ok": True}, None)
    assert not store.record_error("k-err-terminal", 1, {"late": "write"})
    loaded = store.load("k-err-terminal")
    assert loaded is not None
    assert loaded.error_json is None


def test_load_missing_key_returns_none(store: PostgresStore) -> None:
    assert store.load("never-claimed") is None


def test_normalize_postgres_url_pins_psycopg() -> None:
    assert (
        normalize_postgres_url("postgresql://u:p@h:5432/db") == "postgresql+psycopg://u:p@h:5432/db"
    )
    assert normalize_postgres_url("postgres://h/db") == "postgresql+psycopg://h/db"
    assert normalize_postgres_url("postgresql+psycopg://h/db") == "postgresql+psycopg://h/db"
    with pytest.raises(ValueError, match="not a postgres DSN"):
        normalize_postgres_url("mysql://h/db")


def test_from_url_dispatches_postgres(database_url: str) -> None:
    built = from_url(database_url)
    assert isinstance(built, PostgresStore)
    built.close()


def test_from_url_rejects_unknown_scheme() -> None:
    with pytest.raises(NotImplementedError, match=r"P4\.1"):
        from_url("sqlite:///airlock.db")


def test_from_url_rejects_non_dsn() -> None:
    with pytest.raises(ValueError, match="not a DSN"):
        from_url("just-a-path")


def test_from_url_missing_extra_is_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without the postgres extra, from_url points at pip install airlock[postgres]."""
    monkeypatch.delitem(sys.modules, "airlock.store.postgres", raising=False)
    monkeypatch.setitem(sys.modules, "sqlalchemy", None)  # makes `import sqlalchemy` raise
    with pytest.raises(ImportError, match=r"airlock\[postgres\]"):
        from_url("postgresql://localhost/airlock_test")


# ---------------------------------------------------------------------------
# stale_inflight + bump_epoch (P1.3 reconciler store surface)
# ---------------------------------------------------------------------------


def test_stale_inflight_only_returns_rows_past_the_cutoff(
    clock_store: PostgresStore, fake_clock: FakeClock
) -> None:
    """The staleness trigger (SPEC section 5): only in-flight rows whose
    last_attempt_at is older than now - older_than are returned; fresh in-flight
    and terminal rows are invisible."""
    clock_store.claim("k-stale", "a.b", Guarantee.VERIFIABLE, {}, None)
    assert clock_store.mark_executing("k-stale", 1)
    clock_store.claim("k-pending", "a.b", Guarantee.NONE, {}, None)
    clock_store.claim("k-terminal", "a.b", Guarantee.NONE, {}, None)
    assert clock_store.mark_executing("k-terminal", 1)
    assert clock_store.finalize("k-terminal", 1, LedgerState.COMMITTED, {"ok": True}, None)

    # Nothing is stale yet.
    assert clock_store.stale_inflight(timedelta(seconds=60)) == []

    fake_clock.advance(120)  # both in-flight rows cross the cutoff
    stale = clock_store.stale_inflight(timedelta(seconds=60))
    keys = {record.idempotency_key for record in stale}
    assert keys == {"k-stale", "k-pending"}  # terminal excluded


def test_stale_inflight_orders_oldest_first(
    clock_store: PostgresStore, fake_clock: FakeClock
) -> None:
    """Ordered by last_attempt_at so the oldest stale rows recover first."""
    clock_store.claim("k-old", "a.b", Guarantee.NONE, {}, None)
    fake_clock.advance(10)
    clock_store.claim("k-new", "a.b", Guarantee.NONE, {}, None)
    fake_clock.advance(120)
    stale = clock_store.stale_inflight(timedelta(seconds=60))
    assert [record.idempotency_key for record in stale] == ["k-old", "k-new"]


def test_bump_epoch_returns_new_epoch_only_while_still_stale_inflight(
    clock_store: PostgresStore, fake_clock: FakeClock
) -> None:
    """bump_epoch is the takeover fence: atomically bump attempts + refresh
    last_attempt_at, returning the NEW epoch, ONLY while the row is still
    in-flight AND still stale. Terminal or refreshed -> None."""
    clock_store.claim("k-bump", "a.b", Guarantee.NONE, {}, None)
    assert clock_store.mark_executing("k-bump", 1)
    fake_clock.advance(120)

    # Still stale-in-flight -> new epoch.
    assert clock_store.bump_epoch("k-bump", timedelta(seconds=60)) == 2
    loaded = clock_store.load("k-bump")
    assert loaded is not None
    assert loaded.attempts == 2
    assert loaded.last_attempt_at == fake_clock()  # refreshed to now

    # Immediately re-bumping: last_attempt_at == now, so no longer stale -> None.
    assert clock_store.bump_epoch("k-bump", timedelta(seconds=60)) is None

    # Terminal -> None.
    fake_clock.advance(120)
    assert clock_store.finalize("k-bump", 2, LedgerState.COMMITTED, {"ok": True}, None)
    assert clock_store.bump_epoch("k-bump", timedelta(seconds=60)) is None


def test_bump_epoch_fences_the_original_owner(
    clock_store: PostgresStore, fake_clock: FakeClock
) -> None:
    """After bump_epoch the original owner (epoch 1) is fenced: its
    mark_executing/finalize/record_error all carry WHERE attempts=1 and now
    match zero rows — it can no longer execute or finalize (PLAN 10 point 2)."""
    clock_store.claim("k-fenced", "a.b", Guarantee.NONE, {}, None)
    assert clock_store.mark_executing("k-fenced", 1)
    fake_clock.advance(120)
    new_epoch = clock_store.bump_epoch("k-fenced", timedelta(seconds=60))
    assert new_epoch == 2

    # The original owner at epoch 1 is now fenced on every guarded write.
    assert not clock_store.finalize("k-fenced", 1, LedgerState.COMMITTED, {"ok": True}, None)
    assert not clock_store.record_error("k-fenced", 1, {"late": True})
    # The reconciler at epoch 2 owns resolution.
    assert clock_store.finalize("k-fenced", 2, LedgerState.COMMITTED, {"won": True}, None)
    loaded = clock_store.load("k-fenced")
    assert loaded is not None
    assert loaded.result_json == {"won": True}
