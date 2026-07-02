"""PostgresStore semantics: claim, CAS transitions, the epoch fence, from_url.

Lost races are detected by guarded-UPDATE rowcount — these tests pin that a
fenced ``mark_executing``/``finalize``/``record_error`` returns False AND
leaves the row untouched.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime

import pytest
from sqlalchemy.engine import Engine

from airlock.store import from_url
from airlock.store.postgres import PostgresStore, normalize_postgres_url
from airlock.types import Guarantee, LedgerState
from tests.conftest import bump_epoch

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


def test_load_missing_key_returns_none(store: PostgresStore) -> None:
    assert store.load("never-claimed") is None


def test_normalize_postgres_url_pins_psycopg() -> None:
    assert (
        normalize_postgres_url("postgresql://u:p@h:5432/db")
        == "postgresql+psycopg://u:p@h:5432/db"
    )
    assert normalize_postgres_url("postgres://h/db") == "postgresql+psycopg://h/db"
    assert (
        normalize_postgres_url("postgresql+psycopg://h/db") == "postgresql+psycopg://h/db"
    )
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
