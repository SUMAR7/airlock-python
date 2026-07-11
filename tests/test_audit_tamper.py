"""Audit chain: verify + tamper detection + append-only + finalize atomicity.

Runs on BOTH backends (``@pytest.mark.matrix``) — the P4.1 sqlite-equivalent of
the Postgres-internal proofs in ``test_audit_chain.py`` / ``test_audit_atomicity.py``
(which stay Postgres-only because they assert ``xmin`` provenance and use
``ALTER TABLE ... DISABLE TRIGGER``). Here every guarantee is exercised through
mechanisms both dialects share, so the ADR-5 hash chain is proven tamper-evident
and the finalize+append is proven atomic on SqliteStore too:

- **verify**: genesis + N appended rows verify end-to-end.
- **append-only**: the DB triggers block UPDATE and DELETE on ``audit_events``.
- **tamper detection**: with the append-only guard temporarily removed (a
  malicious owner — "a database owner can always defeat in-database controls,
  which is exactly why tamper EVIDENCE is the chain's job"), ANY mutation of a
  row's payload or stored ``row_hash`` is caught by ``verify_chain`` at the
  offending seq.
- **finalize+append atomicity**: a finalize whose audit payload is outside the
  airlock-canon-1 domain (a float) raises INSIDE the finalize transaction, so
  the terminal CAS rolls back with it — the row stays ``executing``, no audit
  row is appended, the head is unchanged. This is the sqlite-equivalent of the
  Postgres same-``xmin`` one-transaction proof: either both land or neither does.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

import pytest
from sqlalchemy import text

from airlock.audit import verify_chain
from airlock.errors import AuditChainError, CanonicalizationError
from airlock.types import AuditEvent, Guarantee, LedgerState

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.matrix


def _append_burst(store: Any, n: int) -> None:
    for i in range(1, n + 1):
        store.append_audit(
            AuditEvent(
                event_type="action_event",
                run_id=f"run_{i}",
                action_type="test.audit",
                payload={"n": i},
            )
        )


@contextmanager
def _tamper(db: Any) -> Iterator[None]:
    """Temporarily remove the append-only guard so a test can forge a row.

    Postgres: ``ALTER TABLE ... DISABLE/ENABLE TRIGGER``. SQLite has no trigger
    toggle, so DROP the triggers and recreate them from the schema constants.
    Either way this models a privileged owner defeating the in-DB control — the
    chain (verify_chain) is the tamper EVIDENCE that survives it.
    """
    if db.dialect.name == "sqlite":
        from airlock.store._schema import (
            SQLITE_AUDIT_NO_DELETE_TRIGGER_DDL,
            SQLITE_AUDIT_NO_UPDATE_TRIGGER_DDL,
        )

        with db.begin() as conn:
            conn.execute(text("DROP TRIGGER IF EXISTS audit_events_no_update"))
            conn.execute(text("DROP TRIGGER IF EXISTS audit_events_no_delete"))
        try:
            yield
        finally:
            with db.begin() as conn:
                conn.execute(text(SQLITE_AUDIT_NO_UPDATE_TRIGGER_DDL))
                conn.execute(text(SQLITE_AUDIT_NO_DELETE_TRIGGER_DDL))
    else:
        with db.begin() as conn:
            conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only"))
        try:
            yield
        finally:
            with db.begin() as conn:
                conn.execute(
                    text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only")
                )


def _assert_verify_fails_at(store: Any, seq: int) -> None:
    with pytest.raises(AuditChainError) as excinfo:
        verify_chain(store)
    assert excinfo.value.seq == seq


def test_chain_verifies_after_appends(store: Any) -> None:
    _append_burst(store, 5)
    report = verify_chain(store)
    assert report.rows_verified == 6  # genesis + 5
    assert report.head_seq == 5


def test_append_only_blocks_update_and_delete(store: Any, db: Any) -> None:
    """The DB triggers make audit_events append-only on both backends."""
    _append_burst(store, 2)
    from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError

    for sql in (
        "UPDATE audit_events SET payload_json = '{}' WHERE seq = 1",
        "DELETE FROM audit_events WHERE seq = 1",
    ):
        with (
            pytest.raises((IntegrityError, OperationalError, DBAPIError), match="append-only"),
            db.begin() as conn,
        ):
            conn.execute(text(sql))


def test_tamper_payload_detected(store: Any, db: Any) -> None:
    _append_burst(store, 5)
    with _tamper(db), db.begin() as conn:
        conn.execute(
            text("UPDATE audit_events SET payload_json = :p WHERE seq = 3"),
            {"p": '{"n": 3, "note": "forged"}'},
        )
    _assert_verify_fails_at(store, 3)


def test_tamper_row_hash_detected(store: Any, db: Any) -> None:
    _append_burst(store, 4)
    with _tamper(db), db.begin() as conn:
        conn.execute(
            text("UPDATE audit_events SET row_hash = :h WHERE seq = 2"),
            {"h": b"\x00" * 32},
        )
    _assert_verify_fails_at(store, 2)


def test_finalize_append_is_atomic_on_canonicalization_fault(store: Any, db: Any) -> None:
    """A finalize whose audit payload is non-canonical (a float) raises inside
    the finalize transaction, rolling back the terminal CAS with it: the row
    stays 'executing', no audit row is appended, the head is unchanged. The
    sqlite-equivalent of the same-xmin one-transaction proof."""
    key = "k-atomic"
    store.claim(key, "test.audit.atomic", Guarantee.VERIFIABLE, {"invoice": key}, None)
    assert store.mark_executing(key, 1)
    _append_burst(store, 2)  # some real history first
    head_before = store.audit_head()
    assert head_before is not None

    poison = AuditEvent(
        event_type="action_event",
        run_id="run_poison",
        action_type="test.audit.atomic",
        payload={"amount": 12.5},  # a float — outside airlock-canon-1
    )
    with pytest.raises(CanonicalizationError):
        store.finalize(key, 1, LedgerState.COMMITTED, {"ok": True}, poison)

    # Neither the terminal CAS nor the audit append landed.
    loaded = store.load(key)
    assert loaded is not None
    assert loaded.state is LedgerState.EXECUTING  # NOT committed — rolled back
    assert loaded.committed_at is None
    head_after = store.audit_head()
    assert head_after is not None
    assert head_after.seq == head_before.seq  # no audit row appended
    verify_chain(store)  # chain still intact
