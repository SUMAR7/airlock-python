"""The hash-chained audit trail (P2.2, ADR-5): schema, append protocol, verify, tamper.

Covers PLAN.md 5.1/5.2 end to end against real Postgres:

- schema: genesis row + chain head seeded idempotently; BYTEA-32 CHECKs; the
  head singleton constraint; DB-level append-only (UPDATE/DELETE raise from
  the trigger, for every role, in addition to the REVOKE).
- append protocol: gapless seq, prev_hash linkage, SDK-computed hashes,
  SDK-supplied created_at (the hashed and stored value are the same instant),
  canon-domain enforcement BEFORE anything is durable.
- verify_chain: full O(n) pass, checkpoint O(delta) pass, and the tamper
  battery — payload, every envelope column, row_hash, prev_hash, a deleted
  row, swapped rows, a truncated tail, a tampered head, a tampered genesis —
  each detected at the RIGHT seq.

Tampering is performed as the table owner with the append-only trigger
disabled (``ALTER TABLE ... DISABLE TRIGGER``): a database owner can always
defeat in-database controls, which is exactly why tamper EVIDENCE (the chain)
exists on top of tamper PREVENTION (the trigger).
"""

from __future__ import annotations

import itertools
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from pydantic import JsonValue
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from airlock.audit import (
    GENESIS_CREATED_AT,
    GENESIS_EVENT_TYPE,
    GENESIS_PAYLOAD,
    GENESIS_ROW_HASH,
    ZERO_HASH,
    compute_row_hash,
    rfc3339_utc,
    verify_chain,
)
from airlock.errors import AirlockError, AuditChainError, CanonicalizationError
from airlock.store._schema import ensure_schema, seed_genesis
from airlock.types import AuditEvent

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore

NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=UTC)


def _event(n: int, *, event_type: str = "action_event") -> AuditEvent:
    return AuditEvent(
        event_type=event_type,
        run_id=f"run_{n}",
        action_type=f"test.audit.{n % 3}",
        payload={"n": n, "note": f"event-{n}", "money": {"amount": "12.5", "currency": "EUR"}},
        created_at=NOW + timedelta(seconds=n),
    )


def _append_burst(store: PostgresStore, count: int) -> None:
    """A burst of mixed events: action_event / reconcile / custom types."""
    types = ("action_event", "reconcile", "custom.metric")
    for n in range(1, count + 1):
        store.append_audit(_event(n, event_type=types[n % 3]))


@contextmanager
def _tamper(db: Engine) -> Iterator[None]:
    """Owner-level tamper window: append-only trigger disabled inside."""
    with db.begin() as conn:
        conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only"))
    try:
        yield
    finally:
        with db.begin() as conn:
            conn.execute(text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only"))


def _assert_verify_fails_at(store: PostgresStore, seq: int) -> AuditChainError:
    with pytest.raises(AuditChainError) as excinfo:
        verify_chain(store)
    assert excinfo.value.seq == seq, (
        f"verification failed at seq {excinfo.value.seq}, expected {seq}: {excinfo.value}"
    )
    return excinfo.value


# ---------------------------------------------------------------------------
# Schema: genesis, head, constraints, DB-level append-only.
# ---------------------------------------------------------------------------


def test_genesis_row_and_head_exist_after_ensure_schema(store: PostgresStore, db: Engine) -> None:
    """ensure_schema seeds seq=0 with prev_hash=0x00*32, the documented payload,
    and the frozen constant row_hash; the head points at it."""
    with db.connect() as conn:
        row = conn.execute(text("SELECT * FROM audit_events WHERE seq = 0")).mappings().one()
    assert bytes(row["prev_hash"]) == ZERO_HASH
    assert bytes(row["row_hash"]) == GENESIS_ROW_HASH
    assert row["event_type"] == GENESIS_EVENT_TYPE
    assert row["payload_json"] == GENESIS_PAYLOAD
    assert row["run_id"] is None and row["action_type"] is None
    assert row["created_at"].astimezone(UTC) == GENESIS_CREATED_AT
    head = store.audit_head()
    assert head is not None
    assert head.seq == 0 and head.row_hash == GENESIS_ROW_HASH


def test_ensure_schema_and_seed_genesis_are_idempotent(store: PostgresStore, db: Engine) -> None:
    """Re-running DDL + genesis seeding never duplicates or rewinds the chain."""
    store.append_audit(_event(1))
    ensure_schema(db)
    seed_genesis(db)
    with db.connect() as conn:
        genesis_count = conn.execute(
            text("SELECT count(*) FROM audit_events WHERE seq = 0")
        ).scalar_one()
        head_count = conn.execute(text("SELECT count(*) FROM audit_chain_head")).scalar_one()
    assert genesis_count == 1
    assert head_count == 1
    head = store.audit_head()
    assert head is not None and head.seq == 1  # not rewound to genesis
    verify_chain(store)


def test_update_and_delete_raise_in_the_db(store: PostgresStore, db: Engine) -> None:
    """DB-level append-only (PLAN.md 5.1): the BEFORE UPDATE OR DELETE trigger
    raises — audit rows are never updated or deleted (ADR-5)."""
    store.append_audit(_event(1))
    with pytest.raises(DBAPIError, match="append-only"), db.begin() as conn:
        conn.execute(text("UPDATE audit_events SET run_id = 'hax' WHERE seq = 1"))
    with pytest.raises(DBAPIError, match="append-only"), db.begin() as conn:
        conn.execute(text("DELETE FROM audit_events WHERE seq = 1"))
    verify_chain(store)  # nothing changed


def test_update_delete_truncate_revoked_from_public(db: Engine) -> None:
    """The migration helper REVOKEs UPDATE/DELETE/TRUNCATE from PUBLIC (belt
    and braces with the trigger; TRUNCATE is not row-level so only the REVOKE
    covers it for non-owner roles)."""
    with db.connect() as conn:
        grants = {
            (row[0], row[1])
            for row in conn.execute(
                text(
                    "SELECT grantee, privilege_type FROM information_schema.role_table_grants "
                    "WHERE table_name = 'audit_events'"
                )
            )
        }
    assert ("PUBLIC", "UPDATE") not in grants
    assert ("PUBLIC", "DELETE") not in grants
    assert ("PUBLIC", "TRUNCATE") not in grants


def test_second_head_row_rejected(db: Engine) -> None:
    """audit_chain_head is a singleton: the CHECK + PK make a second row
    unrepresentable."""
    with pytest.raises(IntegrityError), db.begin() as conn:
        conn.execute(
            text("INSERT INTO audit_chain_head (singleton, seq, row_hash) VALUES (FALSE, 9, :h)"),
            {"h": b"\x01" * 32},
        )
    with pytest.raises(IntegrityError), db.begin() as conn:
        conn.execute(
            text("INSERT INTO audit_chain_head (singleton, seq, row_hash) VALUES (TRUE, 9, :h)"),
            {"h": b"\x01" * 32},
        )


def test_hash_length_checks(db: Engine) -> None:
    """BYTEA hashes are CHECK-constrained to exactly 32 bytes."""
    with pytest.raises(IntegrityError), db.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_events (seq, event_type, payload_json, prev_hash, row_hash,"
                " created_at) VALUES (99, 'x', '{}'::jsonb, :short, :ok, :now)"
            ),
            {"short": b"\x00" * 31, "ok": b"\x00" * 32, "now": NOW},
        )


# ---------------------------------------------------------------------------
# The append protocol.
# ---------------------------------------------------------------------------


def test_append_assigns_gapless_seq_and_links_hashes(store: PostgresStore) -> None:
    rows = [store.append_audit(_event(n)) for n in range(1, 6)]
    assert [row.seq for row in rows] == [1, 2, 3, 4, 5]
    assert rows[0].prev_hash == GENESIS_ROW_HASH
    for prev, row in itertools.pairwise(rows):
        assert row.prev_hash == prev.row_hash
    head = store.audit_head()
    assert head is not None
    assert head.seq == 5 and head.row_hash == rows[-1].row_hash


def test_append_hashes_what_it_stores(store: PostgresStore) -> None:
    """The stored row_hash equals the SDK recomputation over the STORED columns
    — including created_at round-tripped through TIMESTAMPTZ (the hashed and
    stored timestamp are the same value, PLAN.md 5.2)."""
    appended = store.append_audit(_event(7))
    stored = next(iter(store.iter_audit(appended.seq)))
    assert stored.created_at.astimezone(UTC) == (NOW + timedelta(seconds=7))
    recomputed = compute_row_hash(
        stored.prev_hash,
        seq=stored.seq,
        run_id=stored.run_id,
        action_type=stored.action_type,
        event_type=stored.event_type,
        created_at=stored.created_at,
        payload=stored.payload,
    )
    assert recomputed == stored.row_hash == appended.row_hash


def test_append_stamps_created_at_with_store_clock_when_absent(
    clock_store: PostgresStore,
) -> None:
    """AuditEvent.created_at=None -> the store's injectable now_fn stamps it;
    the stamped value is hashed AND stored (never DEFAULT now())."""
    row = clock_store.append_audit(AuditEvent(event_type="e", payload={"a": 1}))
    assert row.created_at == datetime(2026, 7, 3, 12, 0, 0, tzinfo=UTC)  # the FakeClock epoch
    verify_chain(clock_store)


def test_append_rejects_non_canonical_payload_before_anything_is_durable(
    store: PostgresStore,
) -> None:
    """A payload outside the airlock-canon-1 domain (a float) fails the append
    with CanonicalizationError and leaves the chain untouched."""
    head_before = store.audit_head()
    with pytest.raises(CanonicalizationError, match="float"):
        store.append_audit(AuditEvent(event_type="e", payload={"amount": 12.5}))
    assert store.audit_head() == head_before
    verify_chain(store)


def test_append_rejects_naive_created_at(store: PostgresStore) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        store.append_audit(
            AuditEvent(event_type="e", payload={}, created_at=datetime(2026, 7, 6, 12, 0, 0))
        )


def test_append_without_schema_is_a_loud_error(store: PostgresStore, db: Engine) -> None:
    """Appending against a database whose audit schema is missing names
    ensure_schema rather than failing obscurely."""
    with db.begin() as conn:
        conn.execute(text("DELETE FROM audit_chain_head"))
    with pytest.raises(AirlockError, match="ensure_schema"):
        store.append_audit(_event(1))


# ---------------------------------------------------------------------------
# verify_chain: green paths.
# ---------------------------------------------------------------------------


def test_chain_verifies_after_a_burst_of_mixed_events(store: PostgresStore) -> None:
    _append_burst(store, 25)
    report = verify_chain(store)
    assert report.rows_verified == 26  # genesis + 25
    assert report.from_seq == 0
    assert report.head_seq == 25
    head = store.audit_head()
    assert head is not None and report.head_hash == head.row_hash


def test_checkpoint_verification_is_o_delta(store: PostgresStore) -> None:
    """An externally-noted (seq, row_hash) pair anchors a delta-only pass."""
    _append_burst(store, 10)
    checkpoint = store.audit_head()
    assert checkpoint is not None
    _append_burst_more(store, 11, 20)
    report = verify_chain(store, from_seq=checkpoint.seq, from_hash=checkpoint.row_hash)
    assert report.from_seq == checkpoint.seq
    assert report.rows_verified == 11  # the checkpoint row + the 10 appended after
    assert report.head_seq == 20


def _append_burst_more(store: PostgresStore, start: int, end: int) -> None:
    for n in range(start, end + 1):
        store.append_audit(_event(n))


def test_checkpoint_with_wrong_hash_fails_at_the_checkpoint(store: PostgresStore) -> None:
    _append_burst(store, 3)
    with pytest.raises(AuditChainError) as excinfo:
        verify_chain(store, from_seq=2, from_hash=b"\x42" * 32)
    assert excinfo.value.seq == 2


def test_checkpoint_beyond_head_fails(store: PostgresStore) -> None:
    _append_burst(store, 2)
    with pytest.raises(AuditChainError) as excinfo:
        verify_chain(store, from_seq=99, from_hash=b"\x42" * 32)
    assert excinfo.value.seq == 99


def test_checkpoint_args_must_come_together(store: PostgresStore) -> None:
    with pytest.raises(ValueError, match="together"):
        verify_chain(store, from_seq=1)
    with pytest.raises(ValueError, match="together"):
        verify_chain(store, from_hash=b"\x00" * 32)
    with pytest.raises(ValueError, match="32"):
        verify_chain(store, from_seq=1, from_hash=b"\x00" * 8)


# ---------------------------------------------------------------------------
# The tamper battery: ANY mutation is detected, at the RIGHT seq.
# ---------------------------------------------------------------------------


def test_tamper_payload_detected(store: PostgresStore, db: Engine) -> None:
    _append_burst(store, 5)
    with _tamper(db), db.begin() as conn:
        conn.execute(
            text("UPDATE audit_events SET payload_json = :p WHERE seq = 3"),
            {"p": '{"n": 3, "note": "forged", "money": {"amount": "999", "currency": "EUR"}}'},
        )
    _assert_verify_fails_at(store, 3)


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("run_id", "'forged_run'"),
        ("action_type", "'forged.action'"),
        ("event_type", "'forged_type'"),
        ("created_at", "created_at + interval '1 second'"),
        ("run_id", "NULL"),
    ],
)
def test_tamper_any_envelope_column_detected(
    store: PostgresStore, db: Engine, column: str, value: str
) -> None:
    """Every envelope column is covered by the hash — mutating ANY of them
    (including nulling one out or shifting the timestamp) breaks seq 2."""
    _append_burst(store, 4)
    with _tamper(db), db.begin() as conn:
        conn.execute(text(f"UPDATE audit_events SET {column} = {value} WHERE seq = 2"))
    _assert_verify_fails_at(store, 2)


def test_tamper_row_hash_detected(store: PostgresStore, db: Engine) -> None:
    _append_burst(store, 4)
    with _tamper(db), db.begin() as conn:
        conn.execute(
            text("UPDATE audit_events SET row_hash = :h WHERE seq = 2"), {"h": b"\x13" * 32}
        )
    # Recomputation catches the forged hash on row 2 itself.
    _assert_verify_fails_at(store, 2)


def test_tamper_prev_hash_detected(store: PostgresStore, db: Engine) -> None:
    _append_burst(store, 4)
    with _tamper(db), db.begin() as conn:
        conn.execute(
            text("UPDATE audit_events SET prev_hash = :h WHERE seq = 3"), {"h": b"\x13" * 32}
        )
    # The link from row 2 to row 3 no longer holds.
    _assert_verify_fails_at(store, 3)


def test_recomputed_consistent_forgery_still_breaks_the_link(
    store: PostgresStore, db: Engine
) -> None:
    """A smarter attacker recomputes a SELF-CONSISTENT row_hash for the forged
    row. The row verifies in isolation — but the NEXT row's prev_hash no longer
    matches, so the chain still catches it one link later."""
    _append_burst(store, 5)
    forged_payload: dict[str, JsonValue] = {"n": 3, "note": "forged"}
    rows = {row.seq: row for row in store.iter_audit(0)}
    forged_hash = compute_row_hash(
        rows[3].prev_hash,
        seq=3,
        run_id=rows[3].run_id,
        action_type=rows[3].action_type,
        event_type=rows[3].event_type,
        created_at=rows[3].created_at,
        payload=forged_payload,
    )
    with _tamper(db), db.begin() as conn:
        conn.execute(
            text("UPDATE audit_events SET payload_json = :p, row_hash = :h WHERE seq = 3"),
            {"p": '{"n": 3, "note": "forged"}', "h": forged_hash},
        )
    _assert_verify_fails_at(store, 4)


def test_deleted_middle_row_detected_as_gap(store: PostgresStore, db: Engine) -> None:
    _append_burst(store, 5)
    with _tamper(db), db.begin() as conn:
        conn.execute(text("DELETE FROM audit_events WHERE seq = 3"))
    error = _assert_verify_fails_at(store, 4)
    assert "gap" in str(error)


def test_truncated_tail_detected_via_head_mismatch(store: PostgresStore, db: Engine) -> None:
    """Deleting the LAST rows leaves a self-consistent prefix — only the head
    match catches it (the reason audit_chain_head is part of verification)."""
    _append_burst(store, 5)
    with _tamper(db), db.begin() as conn:
        conn.execute(text("DELETE FROM audit_events WHERE seq >= 4"))
    error = _assert_verify_fails_at(store, 3)
    assert "head" in str(error)


def test_swapped_rows_detected(store: PostgresStore, db: Engine) -> None:
    """Swapping two rows' payloads (a reorder of history) breaks recomputation
    at the FIRST swapped position."""
    _append_burst(store, 5)
    with _tamper(db), db.begin() as conn:
        conn.execute(
            text(
                "UPDATE audit_events a SET payload_json = b.payload_json"
                " FROM audit_events b WHERE a.seq = 2 AND b.seq = 4"
            )
        )
        conn.execute(
            text("UPDATE audit_events SET payload_json = :p WHERE seq = 4"),
            {"p": '{"n": 2, "note": "event-2", "money": {"amount": "12.5", "currency": "EUR"}}'},
        )
    _assert_verify_fails_at(store, 2)


def test_tampered_head_detected(store: PostgresStore, db: Engine) -> None:
    _append_burst(store, 3)
    with db.begin() as conn:  # the head table has no trigger; the chain still catches it
        conn.execute(text("UPDATE audit_chain_head SET row_hash = :h"), {"h": b"\x99" * 32})
    error = _assert_verify_fails_at(store, 3)
    assert "head" in str(error)


def test_tampered_genesis_detected(store: PostgresStore, db: Engine) -> None:
    """The genesis row is a frozen constant: any deviation fails at seq 0."""
    _append_burst(store, 2)
    with _tamper(db), db.begin() as conn:
        conn.execute(
            text("UPDATE audit_events SET payload_json = :p WHERE seq = 0"),
            {"p": '{"chain": "evil-chain", "canon": "airlock-canon-1"}'},
        )
    _assert_verify_fails_at(store, 0)


def test_deleted_genesis_detected(store: PostgresStore, db: Engine) -> None:
    _append_burst(store, 2)
    with _tamper(db), db.begin() as conn:
        conn.execute(text("DELETE FROM audit_events WHERE seq = 0"))
    _assert_verify_fails_at(store, 1)


def test_empty_chain_is_an_error(store: PostgresStore, db: Engine) -> None:
    with _tamper(db), db.begin() as conn:
        conn.execute(text("DELETE FROM audit_events"))
    _assert_verify_fails_at(store, 0)


# ---------------------------------------------------------------------------
# Hash-rule unit properties.
# ---------------------------------------------------------------------------


def test_genesis_row_hash_is_a_frozen_constant() -> None:
    """The genesis constant is reproducible from the documented envelope alone
    — pinned here byte-for-byte so it can never drift silently."""
    assert (
        compute_row_hash(
            ZERO_HASH,
            seq=0,
            run_id=None,
            action_type=None,
            event_type="genesis",
            created_at=datetime(1970, 1, 1, tzinfo=UTC),
            payload={"chain": "airlock-audit-v1", "canon": "airlock-canon-1"},
        )
        == GENESIS_ROW_HASH
    )
    assert len(GENESIS_ROW_HASH) == 32
    # Independent recomputation, straight from the /contracts/canonical-json.md
    # section 7 wording (no airlock.audit helpers):
    import hashlib

    envelope_bytes = (
        b'{"action_type":null,"created_at":"1970-01-01T00:00:00.000000Z",'
        b'"event_type":"genesis","payload":{"canon":"airlock-canon-1",'
        b'"chain":"airlock-audit-v1"},"run_id":null,"seq":0}'
    )
    assert hashlib.sha256(b"\x00" * 32 + envelope_bytes).digest() == GENESIS_ROW_HASH


def test_compute_row_hash_rejects_bad_prev_hash_length() -> None:
    with pytest.raises(ValueError, match="32 raw bytes"):
        compute_row_hash(
            b"\x00" * 31,
            seq=1,
            run_id=None,
            action_type=None,
            event_type="e",
            created_at=NOW,
            payload={},
        )


def test_rfc3339_utc_renders_and_rejects() -> None:
    assert rfc3339_utc(datetime(2026, 7, 6, 12, 0, 0, 123, tzinfo=UTC)) == (
        "2026-07-06T12:00:00.000123Z"
    )
    # Non-UTC zones are converted to the same instant in UTC.
    from datetime import timezone

    plus_two = timezone(timedelta(hours=2))
    assert rfc3339_utc(datetime(2026, 7, 6, 14, 0, 0, tzinfo=plus_two)) == (
        "2026-07-06T12:00:00.000000Z"
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        rfc3339_utc(datetime(2026, 7, 6, 12, 0, 0))
