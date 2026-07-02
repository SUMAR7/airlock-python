"""Schema constraints + the enum-consistency CI assertion (PLAN.md section 10, point 5).

The CHECK value lists in the live database must equal the enums in
``airlock.types`` — the single vocabulary source. These tests read the real
constraint definitions back from Postgres, so any drift (hand-edited DDL, a
stale database, a retyped list) fails CI.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from airlock.store._schema import ensure_schema
from airlock.types import IN_FLIGHT_LEDGER_STATES, Guarantee, LedgerState

NOW = datetime(2026, 7, 2, 12, 0, 0, tzinfo=UTC)


def _constraint_def(db: Engine, name: str) -> str:
    with db.connect() as conn:
        found = conn.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint"
                " WHERE conrelid = 'commit_records'::regclass AND conname = :name"
            ),
            {"name": name},
        ).scalar_one_or_none()
    assert found is not None, f"constraint {name!r} is missing"
    return str(found)


def _quoted_values(sql: str) -> list[str]:
    return re.findall(r"'([^']*)'", sql)


def test_state_check_matches_ledger_state_enum(db: Engine) -> None:
    values = _quoted_values(_constraint_def(db, "commit_records_state_check"))
    assert values == [state.value for state in LedgerState]


def test_guarantee_check_matches_guarantee_enum(db: Engine) -> None:
    values = _quoted_values(_constraint_def(db, "commit_records_guarantee_check"))
    assert values == [guarantee.value for guarantee in Guarantee]


def test_inflight_partial_index_matches_in_flight_states(db: Engine) -> None:
    with db.connect() as conn:
        indexdef = conn.execute(
            text("SELECT indexdef FROM pg_indexes WHERE indexname = 'commit_records_inflight_idx'")
        ).scalar_one_or_none()
    assert indexdef is not None, "in-flight partial index is missing"
    assert _quoted_values(str(indexdef)) == [state.value for state in IN_FLIGHT_LEDGER_STATES]


def test_terminal_states_are_the_last_four(db: Engine) -> None:
    """PLAN.md section 3.2: terminal = the last four LedgerState values."""
    states = list(LedgerState)
    assert all(not state.is_terminal for state in states[:2])
    assert all(state.is_terminal for state in states[2:])


def test_ensure_schema_is_idempotent(db: Engine) -> None:
    ensure_schema(db)
    ensure_schema(db)


def _raw_insert(db: Engine, **overrides: object) -> None:
    params: dict[str, object] = {
        "key": "schema-test",
        "action_type": "test.action",
        "state": LedgerState.PENDING.value,
        "guarantee": Guarantee.NONE.value,
        "committed_at": None,
        "now": NOW,
    }
    params.update(overrides)
    with db.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO commit_records (idempotency_key, action_type, state, guarantee,"
                " args_json, attempts, last_attempt_at, created_at, committed_at)"
                " VALUES (:key, :action_type, :state, :guarantee, '{}'::jsonb, 1,"
                " :now, :now, :committed_at)"
            ),
            params,
        )


def test_bogus_state_rejected(db: Engine) -> None:
    with pytest.raises(IntegrityError, match="commit_records_state_check"):
        _raw_insert(db, state="galloping")


def test_bogus_guarantee_rejected(db: Engine) -> None:
    with pytest.raises(IntegrityError, match="commit_records_guarantee_check"):
        _raw_insert(db, guarantee="pinky_promise")


def test_committed_requires_timestamp(db: Engine) -> None:
    with pytest.raises(IntegrityError, match="committed_iff_timestamp"):
        _raw_insert(db, state=LedgerState.COMMITTED.value, committed_at=None)


def test_timestamp_requires_committed(db: Engine) -> None:
    with pytest.raises(IntegrityError, match="committed_iff_timestamp"):
        _raw_insert(db, state=LedgerState.PENDING.value, committed_at=NOW)


def test_duplicate_key_rejected(db: Engine) -> None:
    _raw_insert(db, key="dup-key")
    with pytest.raises(IntegrityError, match="commit_records_key_uq"):
        _raw_insert(db, key="dup-key")
