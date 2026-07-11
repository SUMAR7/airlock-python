"""``commit_records`` + ``paused_runs`` + ``audit_events`` DDL, exactly per
PLAN.md section 5.1.

Conventions (PLAN.md section 5): TEXT + CHECK over Postgres enums; timestamps
are SDK-supplied via the injectable ``now_fn`` — never ``DEFAULT now()``; the
CHECK value lists are GENERATED from the enums in ``airlock.types`` (the
single vocabulary source, PLAN.md section 10 point 5) and a CI test asserts
the live constraints match them.

P2.2 adds the audit chain (ADR-5): the ``audit_events`` table (gapless ``seq``,
32-byte ``prev_hash``/``row_hash``), the ``audit_chain_head`` singleton whose
row lock serializes appenders, DB-level append-only enforcement (a BEFORE
UPDATE OR DELETE trigger that raises, plus ``REVOKE UPDATE, DELETE, TRUNCATE
... FROM PUBLIC`` in this migration helper), and the genesis row —
``seq=0``, ``prev_hash = 0x00*32``, the documented constant payload
(``airlock.audit.GENESIS_PAYLOAD``) — inserted idempotently by
:func:`ensure_schema`. Hashing stays in the SDK (``airlock.audit``); the DB
never computes a hash (PLAN.md 5.2: "the DB stays dumb").

Import-light: sqlalchemy is only imported inside ``ensure_schema`` so this
module (and the base ``airlock`` import) stays free of the postgres extra.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from airlock.types import IN_FLIGHT_LEDGER_STATES, Guarantee, LedgerState, PauseStatus

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

__all__ = [
    "AUDIT_CHAIN_HEAD_DDL",
    "AUDIT_EVENTS_DDL",
    "COMMIT_RECORDS_DDL",
    "DDL_STATEMENTS",
    "INFLIGHT_INDEX_DDL",
    "PAUSED_APPROVED_INDEX_DDL",
    "PAUSED_POLLED_INDEX_DDL",
    "PAUSED_RUNS_DDL",
    "create_tables",
    "ensure_schema",
    "seed_genesis",
]


def _sql_value_list(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


_STATE_VALUES = _sql_value_list(tuple(state.value for state in LedgerState))
_GUARANTEE_VALUES = _sql_value_list(tuple(guarantee.value for guarantee in Guarantee))
_IN_FLIGHT_VALUES = _sql_value_list(tuple(state.value for state in IN_FLIGHT_LEDGER_STATES))

COMMIT_RECORDS_DDL = f"""
CREATE TABLE IF NOT EXISTS commit_records (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    idempotency_key  TEXT        NOT NULL,
    action_type      TEXT        NOT NULL,
    state            TEXT        NOT NULL DEFAULT '{LedgerState.PENDING.value}'
                     CHECK (state IN ({_STATE_VALUES})),
    guarantee        TEXT        NOT NULL
                     CHECK (guarantee IN ({_GUARANTEE_VALUES})),
    args_json        JSONB       NOT NULL,
    downstream_key   TEXT,
    run_id           TEXT,
    result_json      JSONB,
    error_json       JSONB,
    attempts         INT         NOT NULL DEFAULT 1,
    last_attempt_at  TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    committed_at     TIMESTAMPTZ,
    CONSTRAINT commit_records_key_uq UNIQUE (idempotency_key),
    CONSTRAINT committed_iff_timestamp
        CHECK ((state = '{LedgerState.COMMITTED.value}') = (committed_at IS NOT NULL))
)
"""

INFLIGHT_INDEX_DDL = f"""
CREATE INDEX IF NOT EXISTS commit_records_inflight_idx ON commit_records (last_attempt_at)
    WHERE state IN ({_IN_FLIGHT_VALUES})
"""

# --- The durable pause (P2.3, ADR-4) — DDL exactly per PLAN.md 5.1 -----------

_PAUSE_STATUS_VALUES = _sql_value_list(tuple(status.value for status in PauseStatus))

# The status CHECK list is GENERATED from airlock.types.PauseStatus — exactly
# the ADR-4 set (proposed/approved/rejected/committed/aborted). There is NO
# 'expired' value: TTL expiry is not in ADR-4 (PLAN.md 10.9) and adding a
# status here without a PROPOSAL.md would silently unlock a sixth state.
PAUSED_RUNS_DDL = f"""
CREATE TABLE IF NOT EXISTS paused_runs (
    id                   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id               TEXT        NOT NULL,
    idempotency_key      TEXT        NOT NULL,
    approval_ref         UUID        NOT NULL,
    approval_id          TEXT,
    action_type          TEXT        NOT NULL,
    serialized_state     JSONB       NOT NULL,
    state_version        INT         NOT NULL DEFAULT 1,
    status               TEXT        NOT NULL DEFAULT '{PauseStatus.PROPOSED.value}'
                         CHECK (status IN ({_PAUSE_STATUS_VALUES})),
    approved_action_json JSONB,
    decided_by           TEXT,
    decided_by_display   TEXT,
    decided_at           TIMESTAMPTZ,
    decision_latency_ms  INT,
    created_at           TIMESTAMPTZ NOT NULL,
    resolved_at          TIMESTAMPTZ,
    CONSTRAINT paused_runs_key_uq UNIQUE (idempotency_key),
    CONSTRAINT paused_runs_ref_uq UNIQUE (approval_ref)
)
"""

# Supports the reconciler's stale-APPROVED sweep (PLAN.md 4.2): approved rows
# whose decision landed but whose commit never did. Partial, like the ledger's
# in-flight index — resolved rows never re-enter the scan.
PAUSED_APPROVED_INDEX_DDL = f"""
CREATE INDEX IF NOT EXISTS paused_runs_approved_idx ON paused_runs (decided_at)
    WHERE status = '{PauseStatus.APPROVED.value}'
"""

# Supports the reconciler's backstop-poll sweep (P3.4, PLAN.md 6.2): still-
# proposed runs carrying a hosted approval_id whose decided webhook never
# landed. Partial like the approved index — decided rows never re-enter it.
PAUSED_POLLED_INDEX_DDL = f"""
CREATE INDEX IF NOT EXISTS paused_runs_polled_idx ON paused_runs (created_at)
    WHERE status = '{PauseStatus.PROPOSED.value}' AND approval_id IS NOT NULL
"""

# --- The audit chain (P2.2, ADR-5) — DDL exactly per PLAN.md 5.1 -------------

AUDIT_EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS audit_events (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    seq          BIGINT      NOT NULL UNIQUE,
    run_id       TEXT,
    action_type  TEXT,
    event_type   TEXT        NOT NULL,
    payload_json JSONB       NOT NULL,
    prev_hash    BYTEA       NOT NULL CHECK (octet_length(prev_hash) = 32),
    row_hash     BYTEA       NOT NULL CHECK (octet_length(row_hash) = 32),
    created_at   TIMESTAMPTZ NOT NULL
)
"""

AUDIT_CHAIN_HEAD_DDL = """
CREATE TABLE IF NOT EXISTS audit_chain_head (
    singleton BOOL PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    seq BIGINT NOT NULL, row_hash BYTEA NOT NULL CHECK (octet_length(row_hash) = 32)
)
"""

# Append-only enforced IN THE DB (PLAN.md 5.1): the trigger raises on any
# UPDATE or DELETE regardless of role, so even the table owner cannot rewrite
# history through the normal SQL surface. (The owner can still DISABLE the
# trigger — a database owner is always able to defeat in-database controls —
# which is exactly why tamper EVIDENCE is the hash chain's job, not the
# trigger's: airlock.audit.verify_chain catches what the trigger cannot stop.)
AUDIT_APPEND_ONLY_FUNCTION_DDL = """
CREATE OR REPLACE FUNCTION airlock_audit_events_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only (ADR-5): % is forbidden', TG_OP;
END
$$
"""

AUDIT_APPEND_ONLY_TRIGGER_DDL = """
CREATE OR REPLACE TRIGGER audit_events_append_only
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION airlock_audit_events_append_only()
"""

# Belt-and-braces with the trigger (PLAN.md 5.1): strip UPDATE/DELETE/TRUNCATE
# from every role that isn't the table owner. (TRUNCATE is not row-level, so
# the trigger cannot catch it; for non-owner roles this REVOKE does.)
AUDIT_REVOKE_DDL = """
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM PUBLIC
"""

DDL_STATEMENTS: tuple[str, ...] = (
    COMMIT_RECORDS_DDL,
    INFLIGHT_INDEX_DDL,
    PAUSED_RUNS_DDL,
    PAUSED_APPROVED_INDEX_DDL,
    PAUSED_POLLED_INDEX_DDL,
    AUDIT_EVENTS_DDL,
    AUDIT_CHAIN_HEAD_DDL,
    AUDIT_APPEND_ONLY_FUNCTION_DDL,
    AUDIT_APPEND_ONLY_TRIGGER_DDL,
    AUDIT_REVOKE_DDL,
)

# Idempotent genesis seeding (PLAN.md 5.1/5.2): the genesis row (seq=0,
# prev_hash = 32 zero bytes, the documented constant payload) and the chain
# head pointing at it. ON CONFLICT DO NOTHING on both, so concurrent/repeated
# ensure_schema calls are safe and an existing chain is never touched. The
# genesis hash is computed in the SDK (airlock.audit) and bound as a
# parameter — the DB never hashes.
_GENESIS_INSERT_SQL = """
INSERT INTO audit_events
    (seq, run_id, action_type, event_type, payload_json, prev_hash, row_hash, created_at)
VALUES
    (0, NULL, NULL, :event_type, CAST(:payload AS JSONB), :prev_hash, :row_hash, :created_at)
ON CONFLICT (seq) DO NOTHING
"""

_HEAD_INSERT_SQL = """
INSERT INTO audit_chain_head (singleton, seq, row_hash)
VALUES (TRUE, 0, :row_hash)
ON CONFLICT (singleton) DO NOTHING
"""


def seed_genesis(engine: Engine) -> None:
    """Insert the genesis row + chain head if absent (idempotent).

    Split out of :func:`ensure_schema` so tests that reset the audit tables
    can re-seed without re-running DDL; integrators never call it directly.
    """
    from sqlalchemy import text

    from airlock._canonical import canonical_json
    from airlock.audit import (
        GENESIS_CREATED_AT,
        GENESIS_EVENT_TYPE,
        GENESIS_PAYLOAD,
        GENESIS_ROW_HASH,
        ZERO_HASH,
    )

    with engine.begin() as conn:
        conn.execute(
            text(_GENESIS_INSERT_SQL),
            {
                "event_type": GENESIS_EVENT_TYPE,
                "payload": canonical_json(GENESIS_PAYLOAD),
                "prev_hash": ZERO_HASH,
                "row_hash": GENESIS_ROW_HASH,
                "created_at": GENESIS_CREATED_AT,
            },
        )
        conn.execute(text(_HEAD_INSERT_SQL), {"row_hash": GENESIS_ROW_HASH})


def ensure_schema(engine: Engine) -> None:
    """Create the ledger + audit schema if missing. Idempotent; safe to re-run.

    Tests call this once per session; integrators call it (or run the DDL via
    their own migration tool — the statements are exposed as constants, and
    the genesis seed is :func:`seed_genesis`) before first use.
    """
    from sqlalchemy import text

    with engine.begin() as conn:
        for statement in DDL_STATEMENTS:
            conn.execute(text(statement))
    seed_genesis(engine)


#: Alias for integrators who expect the conventional name.
create_tables = ensure_schema
