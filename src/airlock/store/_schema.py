"""``commit_records`` DDL, exactly per PLAN.md section 5.1.

Conventions (PLAN.md section 5): TEXT + CHECK over Postgres enums; timestamps
are SDK-supplied via the injectable ``now_fn`` — never ``DEFAULT now()``; the
CHECK value lists are GENERATED from the enums in ``airlock.types`` (the
single vocabulary source, PLAN.md section 10 point 5) and a CI test asserts
the live constraints match them.

Import-light: sqlalchemy is only imported inside ``ensure_schema`` so this
module (and the base ``airlock`` import) stays free of the postgres extra.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from airlock.types import IN_FLIGHT_LEDGER_STATES, Guarantee, LedgerState

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

__all__ = [
    "COMMIT_RECORDS_DDL",
    "DDL_STATEMENTS",
    "INFLIGHT_INDEX_DDL",
    "create_tables",
    "ensure_schema",
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

DDL_STATEMENTS: tuple[str, ...] = (COMMIT_RECORDS_DDL, INFLIGHT_INDEX_DDL)


def ensure_schema(engine: Engine) -> None:
    """Create the P1.1 ledger schema if missing. Idempotent; safe to re-run.

    Tests call this once per session; integrators call it (or run the DDL via
    their own migration tool — the statements are exposed as constants) before
    first use.
    """
    from sqlalchemy import text

    with engine.begin() as conn:
        for statement in DDL_STATEMENTS:
            conn.execute(text(statement))


#: Alias for integrators who expect the conventional name.
create_tables = ensure_schema
