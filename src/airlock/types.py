"""Shared vocabulary for the commit core (PLAN.md section 3.2).

This module is THE single source for enum vocabularies (PLAN.md section 10,
point 5): the ``commit_records`` DDL CHECK lists in ``airlock.store._schema``
are *generated from* these enums, and a CI test asserts the live database
constraints match them. Never retype these value lists anywhere else —
divergence between the API, the DDL, and (later) the event schema was the
single biggest failure mode found in design review.

P1.1 defined the commit-ledger types; P1.2 adds ``Verification`` (the probe
vocabulary). Later phases add the rest of the section 3.2 table (Decision,
PauseStatus, Reversibility, BlastRadius, Money) to this same module.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, JsonValue

__all__ = [
    "IN_FLIGHT_LEDGER_STATES",
    "TERMINAL_LEDGER_STATES",
    "Claim",
    "CommitOutcome",
    "CommitRecord",
    "Guarantee",
    "LedgerState",
    "Verification",
]


class Guarantee(StrEnum):
    """How exactly-once is achievable for a side effect (ADR-2).

    ``none`` means the downstream is neither idempotent nor verifiable, which
    puts the action in at-most-once mode: it is never blind-retried.
    """

    DOWNSTREAM_IDEMPOTENT = "downstream_idempotent"
    VERIFIABLE = "verifiable"
    NONE = "none"


class Verification(StrEnum):
    """Answer of a post-verify / reconciliation probe: "did this effect happen?"

    - ``present`` — the effect provably took place downstream.
    - ``absent``  — the effect provably did NOT take place.
    - ``unknown`` — the probe cannot prove either way; the honest non-answer.
      The row is never blind-retried on ``unknown`` (ADR-2).

    Used by ``Effect.verify`` (P1.2) and the reconciler's recovery table
    (P1.3, PLAN.md section 4.2). P2.2's ``action_event.v1`` ``post_verify``
    field maps onto this vocabulary; single-source enum rules apply.
    """

    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class LedgerState(StrEnum):
    """Lifecycle of a ``commit_records`` row. Terminal states never change.

    Terminal-state semantics (PLAN.md section 3.2):

    - ``aborted``  — we chose not to execute (precondition failure, config).
    - ``failed``   — executed and confirmed not to have taken effect.
    - ``unknown``  — may have executed, cannot prove either way; never
      retried, loudly audited.

    The ``executing`` marker is what makes crash recovery honest: it commits
    durably *before* the effect is invoked, so a ``pending`` row provably
    never started its effect (PLAN.md section 10, point 1).
    """

    PENDING = "pending"
    EXECUTING = "executing"
    COMMITTED = "committed"
    ABORTED = "aborted"
    FAILED = "failed"
    UNKNOWN = "unknown"

    @property
    def is_terminal(self) -> bool:
        return self in TERMINAL_LEDGER_STATES


#: The four terminal states — a terminal row never transitions again (invariant I5).
TERMINAL_LEDGER_STATES: frozenset[LedgerState] = frozenset(
    {
        LedgerState.COMMITTED,
        LedgerState.ABORTED,
        LedgerState.FAILED,
        LedgerState.UNKNOWN,
    }
)

#: In-flight states, in DDL order — the partial-index WHERE list is generated from this.
IN_FLIGHT_LEDGER_STATES: tuple[LedgerState, ...] = (
    LedgerState.PENDING,
    LedgerState.EXECUTING,
)


class CommitRecord(BaseModel):
    """One row of the ``commit_records`` ledger (DDL in PLAN.md section 5.1)."""

    model_config = ConfigDict(frozen=True)

    id: int
    idempotency_key: str
    action_type: str
    state: LedgerState
    guarantee: Guarantee
    args_json: dict[str, JsonValue]
    downstream_key: str | None = None
    run_id: str | None = None
    result_json: JsonValue = None
    error_json: JsonValue = None
    attempts: int  # doubles as the ownership epoch (PLAN.md section 4.2)
    last_attempt_at: datetime
    created_at: datetime
    committed_at: datetime | None = None


class Claim(BaseModel):
    """Result of ``Store.claim``: did this caller win the row, and the row itself.

    ``won=True``  — the INSERT landed; ``record`` is the fresh ``pending`` row
    and ``record.attempts`` is the caller's ownership epoch.
    ``won=False`` — another caller holds (or held) the key; ``record`` is the
    existing row, which may be in-flight or terminal.
    """

    model_config = ConfigDict(frozen=True)

    won: bool
    record: CommitRecord


class CommitOutcome(BaseModel):
    """Terminal outcome of a ``commit_once`` call.

    ``state`` is always one of ``TERMINAL_LEDGER_STATES``. Duplicate calls for
    the same key receive the identical outcome recorded by whichever call won
    the claim (SPEC.md section 5, rows 1-2).

    ``guarantee`` is the ADR-2 guarantee the action ran under, read back from
    the ledger row — ``none`` means the action operated at-most-once and the
    caller is being told so (SPEC.md section 5, scenario 7: the degradation is
    caller-visible, never hidden).
    """

    model_config = ConfigDict(frozen=True)

    key: str
    state: LedgerState
    guarantee: Guarantee
    result: JsonValue = None
    error: JsonValue = None
