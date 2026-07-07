"""Shared vocabulary for the commit core (PLAN.md section 3.2).

This module is THE single source for enum vocabularies (PLAN.md section 10,
point 5): the ``commit_records`` DDL CHECK lists in ``airlock.store._schema``
are *generated from* these enums, and a CI test asserts the live database
constraints match them. Never retype these value lists anywhere else —
divergence between the API, the DDL, and (later) the event schema was the
single biggest failure mode found in design review.

P1.1 defined the commit-ledger types; P1.2 adds ``Verification`` (the probe
vocabulary); P2.1 adds the policy vocabulary (``Decision``, ``Reversibility``,
``BlastRadius``, ``Money``); P2.2 adds the event vocabulary
(``ActionOutcome``, ``HumanDecision``) and the audit-chain models
(``AuditEvent``/``AuditRow``/``AuditHead``); P2.3 adds the pause vocabulary
(``PauseStatus`` — exactly the ADR-4 state machine — plus ``PausedRun``,
``PauseClaim`` and ``ApprovalDecision``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, JsonValue, field_validator

__all__ = [
    "BLAST_RADIUS_ORDER",
    "IN_FLIGHT_LEDGER_STATES",
    "OPEN_PAUSE_STATUSES",
    "PAUSE_TRANSITIONS",
    "RESOLVED_PAUSE_STATUSES",
    "TERMINAL_LEDGER_STATES",
    "ActionOutcome",
    "ApprovalDecision",
    "AuditEvent",
    "AuditHead",
    "AuditRow",
    "BlastRadius",
    "Claim",
    "CommitOutcome",
    "CommitRecord",
    "Decision",
    "Guarantee",
    "HumanDecision",
    "LedgerState",
    "Money",
    "PauseClaim",
    "PauseStatus",
    "PausedRun",
    "Reversibility",
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


# ---------------------------------------------------------------------------
# Policy vocabulary (P2.1) — the auto/gate/deny decision inputs and output.
#
# These are the SAME single-sourced types that will appear in the P2.2
# ``action_event.v1`` schema, the hosted ``risk_meta`` (PLAN.md 5.3), and the
# wire contract (PLAN.md 6.1). One definition, never forked (PLAN.md 10.5).
# ---------------------------------------------------------------------------


class Decision(StrEnum):
    """The policy verdict for one guarded call (ADR-6, PLAN.md 3.2).

    - ``auto``  — safe to commit inline (``commit_once``); the ~95% hot path.
    - ``gate``  — pause for human approval (the durable pause is P2.3; in P2.1
      a GATE decision surfaces cleanly without executing — see ``guard.py``).
    - ``deny``  — block; no side effect, an audit record, and ``ActionDenied``.

    The verdict is produced by a :class:`~airlock.policy.PolicyBackend` in pure,
    in-process, I/O-free Python (ADR-3 + the hot-path rule, SPEC.md 3).
    """

    AUTO = "auto"
    GATE = "gate"
    DENY = "deny"


class Reversibility(StrEnum):
    """Whether an action's effect can be undone (PLAN.md 3.2).

    - ``reversible``   — the effect can be rolled back (e.g. a draft edit).
    - ``irreversible`` — the effect cannot be undone (e.g. a wire transfer);
      the conservative default for a guarded action (PLAN.md 3.3).
    - ``unknown``      — the integrator has not classified it; treated as the
      cautious end by any policy that filters on reversibility.
    """

    REVERSIBLE = "reversible"
    IRREVERSIBLE = "irreversible"
    UNKNOWN = "unknown"


class BlastRadius(StrEnum):
    """How wide an action's impact is — an ORDERED enum (PLAN.md 3.2).

    ``low < medium < high``. Never an int, never a free string (PLAN.md 3.2):
    a fixed, ordered vocabulary so a ``max_blast_radius`` threshold means the
    same thing in the native ``Policy``, a future Rego backend, the event
    schema, and the hosted risk model. Order is via :data:`BLAST_RADIUS_ORDER`
    and the rich-comparison operators below (``StrEnum`` compares as ``str``
    otherwise, which is alphabetical — ``high < low < medium`` — and wrong).
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def _rank(self) -> int:
        return BLAST_RADIUS_ORDER[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, BlastRadius):
            return NotImplemented
        return self._rank < other._rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, BlastRadius):
            return NotImplemented
        return self._rank <= other._rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, BlastRadius):
            return NotImplemented
        return self._rank > other._rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, BlastRadius):
            return NotImplemented
        return self._rank >= other._rank


#: The severity order of :class:`BlastRadius` (low=0 < medium=1 < high=2). The
#: single source for the comparison operators above and any threshold check.
BLAST_RADIUS_ORDER: dict[BlastRadius, int] = {
    BlastRadius.LOW: 0,
    BlastRadius.MEDIUM: 1,
    BlastRadius.HIGH: 2,
}


class Money(BaseModel):
    """An amount of money — ``{amount: decimal-string, currency: ISO-4217}``.

    **Never a JSON float, anywhere** (PLAN.md 3.2 / 5.2): floats cannot
    represent decimal amounts exactly and format differently across languages,
    which would fork idempotency keys and audit hashes between SDKs. ``amount``
    is a canonical decimal string produced by
    :func:`airlock._canonical.decimal_string`; pass a :class:`decimal.Decimal`
    (or a decimal string / int) to the constructor and it is normalized on the
    way in, so ``Money(amount=Decimal("12.50"), ...)`` and
    ``Money(amount="12.5", ...)`` are equal.

    ``currency`` is an ISO-4217 alphabetic code, upper-cased and length-checked
    (three A-Z letters); it is NOT validated against the live ISO register (no
    I/O on the hot path, ADR-3) — a typo'd but well-formed code is the
    integrator's responsibility.

    Cross-currency comparison is deliberately undefined: two ``Money`` values in
    different currencies are not ordered (there is no I/O-free exchange rate on
    the hot path). :class:`~airlock.policy.Rule`'s ``max_cost`` therefore
    constrains a cost only when the currencies match — documented there.
    """

    model_config = ConfigDict(frozen=True)

    amount: str
    currency: str

    @field_validator("amount", mode="before")
    @classmethod
    def _canonical_amount(cls, value: object) -> str:
        # Lazy import to avoid a circular import at module load: _canonical
        # imports airlock.errors, which imports this module (airlock.types).
        from airlock._canonical import decimal_string

        if isinstance(value, Decimal):
            return decimal_string(value)
        if isinstance(value, bool):  # bool subclasses int; reject it explicitly
            raise ValueError("Money amount must be a decimal string or Decimal, not a bool")
        if isinstance(value, int):
            return decimal_string(Decimal(value))
        if isinstance(value, str):
            try:
                parsed = Decimal(value)
            except InvalidOperation:
                raise ValueError(f"Money amount {value!r} is not a valid decimal string") from None
            if not parsed.is_finite():
                raise ValueError(f"Money amount {value!r} must be finite (no NaN/Infinity)")
            return decimal_string(parsed)
        # Floats land here and are refused on principle (already lost precision).
        raise ValueError(
            f"Money amount must be a decimal string or Decimal, got {type(value).__name__}; "
            "floats are forbidden (they cannot represent decimal amounts exactly)"
        )

    @field_validator("currency")
    @classmethod
    def _normalize_currency(cls, value: str) -> str:
        code = value.strip().upper()
        if len(code) != 3 or not code.isalpha() or not code.isascii():
            raise ValueError(
                f"currency {value!r} is not a 3-letter ISO-4217 alphabetic code (e.g. 'USD')"
            )
        return code

    def as_decimal(self) -> Decimal:
        """The amount as a :class:`decimal.Decimal` (for comparisons/arithmetic)."""
        return Decimal(self.amount)


# ---------------------------------------------------------------------------
# Event vocabulary (P2.2) — the ``action_event.v1`` enums (PLAN.md 6.3).
#
# Same single-source rule (PLAN.md 10.5): the JSON-schema enum lists in
# /contracts/events/action_event.v1.json are CI-asserted against these.
# ---------------------------------------------------------------------------


class ActionOutcome(StrEnum):
    """The ``outcome`` field of ``action_event.v1`` (PLAN.md 6.3).

    The four terminal ledger states plus ``denied`` (a policy DENY blocks the
    call before any ledger claim exists, so it is an event outcome but never a
    ledger state). The first four values are asserted equal to
    :data:`TERMINAL_LEDGER_STATES` by a CI test — one vocabulary, never forked.
    """

    COMMITTED = "committed"
    ABORTED = "aborted"
    FAILED = "failed"
    UNKNOWN = "unknown"
    DENIED = "denied"


class HumanDecision(StrEnum):
    """The ``human_decision`` field of ``action_event.v1`` (PLAN.md 6.3).

    ``null`` on the event means no human was involved (auto/deny paths, and
    every P2.2 event — the approval flow that populates this lands in P2.3).
    """

    APPROVED = "approved"
    REJECTED = "rejected"


# ---------------------------------------------------------------------------
# Audit models (P2.2, ADR-5) — the hash-chained ``audit_events`` rows.
# Hash computation/verification lives in ``airlock.audit``; these are the
# import-light data shapes (pydantic only) the Store protocol speaks.
# ---------------------------------------------------------------------------


class AuditEvent(BaseModel):
    """One audit event to append to the chain (the ``Store.append_audit`` input).

    ``seq``, ``prev_hash`` and ``row_hash`` are assigned by the append protocol
    under the chain-head lock (PLAN.md 5.1/5.2) — a caller never supplies them.
    ``created_at`` is SDK-supplied (never ``DEFAULT now()``); when ``None`` the
    store stamps it with its own injectable ``now_fn`` at append time, and the
    STAMPED value is both hashed and stored (the hashed ``created_at`` and the
    stored column are the same instant, PLAN.md 5.2). A naive (tz-less)
    ``created_at`` is rejected at hash time (``airlock.audit``).

    ``payload`` must lie in the ``airlock-canon-1`` value domain (no floats,
    no over-bound ints, ... — /contracts/canonical-json.md): it is canonicalized
    for hashing at append time, and a value outside the domain fails the append
    BEFORE anything is durable.
    """

    model_config = ConfigDict(frozen=True)

    event_type: str
    payload: dict[str, JsonValue]
    run_id: str | None = None
    action_type: str | None = None
    created_at: datetime | None = None


class AuditRow(BaseModel):
    """One appended row of the ``audit_events`` chain (PLAN.md 5.1).

    Rows are append-only (ADR-5): never updated, never deleted — enforced in
    the DB by a BEFORE UPDATE/DELETE trigger plus REVOKE, and tamper-evident
    via the hash chain (``airlock.audit.verify_chain``).
    """

    model_config = ConfigDict(frozen=True)

    id: int
    seq: int
    event_type: str
    payload: dict[str, JsonValue]
    prev_hash: bytes
    row_hash: bytes
    created_at: datetime
    run_id: str | None = None
    action_type: str | None = None


class AuditHead(BaseModel):
    """The ``audit_chain_head`` singleton: O(1) tail lookup (PLAN.md 5.1).

    Its row lock serializes appenders across processes; ``seq``/``row_hash``
    always mirror the last appended row.
    """

    model_config = ConfigDict(frozen=True)

    seq: int
    row_hash: bytes


# ---------------------------------------------------------------------------
# Pause vocabulary (P2.3, ADR-4) — the durable-pause state machine.
#
# Same single-source rule (PLAN.md 10.5): the ``paused_runs.status`` DDL CHECK
# list is GENERATED from ``PauseStatus`` and CI-asserted against it. The state
# machine is LOCKED by ADR-4: ``proposed -> approved|rejected ->
# committed|aborted`` — there is NO TTL/'expired' state in v1 (PLAN.md 10.9;
# adding one goes through PROPOSAL.md, never here).
# ---------------------------------------------------------------------------


class PauseStatus(StrEnum):
    """Lifecycle of a ``paused_runs`` row — exactly the ADR-4 machine.

    - ``proposed``  — persisted, awaiting a human decision.
    - ``approved``  — a human approved; the commit may not have landed yet
      (this is the state the ensure-committed core / the reconciler sweep
      exists for — an approved run is NEVER stranded, PLAN.md 4.3).
    - ``rejected``  — a human rejected; driven to ``aborted`` by
      ``apply_decision`` (rejected is an intermediate state, not terminal).
    - ``committed`` — the effect committed exactly once (terminal).
    - ``aborted``   — we chose not to execute: rejection, or preconditions
      violated at commit time (terminal).
    """

    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    COMMITTED = "committed"
    ABORTED = "aborted"

    @property
    def is_resolved(self) -> bool:
        return self in RESOLVED_PAUSE_STATUSES


#: The ADR-4 DAG — the ONLY legal status transitions, single-sourced here:
#: the store's guarded CAS refuses any pair not in this set, and the property
#: machine's I6 invariant asserts observed history never leaves it.
PAUSE_TRANSITIONS: frozenset[tuple[PauseStatus, PauseStatus]] = frozenset(
    {
        (PauseStatus.PROPOSED, PauseStatus.APPROVED),
        (PauseStatus.PROPOSED, PauseStatus.REJECTED),
        (PauseStatus.APPROVED, PauseStatus.COMMITTED),
        (PauseStatus.APPROVED, PauseStatus.ABORTED),
        (PauseStatus.REJECTED, PauseStatus.ABORTED),
    }
)

#: Terminal pause statuses — a resolved run never transitions again.
RESOLVED_PAUSE_STATUSES: frozenset[PauseStatus] = frozenset(
    {PauseStatus.COMMITTED, PauseStatus.ABORTED}
)

#: Non-terminal statuses, in DDL/lifecycle order. A re-gate of the same action
#: ATTACHES to a run in one of these (PLAN.md 4.3: collide-and-dedupe).
OPEN_PAUSE_STATUSES: tuple[PauseStatus, ...] = (
    PauseStatus.PROPOSED,
    PauseStatus.APPROVED,
    PauseStatus.REJECTED,
)


class PausedRun(BaseModel):
    """One row of ``paused_runs`` (DDL exactly per PLAN.md 5.1).

    ``approval_ref`` is SDK-minted and is THE only cross-boundary join key
    (PLAN.md 6.1); ``approval_id`` is reserved for the P3.x backstop poll and
    stays ``None`` until a hosted control plane assigns one.
    ``serialized_state`` is canonical JSON (never pickle): the arg_map, the
    propose-time precondition snapshot, and the resolved risk metadata —
    everything a FRESH process needs to rehydrate the call (scenario 6).
    ``state_version`` gates rehydration: an unknown version is refused loudly,
    never misparsed. ``approved_action_json`` is RESERVED for
    edit-before-approve and is always ``None`` in v1 (PLAN.md 10.9).
    """

    model_config = ConfigDict(frozen=True)

    id: int
    run_id: str
    idempotency_key: str
    approval_ref: str
    action_type: str
    serialized_state: dict[str, JsonValue]
    state_version: int
    status: PauseStatus
    approval_id: str | None = None
    approved_action_json: JsonValue = None  # reserved; NULL in v1
    decided_by: str | None = None
    decided_by_display: str | None = None
    decided_at: datetime | None = None
    decision_latency_ms: int | None = None
    created_at: datetime
    resolved_at: datetime | None = None


class PauseClaim(BaseModel):
    """Result of ``Store.save_paused`` — did this caller create the row?

    ``created=True``  — the INSERT landed; ``run`` is the fresh ``proposed``
    row. ``created=False`` — the ``UNIQUE(idempotency_key)`` conflict fired:
    ``run`` is the EXISTING row (open: the caller attaches to it; resolved:
    its terminal outcome is surfaced — collide-and-dedupe, PLAN.md 4.3).
    Mirrors :class:`Claim` for the commit ledger.
    """

    model_config = ConfigDict(frozen=True)

    created: bool
    run: PausedRun


@dataclass(frozen=True)
class ApprovalDecision:
    """A human decision for one paused run (PLAN.md 3.3), transport-delivered.

    ``decided_by`` is an opaque actor id (``usr_...``), never an email — the
    email belongs in ``decided_by_display`` (PLAN.md 10.6).
    ``decision_latency_ms`` is control-plane-computed and recorded VERBATIM
    when present (PLAN.md 6.2); a local transport may leave it ``None`` and
    ``apply_decision`` computes it from the SDK's own clock pair instead.

    ``edited_args`` is RESERVED (PLAN.md 10.9 / settled decision 9): the field
    exists so the shape is stable, and it is always ``None`` in v1 — no
    transport can carry edits until the edit-before-approve phase. Setting it
    raises ``NotImplementedError`` at construction, before any state changes.

    A plain frozen dataclass (not pydantic) so the reserved-field check can
    raise ``NotImplementedError`` verbatim rather than a wrapped
    ``ValidationError``.
    """

    decision: HumanDecision
    decided_by: str | None = None
    decided_by_display: str | None = None
    decided_at: datetime | None = None
    decision_latency_ms: int | None = None
    reason: str | None = None
    edited_args: None = None  # RESERVED — always None in v1

    def __post_init__(self) -> None:
        if not isinstance(self.decision, HumanDecision):
            raise TypeError(
                f"decision must be an airlock.types.HumanDecision, got {self.decision!r}"
            )
        if self.edited_args is not None:
            raise NotImplementedError(
                "ApprovalDecision.edited_args is reserved for the edit-before-approve "
                "phase (post-MVP; PLAN.md section 10, settled decision 9) and must be "
                "None in v1 — no transport can carry edits yet. Only the schema "
                "reservation ships now."
            )
        if self.decision_latency_ms is not None and self.decision_latency_ms < 0:
            raise ValueError(f"decision_latency_ms must be >= 0, got {self.decision_latency_ms!r}")
        if self.decided_at is not None and self.decided_at.tzinfo is None:
            raise ValueError(f"decided_at must be timezone-aware, got naive {self.decided_at!r}")
