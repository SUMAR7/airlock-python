"""THE one event contract — ``action_event.v1`` — plus the ``EventSink`` mirror.

This module absorbs the P2.1 event seam (the interim ``PolicyDecisionEvent``
subset is gone) so there is EXACTLY ONE event shape (PLAN.md 6.3 / section 10
point 5): :class:`ActionEvent`, ``schema_version: 1``, validated against the
frozen JSON Schema at ``/contracts/events/action_event.v1.json`` by a fixture
round-trip test in the same PR that ships it. Enum values come from
``airlock.types`` — the single vocabulary source — and a CI test asserts the
JSON-schema enum lists match them (and the DDL CHECKs).

Emission (PLAN.md 6.3, SPEC section 7 — "the signal is unrecoverable if we
don't capture it now"): for **every** guarded call —

- **deny** at decision time: ``@guard`` appends the event durably as an
  ``audit_events`` row (``event_type='action_event'``) via
  ``Store.append_audit`` — DENY = decision + one local audit append
  (PLAN.md 4.4); the hot-path DECISION itself stays pure and I/O-free.
- **auto** at terminal state: ``commit_once`` builds the event at each
  terminal transition and hands it to ``Store.finalize``, which appends it
  INSIDE the terminal-state transaction — the event inherits the chain's
  integrity and is atomic with the state it describes.
- **gate** at terminal state: a gated action has no terminal state until the
  P2.3 durable pause resolves it, so P2.2 emits nothing for GATE — the gate
  outcome (``human_decision``, ``decision_latency_ms``, ``decided_by``) is
  exactly what P2.3's resume path fills in. Emitting a fabricated
  decision-time event here would double-count the call once P2.3 lands.

The durable ``audit_events`` row is the record of truth. :class:`EventSink`
stays as the **best-effort mirror of the same object**: sinks receive the
identical :class:`ActionEvent` instance that was appended, and a sink that
raises (or is slow) must never raise into or block the guarded call —
:func:`emit_action_event` isolates failures into warnings.

An event is emitted per **terminal transition**, not per call: a duplicate
call that reads back an already-terminal ledger row appends nothing (the
transition it observed was already evidenced once, atomically). Every denied
call, by contrast, is its own decision-time block and gets its own event.

Import-light: pydantic + ``airlock.types`` + ``airlock.audit`` (both
stdlib+pydantic only), so the event model is constructible on the pure
decision hot path.
"""

from __future__ import annotations

import re
import uuid
import warnings
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, JsonValue, field_validator, model_validator

from airlock.audit import rfc3339_utc
from airlock.types import (
    ActionOutcome,
    AuditEvent,
    BlastRadius,
    Decision,
    Guarantee,
    HumanDecision,
    Money,
    Reversibility,
    Verification,
)

__all__ = [
    "ACTION_EVENT_TYPE",
    "ActionEvent",
    "ActionEventContext",
    "EventSink",
    "PostVerify",
    "build_action_event",
    "emit_action_event",
]

#: The ``audit_events.event_type`` value for action events (PLAN.md 6.3).
ACTION_EVENT_TYPE = "action_event"

#: The frozen ``emitted_at`` shape: RFC 3339 UTC, microseconds, ``Z`` suffix —
#: the airlock-canon-1 timestamp convention (/contracts/canonical-json.md §5).
_EMITTED_AT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


class PostVerify(BaseModel):
    """The ``post_verify`` sub-object of ``action_event.v1``: ``{ran, result}``.

    ``ran`` says whether a post-verify probe executed for this call;
    ``result`` is its :class:`~airlock.types.Verification` verdict (the
    single-sourced probe vocabulary), or ``null``. ``ran=false`` forces
    ``result=null`` — a verdict from a probe that never ran would be a false
    statement, and the model makes it unrepresentable.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ran: bool
    result: Verification | None = None

    @model_validator(mode="after")
    def _no_verdict_without_a_probe(self) -> PostVerify:
        if not self.ran and self.result is not None:
            raise ValueError(
                "post_verify.result must be null when ran is false — a probe that "
                "never ran cannot have produced a verdict"
            )
        return self


class ActionEvent(BaseModel):
    """One ``action_event`` — the day-one moat signal (PLAN.md 6.3, SPEC §7).

    Fields exactly per PLAN.md 6.3; the JSON wire shape is frozen in
    ``/contracts/events/action_event.v1.json`` and pinned by fixtures.
    Versioning: adding optional fields does not bump the version; consumers
    ignore unknown fields; any rename/type/semantic change is
    ``action_event.v2`` and the v1 fixtures stay green forever.

    ``human_decision`` / ``decision_latency_ms`` / ``decided_by`` are ``null``
    until the P2.3 approval flow populates them (``decision_latency_ms`` is
    control-plane-computed and recorded verbatim — PLAN.md 6.2).
    ``action_diff`` is RESERVED for the preference-learning signal (SPEC §7):
    the field exists so v1 consumers already parse it, and it is always
    ``null`` in v1 — the type makes any other value unrepresentable.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    event_id: str
    emitted_at: str
    run_id: str
    idempotency_key: str
    action_type: str
    policy_decision: Decision
    cost: Money | None = None
    reversibility: Reversibility
    blast_radius_estimate: BlastRadius | None = None
    guarantee: Guarantee
    human_decision: HumanDecision | None = None
    decision_latency_ms: int | None = None
    decided_by: str | None = None
    action_diff: None = None  # reserved (SPEC §7); always null in v1
    outcome: ActionOutcome
    post_verify: PostVerify

    @field_validator("emitted_at", mode="before")
    @classmethod
    def _render_emitted_at(cls, value: object) -> object:
        # Accept a tz-aware datetime for construction convenience; the stored
        # field is always the canonical string (what the JSON schema pins).
        if isinstance(value, datetime):
            return rfc3339_utc(value)
        return value

    @field_validator("emitted_at")
    @classmethod
    def _check_emitted_at(cls, value: str) -> str:
        if not _EMITTED_AT_RE.match(value):
            raise ValueError(
                f"emitted_at {value!r} is not an RFC 3339 UTC timestamp with microsecond "
                "precision and a 'Z' suffix (YYYY-MM-DDTHH:MM:SS.ffffffZ)"
            )
        return value

    @field_validator("event_id", "run_id", "idempotency_key", "action_type")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("must be a non-empty string")
        return value

    def to_payload(self) -> dict[str, JsonValue]:
        """The JSON-object form of this event — the ``payload_json`` content.

        Exactly the shape the JSON Schema validates: enums as their string
        values, Money as ``{amount, currency}`` decimal-string object, nulls
        explicit. Every value lies in the ``airlock-canon-1`` domain (Money is
        never a float), so the payload is hashable into the audit chain as-is.
        """
        dumped: dict[str, JsonValue] = self.model_dump(mode="json")
        return dumped

    def to_audit_event(self) -> AuditEvent:
        """This event as the chained audit row it is durably written as.

        ``event_type='action_event'``; the row's hashed/stored ``created_at``
        is the event's own ``emitted_at`` instant — one timestamp, no skew
        between the contract object and its tamper-evident record.
        """
        emitted = datetime.strptime(self.emitted_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
        return AuditEvent(
            event_type=ACTION_EVENT_TYPE,
            run_id=self.run_id,
            action_type=self.action_type,
            payload=self.to_payload(),
            created_at=emitted,
        )


@runtime_checkable
class EventSink(Protocol):
    """A best-effort receiver of :class:`ActionEvent`s — the mirror, not the record.

    The durable hash-chained ``audit_events`` row is the record of truth; a
    sink mirrors the SAME object for telemetry/streaming (PLAN.md 4.4:
    "EventSink flushing (best-effort mirror)"). Implementations MUST be cheap
    and MUST NOT raise into the guarded call — :func:`emit_action_event`
    isolates a raising sink, but a slow sink still sits on the caller's
    thread, so heavy work belongs behind the sink's own queue.
    """

    def emit(self, event: ActionEvent) -> None:
        """Receive one action event. Must not raise on the hot path."""
        ...


@dataclass(frozen=True)
class ActionEventContext:
    """The decision-time half of an ``action_event``, carried to the terminal seam.

    ``@guard`` resolves these at decision time (run_id minted per call, the
    policy verdict, the resolved risk inputs) and hands them to ``commit_once``,
    which builds the full :class:`ActionEvent` at each terminal transition —
    where the ``outcome`` and ``post_verify`` halves become known — and appends
    it inside the finalize transaction, then mirrors it to ``sinks``.

    ``human_decision`` / ``decided_by`` / ``decision_latency_ms`` are the P2.3
    approval half: ``apply_decision`` populates them when it drives an
    approved/rejected pause to its terminal state (the gate's ``action_event``
    is emitted at that terminal state — PLAN.md 6.3), so the one event carries
    both the policy verdict and the human decision. They stay ``None`` on the
    auto/deny paths, exactly as the P2.2 emission matrix pinned.
    """

    run_id: str
    policy_decision: Decision
    reversibility: Reversibility
    cost: Money | None = None
    blast_radius: BlastRadius | None = None
    human_decision: HumanDecision | None = None
    decided_by: str | None = None
    decision_latency_ms: int | None = None
    sinks: tuple[EventSink, ...] = ()


def build_action_event(
    ctx: ActionEventContext,
    *,
    idempotency_key: str,
    action_type: str,
    guarantee: Guarantee,
    outcome: ActionOutcome,
    post_verify: PostVerify,
    now_fn: Callable[[], datetime],
) -> ActionEvent:
    """Assemble the one event: decision-time context + terminal outcome.

    ``event_id`` is minted here (uuid4 hex); ``emitted_at`` comes from the
    caller's injectable clock (the determinism substrate — never a hidden
    ``now()``), and doubles as the audit row's hashed ``created_at``.
    """
    return ActionEvent(
        event_id=uuid.uuid4().hex,
        emitted_at=rfc3339_utc(now_fn()),
        run_id=ctx.run_id,
        idempotency_key=idempotency_key,
        action_type=action_type,
        policy_decision=ctx.policy_decision,
        cost=ctx.cost,
        reversibility=ctx.reversibility,
        blast_radius_estimate=ctx.blast_radius,
        guarantee=guarantee,
        human_decision=ctx.human_decision,
        decision_latency_ms=ctx.decision_latency_ms,
        decided_by=ctx.decided_by,
        outcome=outcome,
        post_verify=post_verify,
    )


def emit_action_event(sinks: Sequence[EventSink], event: ActionEvent) -> None:
    """Mirror ``event`` to every sink, isolating failures (best-effort).

    A sink that raises is caught and turned into a warning rather than
    propagated: mirror emission must never change the guarded call's control
    flow (a broken telemetry sink cannot be allowed to fail a deny/execute
    decision, and the durable audit row has already landed by the time the
    mirror fires).
    """
    for sink in sinks:
        try:
            sink.emit(event)
        except Exception as exc:  # a mirror sink must never break the decision path
            warnings.warn(
                f"airlock: EventSink {type(sink).__name__} raised while mirroring an "
                f"action_event ({event.policy_decision.value}/{event.outcome.value}) for "
                f"{event.action_type!r} ({exc!r}); the durable audit row is unaffected.",
                stacklevel=2,
            )
