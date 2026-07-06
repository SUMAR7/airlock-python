"""The event seam (P2.1) — a MINIMAL policy-decision hook, not the real chain.

This is a deliberate placeholder for the P2.2 audit layer, scoped exactly to
what P2.1 needs and no more (the scope fence). P2.2 owns:

- the hash-chained ``audit_events`` table + ``audit_chain_head`` + genesis
  (ADR-5, PLAN.md 5.1/5.2),
- the ONE ``action_event.v1`` schema (model + JSON Schema + fixture
  round-trip, PLAN.md 6.3),
- ``finalize`` upgraded to append the chained audit row inside its own
  transaction (PLAN.md 5.1, the P1.1 ``audit`` seam).

**P2.1 does NONE of that.** It emits a small, structured
:class:`PolicyDecisionEvent` describing the auto/gate/deny verdict through an
:class:`EventSink` hook so the decision signal exists from day one (SPEC.md 7:
"the signal is unrecoverable if we don't capture it now"). The event is a
strict SUBSET of the ``action_event.v1`` fields (``action_type``,
``policy_decision``, ``cost``, ``reversibility``, ``blast_radius``) — P2.2
widens it to the full schema and makes the durable, hash-chained
``audit_events`` row the record of truth.

**Durability disclaimer (honest, per PLAN "Deny = block + audit event").**
Until P2.2 there is no hash-chained ``audit_events`` table, so a P2.1 event is
**best-effort**: it is delivered to the configured sinks and that is all. DENY
in particular is required to leave a durable-enough record; in P2.1 the only
honest option without the chain is this best-effort emission, and **P2.2 is the
durability owner** that turns it into a tamper-evident row. A sink that raises
must NOT break the guarded call's control flow (a broken telemetry sink cannot
be allowed to fail a deny/execute decision), so emission swallows sink errors —
another reason this layer is explicitly not the audit-of-record.

Import-light: pydantic + ``airlock.types`` only (no sqlalchemy/httpx), so the
event model is constructible on the pure decision hot path.
"""

from __future__ import annotations

import warnings
from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from airlock.types import BlastRadius, Decision, Money, Reversibility

__all__ = [
    "EventSink",
    "PolicyDecisionEvent",
    "emit_policy_decision",
]


class PolicyDecisionEvent(BaseModel):
    """The P2.1 policy-decision record — a subset of ``action_event.v1`` (P2.2).

    Carries exactly the decision-time fields PLAN.md deliverable 4 lists:
    ``action_type``, the ``policy_decision`` (auto/gate/deny), and the three
    risk inputs the policy evaluated (``cost``, ``reversibility``,
    ``blast_radius``). It is intentionally NOT the full event: no ``event_id``,
    ``emitted_at``, ``run_id``, ``idempotency_key``, ``guarantee``,
    ``human_decision``, ``outcome``, or ``post_verify`` — those (and the
    hash-chain columns) arrive with P2.2's ``action_event.v1``.

    Frozen and JSON-serializable (Money is a decimal-string model, the enums
    are ``StrEnum``) so a sink can forward it as-is.
    """

    model_config = ConfigDict(frozen=True)

    #: P2.2 will bump this to the full action_event schema_version. Kept as a
    #: field so a sink written today can branch on the shape it receives.
    schema_version: int = 0
    action_type: str
    policy_decision: Decision
    cost: Money | None = None
    reversibility: Reversibility
    blast_radius: BlastRadius | None = None


@runtime_checkable
class EventSink(Protocol):
    """A best-effort receiver of :class:`PolicyDecisionEvent`s (P2.1 seam).

    Deliberately minimal: one method, no ordering/durability guarantees. P2.2's
    durable ``audit_events`` row is the record of truth; a sink is a mirror
    (PLAN.md 4.4: "EventSink flushing (best-effort mirror)"). Implementations
    MUST be cheap and SHOULD NOT raise — :func:`emit_policy_decision` isolates a
    raising sink so it cannot perturb the guarded call, but a slow sink still
    sits on the caller's thread, so heavy work belongs behind the sink's own
    queue.
    """

    def emit(self, event: PolicyDecisionEvent) -> None:
        """Receive one policy-decision event. Must not raise on the hot path."""
        ...


def emit_policy_decision(
    sinks: Sequence[EventSink],
    event: PolicyDecisionEvent,
) -> None:
    """Deliver ``event`` to every sink, isolating failures (best-effort).

    A sink that raises is caught and turned into a warning rather than
    propagated: telemetry emission must never change the guarded call's
    control flow (a broken sink cannot fail a deny/execute decision). This is
    the P2.1 disclaimer made mechanical — the audit-of-record is P2.2's durable
    hash-chained row, not this hook.
    """
    for sink in sinks:
        try:
            sink.emit(event)
        except Exception as exc:  # a mirror sink must never break the decision path
            warnings.warn(
                f"airlock: EventSink {type(sink).__name__} raised while emitting a "
                f"{event.policy_decision.value} policy decision for "
                f"{event.action_type!r} ({exc!r}); the decision itself is unaffected. "
                "The durable audit record is P2.2's hash-chained audit_events row.",
                stacklevel=2,
            )
