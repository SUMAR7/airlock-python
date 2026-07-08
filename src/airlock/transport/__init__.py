"""``ApprovalTransport`` — how a gated action reaches a human (PLAN.md 3.3).

The transport is touched ONLY on the GATE path, where a human is already the
latency floor (SPEC.md 3): the auto/deny hot path never imports or calls it.
P2.3 ships the protocol plus the stub :class:`~airlock.transport.console.
ConsoleApprovalTransport` (CLI/file approve — SPEC.md Phase 2's "use a stub
ApprovalTransport here"); the HTTP transport and the ``/contracts`` wire
module are P3.x and deliberately absent.

:class:`PauseRequest` is the ApprovalRequestWire-SHAPED summary of one paused
action — a minimal local dataclass, NOT the wire contract (P3.1 formalizes
that in ``/contracts`` with the frozen field allowlist and ``extra="forbid"``
enforcement). It already honors the boundary rule it will be frozen under
(PLAN.md 6.1): it carries the SDK-minted ``approval_ref`` (the only
cross-boundary key), ``run_id``, ``action_type``, an integrator-facing
``summary`` and the risk metadata — and structurally CANNOT carry tool
args/payloads, the ``idempotency_key`` (a digest of the payload), or results:
those fields do not exist on it, so raw payloads have no code path to a
transport.

Durability contract: by the time ``send`` is called, the ``paused_runs`` row
is ALREADY durable (``@guard`` persists BEFORE any transport call) — a lost or
duplicated send can always be retried, so ``send`` MUST be redelivery-safe
(sending the same ``approval_ref`` twice is harmless). ``wait`` blocks/polls
up to ``timeout`` seconds and returns the decision, or ``None`` on timeout
(the caller raises ``ActionPending``; the pause stays durable and is resumed
later).

Import-light: stdlib + pydantic (``airlock.types``) only — no sockets, no
extras. A CI test imports ``airlock`` with extras uninstalled and this package
must not break it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from airlock.types import ApprovalDecision, BlastRadius, Money, Reversibility

__all__ = ["ApprovalTransport", "PauseRequest", "SendReceipt"]


@dataclass(frozen=True)
class PauseRequest:
    """The ApprovalRequestWire-shaped summary of one paused action (P2.3-local).

    Carries ONLY boundary-safe metadata (PLAN.md 6.1's frozen allowlist, minus
    the P3.x-only fields): identifiers the human needs to find the run, and the
    risk vocabulary the inbox renders. Never tool args, never the
    idempotency_key, never results — those fields do not exist here.

    ``summary`` is an integrator-facing one-liner (defaults to the
    action_type); the P3.1 wire contract caps it at 500 chars and forbids
    ``repr(args)`` — the same posture applies here.
    """

    approval_ref: str
    run_id: str
    action_type: str
    summary: str
    requested_at: datetime
    cost: Money | None = None
    reversibility: Reversibility | None = None
    blast_radius_estimate: BlastRadius | None = None


@dataclass(frozen=True)
class SendReceipt:
    """What ``send`` returns: the ref it delivered, and (P3.x) the hosted
    ``approval_id`` for the reconciler backstop poll — ``None`` for local
    transports."""

    approval_ref: str
    approval_id: str | None = None


@runtime_checkable
class ApprovalTransport(Protocol):
    """The stable transport seam (PLAN.md 3.3) — gate path only.

    ``send`` MUST be redelivery-safe: the durable pause precedes it, so a
    retry / re-gate may send the same ``approval_ref`` again and nothing may
    double-apply because of it (decisions are deduped by ``apply_decision``,
    not by the transport). ``wait`` polls/blocks for up to ``timeout`` seconds
    for a decision on ``approval_ref`` — the SDK-minted reference is the only
    key a transport ever correlates on (PLAN.md 6.1) — and returns ``None`` on
    timeout (never raises for "no decision yet").
    """

    def send(self, request: PauseRequest) -> SendReceipt:
        """Deliver the pause summary to wherever decisions come from."""
        ...

    def wait(self, approval_ref: str, timeout: float) -> ApprovalDecision | None:
        """Block/poll up to ``timeout`` seconds; the decision, or ``None``."""
        ...
