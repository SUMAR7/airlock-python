"""Airlock error hierarchy — P1.2 + P2.1 surface.

P2.1 adds the ``@guard`` decision-path errors (``ActionDenied``,
``ActionPending``, ``PreconditionFailed`` — PLAN.md 3.1). ``AtMostOnceUnknown``
remains unbuilt; do not pre-create it — the SDK raises exactly what is defined
below.

``AtMostOnceWarning`` lives here too: it is not an ``AirlockError`` (it is a
``Warning``), but this module is the single home for every signal type Airlock
emits.
"""

from __future__ import annotations

from typing import Any

from airlock.types import LedgerState

__all__ = [
    "ActionDenied",
    "ActionPending",
    "AirlockError",
    "AtMostOnceWarning",
    "AuditChainError",
    "CanonicalizationError",
    "CommitFailed",
    "CommitWaitTimeout",
    "ExecuteTimeout",
    "GateNotSupported",
    "PreconditionFailed",
    "VerificationUnknown",
]


class AirlockError(Exception):
    """Base class for every error Airlock raises."""


class CanonicalizationError(AirlockError, ValueError):
    """A value cannot be represented in canonical JSON (``airlock-canon-1``).

    Raised at emit time by ``airlock._canonical`` for values outside the
    permitted domain — most importantly floats, which are forbidden
    everywhere because Money is a decimal string (PLAN.md section 3.2). Also
    a ``ValueError`` so generic validation handling catches it.
    """


class AtMostOnceWarning(UserWarning):
    """An action is running in at-most-once mode (ADR-2 degradation).

    Emitted by ``commit_once`` when the ``Effect`` guarantee is ``none`` —
    the downstream is neither idempotent nor verifiable, so exactly-once is
    refused (SPEC.md section 5, scenario 7): if a crash lands mid-execute,
    the row is finalized ``unknown`` and NEVER blind-retried. The honesty is
    a feature; never suppress this warning in library code. Escalate it to an
    error in strict deployments with ``-W error::airlock.AtMostOnceWarning``.
    """


class AuditChainError(AirlockError):
    """The hash-chained audit trail failed verification (ADR-5).

    Raised by ``airlock.audit.verify_chain`` when any row's recomputed hash,
    ``prev_hash`` linkage, gapless ``seq`` ordering, genesis constant, or the
    chain-head match fails — i.e. the append-only history was tampered with,
    truncated, reordered, or the chain metadata is corrupt. This is exactly
    the condition the chain exists to make detectable; treat it as a P0
    integrity incident, never a transient error.

    Attributes:
        seq: the first offending chain position.
    """

    def __init__(self, message: str, *, seq: int) -> None:
        super().__init__(message)
        self.seq = seq


class CommitWaitTimeout(AirlockError):
    """A ``commit_once`` loser gave up waiting on an in-flight claim.

    Raised when another caller holds the row (state ``pending`` or
    ``executing``) and it did not reach a terminal state within
    ``wait_timeout`` (or immediately, when ``wait=False``). The action is
    NEVER re-executed by the waiter: a stale in-flight row is resolved only by
    verification-first reconciliation (the P1.3 reconciler,
    ``python -m airlock reconcile``).

    Attributes:
        key: the idempotency key that timed out.
        last_state: the ledger state last observed for the row.
    """

    def __init__(self, message: str, *, key: str, last_state: LedgerState) -> None:
        super().__init__(message)
        self.key = key
        self.last_state = last_state


class ExecuteTimeout(AirlockError):
    """``execute`` ran past its ``execute_timeout`` and was ABANDONED.

    PLAN.md 4.1 step 4 / 10 point 2: an owner's ``execute`` must abort strictly
    before a row becomes recover-eligible (``execute_timeout < reconcile_after``),
    so a reconciler can never probe a row while its original owner is still
    legitimately mid-execute — the residual double-execute the epoch fence exists
    to close. When ``execute`` exceeds ``execute_timeout``, ``commit_once`` stops
    waiting on it, records the timeout in ``error_json``, leaves the row
    ``executing`` for the verification-first reconciler, and raises this.

    The abandoned work may still be running in the background: Python cannot
    forcibly kill a synchronous call. That is safe — the owner is fenced. If the
    slow ``execute`` eventually lands its effect, the owner's epoch has been (or
    will be) bumped by the reconciler, so its ``finalize`` matches zero rows
    (``WHERE attempts = epoch``), and the effect is reconciled once via the
    probe / downstream dedup. The caller must NOT retry: the ledger holds the
    claim.

    Attributes:
        key: the idempotency key whose ``execute`` was abandoned.
        timeout: the ``execute_timeout`` that was exceeded.
    """

    def __init__(self, message: str, *, key: str, timeout: float) -> None:
        super().__init__(message)
        self.key = key
        self.timeout = timeout


class VerificationUnknown(AirlockError):
    """The post-verify probe could not prove the effect present OR absent.

    The honest non-answer (PLAN.md 4.1 step 5): ``execute`` returned (or the
    probe itself failed), but "did this effect happen?" got no answer, so no
    terminal state would be truthful. The ledger row stays ``executing`` with
    the probe evidence recorded in ``error_json``; it is resolved only by the
    verification-first reconciler (P1.3: ``python -m airlock reconcile``) —
    exactly how stale-loser waits (:class:`CommitWaitTimeout`) behave. The
    caller must NOT retry the action: the ledger still holds the claim.

    Attributes:
        key: the idempotency key whose row was left ``executing``.
        evidence: whatever the probe returned (or ``None`` if it raised).
    """

    def __init__(self, message: str, *, key: str, evidence: Any | None = None) -> None:
        super().__init__(message)
        self.key = key
        self.evidence = evidence


# ---------------------------------------------------------------------------
# The @guard decision-path errors (P2.1).
# ---------------------------------------------------------------------------


class ActionDenied(AirlockError):
    """The policy returned ``deny``: the guarded action is BLOCKED (ADR-6).

    No side effect runs — ``@guard`` raises this INSTEAD of calling the tool,
    before any ledger claim — and a policy-decision audit record is emitted
    first (PLAN.md "Deny = block + audit event"; the durable hash-chained row
    is P2.2, which formalizes it). This is a hard stop for the current call:
    there is nothing to retry until the policy or the action's risk metadata
    changes.

    Attributes:
        action_type: the action the policy denied.
    """

    def __init__(self, message: str, *, action_type: str) -> None:
        super().__init__(message)
        self.action_type = action_type


class ActionPending(AirlockError):
    """The policy returned ``gate``: the action needs human approval (ADR-4).

    In P2.1 gating is DELIBERATELY MINIMAL: the durable pause, resume, and
    approval transport are P2.3. ``@guard`` raises this the moment a GATE
    decision is reached — AFTER emitting the policy-decision audit record and
    BEFORE any side effect (fail-safe: a gated action never executes here) —
    so a gate is surfaced cleanly rather than silently executed or dropped.
    P2.3 replaces the raise with a durable ``paused_runs`` write + transport
    send/wait; the seam is documented in ``airlock._guard``.

    ``run_id`` is ``None`` in P2.1 (no ``paused_runs`` row is created yet);
    the attribute exists so P2.3 can populate it without a signature change.

    Attributes:
        action_type: the action the policy gated.
        run_id: the paused-run id — always ``None`` until P2.3.
    """

    def __init__(self, message: str, *, action_type: str, run_id: str | None = None) -> None:
        super().__init__(message)
        self.action_type = action_type
        self.run_id = run_id


class GateNotSupported(ActionPending):
    """A GATE decision was reached but no pause layer is wired (P2.1 default).

    A subclass of :class:`ActionPending` (so ``except ActionPending`` catches
    it) that names P2.3 explicitly: in P2.1 there is no durable pause or
    transport, so the only honest thing ``@guard`` can do on GATE is refuse to
    proceed and say why. When P2.3 lands, a configured pause layer supersedes
    this and the plain :class:`ActionPending` (with a ``run_id``) is raised for
    async callers instead. The distinct type lets integrators assert "P2.1 did
    not silently execute a gated action" without conflating it with a real
    async-pending pause.
    """


class PreconditionFailed(AirlockError):
    """A guarded action's ``preconditions`` returned ``False`` before executing.

    Raised by ``@guard`` when the AUTO path re-validates preconditions after
    the claim and they do not hold (SPEC.md scenario 8 at the decorator layer):
    the action is finalized ``aborted`` in the ledger (no side effect) and this
    is raised so the caller sees the abort explicitly rather than a silent
    no-op. ``commit_once`` performs the same re-validation internally; this
    error is the caller-facing surface ``@guard`` puts on that abort.

    Attributes:
        action_type: the action whose preconditions failed.
        key: the idempotency key of the aborted ledger row.
    """

    def __init__(self, message: str, *, action_type: str, key: str) -> None:
        super().__init__(message)
        self.action_type = action_type
        self.key = key


class CommitFailed(AirlockError):
    """An AUTO-path ``commit_once`` reached a terminal state that is NOT committed.

    Raised by ``@guard`` on the AUTO path when the ledger row finalized to a
    non-``committed`` terminal state that the caller must not mistake for a
    successful result (PLAN.md prime directive: "always provable" — a caller
    that got a bare ``None`` back could not tell a committed None-returning tool
    from an effect that did not land):

    - ``failed``  — the effect executed and the post-verify probe PROVED it did
      not take effect (``Effect.verify`` answered ``absent``). The evidence is
      on the ledger row's ``error_json`` and echoed in :attr:`error`.
    - ``unknown`` — a DUPLICATE call landed on a prior row the reconciler (or a
      degraded at-most-once crash) left ``unknown``: may have executed, cannot
      be proven either way, never retried. The caller is told rather than handed
      a silent ``None``.

    (The live ``unknown`` path where THIS call's own post-verify answers
    ``unknown`` raises :class:`VerificationUnknown` from ``commit_once`` before a
    terminal state is written — that propagates through ``@guard`` unchanged;
    this error is for the terminal-``unknown`` row a *duplicate* call reads back,
    and for the ``failed`` outcome.) An ``aborted`` outcome is surfaced
    separately as :class:`PreconditionFailed`.

    Attributes:
        action_type: the action whose AUTO commit did not land.
        key: the idempotency key of the non-committed ledger row.
        state: the terminal :class:`~airlock.types.LedgerState` value
            (``"failed"`` or ``"unknown"``).
        error: the ledger row's recorded error/evidence, if any.
    """

    def __init__(
        self,
        message: str,
        *,
        action_type: str,
        key: str,
        state: str,
        error: Any | None = None,
    ) -> None:
        super().__init__(message)
        self.action_type = action_type
        self.key = key
        self.state = state
        self.error = error
