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
    "ApprovalRejected",
    "AtMostOnceWarning",
    "AuditChainError",
    "CanonicalizationError",
    "CommitFailed",
    "CommitWaitTimeout",
    "ExecuteTimeout",
    "GateNotSupported",
    "PreconditionFailed",
    "StateVersionError",
    "UnknownApprovalRef",
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
    """The policy returned ``gate``: the action is durably paused (ADR-4).

    As of P2.3 a GATE decision persists a ``paused_runs`` row BEFORE this is
    raised, so the pause survives crash/deploy/restart (scenario 6). ``@guard``
    raises it when the caller is not waiting for the decision inline —
    ``gate_wait=False``, or ``transport.wait`` timed out — and the run stays
    ``proposed`` until a decision arrives. Resume later with
    :meth:`airlock.Airlock.resume` (or any path into
    :func:`airlock.pause.apply_decision`) using ``approval_ref``. The side
    effect has NOT executed (fail-safe).

    Attributes:
        action_type: the action the policy gated.
        run_id: the persisted paused-run id.
        approval_ref: the SDK-minted approval reference — the resume handle
            (and the only cross-boundary key, PLAN.md 6.1).
    """

    def __init__(
        self,
        message: str,
        *,
        action_type: str,
        run_id: str | None = None,
        approval_ref: str | None = None,
    ) -> None:
        super().__init__(message)
        self.action_type = action_type
        self.run_id = run_id
        self.approval_ref = approval_ref


class GateNotSupported(ActionPending):
    """A GATE decision was reached but no pause layer is wired.

    Historical (P2.1): before the P2.3 durable pause existed, this named the
    missing layer. As of P2.3 ``init`` always wires a pause layer (the
    ``ConsoleApprovalTransport`` stub by default), so a normally-configured
    runtime never raises it; it remains a subclass of :class:`ActionPending`
    for compatibility with integrators that caught it explicitly.
    """


class ApprovalRejected(AirlockError):
    """A gated action's approval was REJECTED by a human (ADR-4).

    Raised by ``@guard`` (and by re-gates of the same action) when the paused
    run's recorded outcome is a rejection: the run is ``aborted``, no side
    effect ran, and the rejection is hash-chain audited. A re-gate with
    identical args attaches to the SAME run and surfaces this same outcome
    (collide-and-dedupe, PLAN.md 4.3) — a deliberate second attempt needs a
    distinguishing arg or a ``key`` override.

    The reviewer's structured CHOICE flows back here (P3.9): ``reason_code`` is
    the code the human picked from the set the action OFFERED
    (``@guard(reject_reasons=...)``), so the calling agent can branch on it
    (``except ApprovalRejected as rej: if rej.reason_code == "needs_more_info":
    ...``); ``reason`` is the optional free-text note. Both are ``None`` when the
    reviewer chose no code / left no note, or when the transport carried neither.
    They originate from the ``ApprovalDecision`` the transport returned, are
    persisted on the ``paused_runs`` row when the decision is applied, and are
    surfaced from there — so a FRESH-process resume (a redelivery / reconciler
    sweep that rehydrates by ``approval_ref``) surfaces the same code, not only
    the in-memory path.

    Attributes:
        action_type: the rejected action.
        run_id: the paused run.
        approval_ref: the approval reference the rejection resolved.
        decided_by: the opaque actor id that rejected, if recorded.
        reason_code: the structured code the human chose from the offered set,
            or ``None``. Opaque here — the SDK never re-validates it against the
            offered set (the control plane owns that).
        reason: the optional free-text reason the human gave, or ``None``.
    """

    def __init__(
        self,
        message: str,
        *,
        action_type: str,
        run_id: str,
        approval_ref: str,
        decided_by: str | None = None,
        reason_code: str | None = None,
        reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.action_type = action_type
        self.run_id = run_id
        self.approval_ref = approval_ref
        self.decided_by = decided_by
        self.reason_code = reason_code
        self.reason = reason


class UnknownApprovalRef(AirlockError):
    """No ``paused_runs`` row exists for the given ``approval_ref``.

    Raised by ``apply_decision`` / ``Airlock.resume`` when the approval
    reference does not match any persisted pause — a decision for a run this
    database has never seen (wrong environment, typo, or a fabricated ref).
    Never a silent no-op: an unmatched decision must be investigated.

    Attributes:
        approval_ref: the reference that matched nothing.
    """

    def __init__(self, message: str, *, approval_ref: str) -> None:
        super().__init__(message)
        self.approval_ref = approval_ref


class StateVersionError(AirlockError):
    """A ``paused_runs`` row carries an UNKNOWN ``state_version`` — refused loudly.

    Rehydration (scenario 6) reconstructs a call from ``serialized_state``;
    parsing a serialization this SDK version does not understand could execute
    a subtly different action than the human approved. So an unknown version
    is never misparsed and never guessed at: the run is left untouched and this
    is raised. Upgrade (or downgrade) the SDK to a version that understands
    ``found``, or migrate the row explicitly.

    Attributes:
        run_id: the affected paused run.
        approval_ref: its approval reference.
        found: the state_version on the row.
        supported: the version this SDK writes and understands.
    """

    def __init__(
        self, message: str, *, run_id: str, approval_ref: str, found: int, supported: int
    ) -> None:
        super().__init__(message)
        self.run_id = run_id
        self.approval_ref = approval_ref
        self.found = found
        self.supported = supported


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
