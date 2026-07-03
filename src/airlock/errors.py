"""Airlock error hierarchy — P1.2 surface.

Later phases add their own errors here (``ActionDenied``, ``ActionPending``,
``PreconditionFailed``, ``AtMostOnceUnknown`` — PLAN.md section 3.1); do not
pre-create them: the SDK raises exactly what is defined below.

``AtMostOnceWarning`` lives here too: it is not an ``AirlockError`` (it is a
``Warning``), but this module is the single home for every signal type Airlock
emits.
"""

from __future__ import annotations

from typing import Any

from airlock.types import LedgerState

__all__ = [
    "AirlockError",
    "AtMostOnceWarning",
    "CanonicalizationError",
    "CommitWaitTimeout",
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
