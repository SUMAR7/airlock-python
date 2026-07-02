"""Airlock error hierarchy — P1.1 surface only.

Later phases add their own errors here (``ActionDenied``, ``ActionPending``,
``PreconditionFailed``, ``AtMostOnceUnknown`` — PLAN.md section 3.1); do not
pre-create them: P1.1 raises exactly what is defined below.
"""

from __future__ import annotations

from airlock.types import LedgerState

__all__ = ["AirlockError", "CommitWaitTimeout"]


class AirlockError(Exception):
    """Base class for every error Airlock raises."""


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
