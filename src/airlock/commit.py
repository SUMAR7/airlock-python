"""``commit_once`` — the exactly-once commit primitive (PLAN.md section 4.1).

Implements steps 1-6 of the commit flow with the documented P1.1 reductions
(each is a seam, not a missing thought):

- **Key is caller-supplied.** Derivation from the action signature
  (``sha256("airlock/v1" || action_type || canonical_json(arg_map))``) is
  P1.2; until then the caller passes a deterministic key.
- **``downstream_key`` is plumbed, never derived.** It is passed verbatim to
  ``execute(downstream_key)`` and persisted on the ledger row; deriving it
  from the idempotency key (via ``Effect.map_key``) is P1.2.
- **No post-verify probe (step 5).** The ``Effect``/probe interface is P1.2;
  a successful execute goes straight to finalize.
- **No reconciliation.** A loser waiting on an in-flight row that never
  terminates raises ``CommitWaitTimeout`` naming the P1.3 reconciler — it
  NEVER re-executes. Blind re-execution of an in-flight action is the exact
  double-commit this library exists to prevent.

Failure honesty: if ``execute`` raises, the row stays ``executing`` with
``error_json`` recorded and the exception propagates. The effect's status is
genuinely unknown (the exception may have fired after the side effect landed),
so no terminal state would be truthful — the P1.3 reconciler resolves the row
by verification, per the PLAN.md section 4.2 recovery table.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping

from pydantic import JsonValue

from airlock.errors import AirlockError, CommitWaitTimeout
from airlock.store import Store
from airlock.types import CommitOutcome, CommitRecord, Guarantee, LedgerState

__all__ = ["commit_once"]


def commit_once(
    store: Store,
    *,
    key: str,
    action_type: str,
    execute: Callable[[str | None], JsonValue],
    preconditions: Callable[[], bool] | None = None,
    guarantee: Guarantee,
    args_json: Mapping[str, JsonValue],
    downstream_key: str | None = None,
    wait: bool = True,
    wait_timeout: float = 30.0,
    poll_interval: float = 0.05,
) -> CommitOutcome:
    """Execute ``execute(downstream_key)`` at most once per ``key``.

    Duplicate calls (sequential or concurrent, any process) return the
    outcome recorded by whichever call won the claim — exactly one side
    effect ever happens (SPEC.md section 5, rows 1-2).

    Args:
        store: the commit ledger.
        key: caller-supplied deterministic idempotency key (derivation: P1.2).
        action_type: stable action identifier, stamped on the ledger row.
        execute: the side effect; receives ``downstream_key`` verbatim. Its
            JSON-safe return value becomes the recorded result.
        preconditions: re-validated AFTER the claim (PLAN.md 4.1 step 2 /
            SPEC scenario 8); returning ``False`` finalizes ``aborted``
            without executing.
        guarantee: the ADR-2 guarantee class, stamped on the ledger row.
        args_json: JSON-safe arg map persisted at claim time for
            cross-process recovery (PLAN.md section 4.2).
        downstream_key: optional downstream idempotency key, persisted and
            passed to ``execute``. Never derived here (P1.2).
        wait: when this call loses to an in-flight row, whether to poll for
            the winner's terminal outcome. ``False`` raises
            ``CommitWaitTimeout`` immediately.
        wait_timeout: seconds a loser polls before raising
            ``CommitWaitTimeout`` (P1.1 stand-in for ``reconcile_after``:
            P1.3 runs targeted reconciliation here instead of raising).
        poll_interval: seconds between loser polls (implementation detail,
            not test timing).

    Returns:
        The terminal :class:`~airlock.types.CommitOutcome` for ``key``.

    Raises:
        CommitWaitTimeout: lost to an in-flight row that did not reach a
            terminal state in time (or ``wait=False``), or this call was
            epoch-fenced mid-flight and the takeover's resolution did not
            land in time.
        Exception: whatever ``execute`` raised, after ``error_json`` is
            recorded; the row stays ``executing`` for the reconciler. If the
            evidence write itself fails, the original exception still
            propagates, with the secondary failure attached as a note.
    """
    if wait_timeout <= 0:
        raise ValueError(f"wait_timeout must be > 0, got {wait_timeout!r}")
    if poll_interval <= 0:
        raise ValueError(f"poll_interval must be > 0, got {poll_interval!r}")

    # Step 1 — claim, committed in its own transaction before anything runs.
    claim = store.claim(key, action_type, guarantee, args_json, downstream_key)
    if not claim.won:
        if claim.record.state.is_terminal:
            # Scenario 1: duplicate call returns the recorded outcome.
            return _outcome_from(claim.record)
        # Scenario 2: another caller is in flight; wait for its outcome.
        return _await_terminal(
            store, key, wait=wait, wait_timeout=wait_timeout, poll_interval=poll_interval
        )

    epoch = claim.record.attempts  # our ownership epoch (PLAN.md section 4.2)

    # Step 2 — re-validate preconditions after the claim (scenario 8).
    if preconditions is not None and not preconditions():
        if store.finalize(key, epoch, LedgerState.ABORTED, None, None):
            return CommitOutcome(key=key, state=LedgerState.ABORTED)
        # Fenced: a takeover owns the row now; treat as a lost claim.
        return _await_terminal(
            store, key, wait=wait, wait_timeout=wait_timeout, poll_interval=poll_interval
        )

    # Step 3 — durable executing marker, committed BEFORE the effect runs.
    if not store.mark_executing(key, epoch):
        # Fenced: ownership moved on. Treat as a lost claim — do NOT execute.
        return _await_terminal(
            store, key, wait=wait, wait_timeout=wait_timeout, poll_interval=poll_interval
        )

    # Step 4 — the side effect. (Step 5, post-verify, is a P1.2 seam.)
    try:
        result = execute(downstream_key)
    except Exception as exc:
        # Honest failure: the effect's status is unknown, so the row stays
        # 'executing' with the error recorded; the P1.3 reconciler resolves
        # it by verification. A fenced record_error is fine to ignore — the
        # takeover already owns the evidence trail.
        try:
            store.record_error(key, epoch, {"type": type(exc).__name__, "message": str(exc)})
        except Exception as record_exc:
            # The evidence write itself failed (e.g. the ledger connection
            # dropped at exactly the wrong moment). The caller must still see
            # what the TOOL did — an infrastructure error from Airlock would
            # be the wrong signal — so attach the secondary failure as a note
            # and re-raise the original execute exception.
            exc.add_note(
                f"airlock: recording error_json on the ledger row failed ({record_exc!r}); "
                "the row stays 'executing' for the reconciler (P1.3)"
            )
        raise

    # Step 6 — finalize committed (audit append joins this transaction in P2.2).
    if store.finalize(key, epoch, LedgerState.COMMITTED, result, None):
        return CommitOutcome(key=key, state=LedgerState.COMMITTED, result=result)
    # Fenced: a takeover owns resolution — never override it. Report whatever
    # the ledger converges to.
    return _await_terminal(
        store, key, wait=wait, wait_timeout=wait_timeout, poll_interval=poll_interval
    )


def _outcome_from(record: CommitRecord) -> CommitOutcome:
    return CommitOutcome(
        key=record.idempotency_key,
        state=record.state,
        result=record.result_json,
        error=record.error_json,
    )


def _await_terminal(
    store: Store,
    key: str,
    *,
    wait: bool,
    wait_timeout: float,
    poll_interval: float,
) -> CommitOutcome:
    """Poll the ledger until ``key`` is terminal, or give up loudly.

    Giving up NEVER re-executes: a stale in-flight row is resolved only by
    the verification-first reconciler (P1.3).
    """
    record = _load_required(store, key)
    if record.state.is_terminal:
        return _outcome_from(record)
    if not wait:
        raise CommitWaitTimeout(
            f"commit for key {key!r} is in flight (state={record.state.value!r}) and "
            "wait=False; poll Store.load(key) for the outcome, or run the reconciler "
            "(P1.3: python -m airlock reconcile) if it goes stale — Airlock never "
            "re-executes an in-flight action.",
            key=key,
            last_state=record.state,
        )
    deadline = time.monotonic() + wait_timeout
    while time.monotonic() < deadline:
        time.sleep(poll_interval)
        record = _load_required(store, key)
        if record.state.is_terminal:
            return _outcome_from(record)
    raise CommitWaitTimeout(
        f"commit for key {key!r} was still in flight (state={record.state.value!r}) after "
        f"waiting {wait_timeout}s. The row is stale: resolve it with the verification-first "
        "reconciler (P1.3: python -m airlock reconcile) — Airlock never blindly re-executes "
        "an in-flight action.",
        key=key,
        last_state=record.state,
    )


def _load_required(store: Store, key: str) -> CommitRecord:
    record = store.load(key)
    if record is None:
        raise AirlockError(
            f"ledger row for key {key!r} disappeared while waiting — "
            "ledger rows must never be deleted (ADR-1)"
        )
    return record
