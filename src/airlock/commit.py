"""``commit_once`` — the exactly-once commit primitive (PLAN.md section 4.1).

Implements steps 1-6 of the commit flow. As of P1.2 the ADR-2 surface is in:
the ``Effect`` declares how exactly-once is achievable, the guarantee is
derived from it (never passed separately), the downstream idempotency key is
derived from the ledger key (``Effect.downstream_key_for``), and the
post-verify probe (step 5) runs when the effect has one. Remaining documented
reductions:

- **Key is caller-supplied.** ``airlock.idempotency.derive_key`` exists
  (P1.2), but wiring it to a function signature is the ``@guard`` decorator's
  job (P2.1) — ``commit_once`` stays the primitive that takes the final key.
- **No reconciliation.** A loser waiting on an in-flight row that never
  terminates raises ``CommitWaitTimeout`` naming the P1.3 reconciler — it
  NEVER re-executes. Blind re-execution of an in-flight action is the exact
  double-commit this library exists to prevent.

Failure honesty (the shared principle behind three paths that all leave the
row ``executing`` for the P1.3 reconciler):

- ``execute`` raised → status genuinely unknown (the exception may have fired
  after the side effect landed); evidence recorded; the exception propagates.
- post-verify answered ``unknown`` → the probe could not prove presence OR
  absence; evidence recorded; ``VerificationUnknown`` raised. No terminal
  state would be truthful, so none is written.
- a loser's wait timed out → ``CommitWaitTimeout``; the row belongs to
  whoever claimed it.

At-most-once degradation (SPEC.md section 5, scenario 7): an ``Effect`` with
neither ``key_param`` nor ``verify`` means exactly-once is impossible, so the
action runs at-most-once — ``AtMostOnceWarning`` fires once per action type
per process, the ``none`` guarantee is stamped durably on the ledger row, and
``CommitOutcome.guarantee`` tells the caller. Never hidden, never retried.
"""

from __future__ import annotations

import json
import time
import warnings
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from pydantic import JsonValue

from airlock._canonical import canonical_json
from airlock.effects import Effect
from airlock.errors import (
    AirlockError,
    AtMostOnceWarning,
    CommitWaitTimeout,
    VerificationUnknown,
)
from airlock.reconcile import OnAbsent
from airlock.store import Store
from airlock.types import CommitOutcome, CommitRecord, Guarantee, LedgerState, Verification

__all__ = ["commit_once"]


def _utcnow() -> datetime:
    return datetime.now(UTC)


#: Action types already warned about at-most-once degradation (per process).
_at_most_once_warned: set[str] = set()


def commit_once(
    store: Store,
    *,
    key: str,
    action_type: str,
    execute: Callable[[str | None], JsonValue],
    effect: Effect,
    preconditions: Callable[[], bool] | None = None,
    args_json: Mapping[str, JsonValue],
    wait: bool = True,
    wait_timeout: float = 30.0,
    poll_interval: float = 0.05,
    reconcile_after: timedelta | None = None,
    on_absent: OnAbsent = OnAbsent.ABORT,
    now_fn: Callable[[], datetime] = _utcnow,
) -> CommitOutcome:
    """Execute ``execute(downstream_key)`` at most once per ``key``.

    Duplicate calls (sequential or concurrent, any process) return the
    outcome recorded by whichever call won the claim — exactly one side
    effect ever happens (SPEC.md section 5, rows 1-2).

    Args:
        store: the commit ledger.
        key: the deterministic idempotency key — derive it with
            ``airlock.idempotency.derive_key`` (or ``namespace_user_key``
            for overrides); ``@guard`` automates that wiring in P2.1.
        action_type: stable action identifier, stamped on the ledger row.
        execute: the side effect. Receives the downstream idempotency key —
            ``effect.downstream_key_for(key)``: ``map_key(key)`` if the
            effect has ``map_key``, else ``key`` itself, else ``None`` when
            the downstream accepts no key — and must pass it through via the
            effect's ``key_param`` kwarg. Its JSON-safe return value becomes
            the recorded result.
        effect: the ADR-2 declaration for this action type. Supplies the
            guarantee (``effect.guarantee`` — stamped on the ledger row,
            reported on the outcome), the downstream key derivation, and the
            optional post-verify probe.
        preconditions: re-validated AFTER the claim (PLAN.md 4.1 step 2 /
            SPEC scenario 8); returning ``False`` finalizes ``aborted``
            without executing.
        args_json: the canonical arg map (see ``build_arg_map``), persisted
            at claim time for cross-process recovery (PLAN.md section 4.2)
            and splatted into ``effect.verify`` at post-verify time. Values
            must lie in the ``airlock-canon-1`` domain (no floats, no
            over-bound ints, ...) — enforced before the claim, whatever the
            key's provenance.
        wait: when this call loses to an in-flight row, whether to poll for
            the winner's terminal outcome. ``False`` raises
            ``CommitWaitTimeout`` immediately.
        wait_timeout: seconds a loser polls before raising
            ``CommitWaitTimeout`` (P1.1 stand-in for ``reconcile_after``:
            P1.3 runs targeted reconciliation here instead of raising).
        poll_interval: seconds between loser polls (implementation detail,
            not test timing).

    Returns:
        The terminal :class:`~airlock.types.CommitOutcome` for ``key``. A
        post-verify answer of ``absent`` returns state ``failed`` with the
        probe evidence in ``error`` — executed, confirmed not to have taken
        effect.

    Warns:
        AtMostOnceWarning: once per ``action_type`` per process when
            ``effect.guarantee`` is ``none`` (scenario 7 degradation).

    Raises:
        CanonicalizationError: ``args_json`` contains values outside the
            ``airlock-canon-1`` domain. Raised before anything is durable.
        AirlockError: the key is already claimed by a DIFFERENT action type —
            a cross-action key collision that must never be absorbed silently
            (the other action's outcome would be returned and this action's
            side effect silently skipped).
        VerificationUnknown: the post-verify probe answered ``unknown`` (or
            itself failed) — the honest non-answer. The row stays
            ``executing`` with the evidence recorded; the P1.3 reconciler
            (``python -m airlock reconcile``) resolves it. Do not retry.
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

    # args_json is persisted as canonical JSON at claim time (PLAN 4.2/5.1)
    # and rehydrated by the P1.3 reconciler for verify/preconditions/retry, so
    # the airlock-canon-1 value domain is enforced HERE, before anything is
    # durable — regardless of whether the key came from derive_key (which
    # canonicalizes as a side effect of hashing) or namespace_user_key (which
    # never sees the args). A float smuggled past the claim would rehydrate as
    # a float, the probe (written against canonical values — decimal strings)
    # would answer 'absent' for an effect that happened, and the recovery
    # table would re-execute: the double-commit the prime directive forbids.
    canonical_json(dict(args_json))

    guarantee = effect.guarantee
    # Derived BEFORE the claim: a broken map_key must fail before anything is
    # durable, and the claim persists exactly the post-map value that execute
    # will receive (the probe and the P1.3 reconciler depend on stored ==
    # sent).
    downstream_key = effect.downstream_key_for(key)
    if guarantee is Guarantee.NONE:
        _warn_at_most_once(action_type)

    # Step 1 — claim, committed in its own transaction before anything runs.
    claim = store.claim(key, action_type, guarantee, args_json, downstream_key)
    if not claim.won:
        if claim.record.action_type != action_type:
            # Belt-and-braces under ADR-1: key derivation/namespacing makes
            # cross-action-type key collisions impossible, but silently
            # returning ANOTHER action's outcome (and never executing this
            # one) would be a lost side effect plus a ledger that "proves"
            # the wrong thing — so any residual collision fails loudly.
            raise AirlockError(
                f"idempotency key {key!r} is already claimed by action type "
                f"{claim.record.action_type!r}, but this call is for action type "
                f"{action_type!r} — two different actions derived the same ledger key. "
                "Refusing to return the other action's outcome; fix the key derivation "
                "or override (contracts/idempotency.md §4)."
            )
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
            return CommitOutcome(key=key, state=LedgerState.ABORTED, guarantee=guarantee)
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

    # Step 4 — the side effect.
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

    # Step 5 — post-verify, when the effect has a probe (PLAN.md 4.1 step 5).
    if effect.verify is not None:
        verify_outcome = _post_verify(
            store,
            effect,
            key=key,
            epoch=epoch,
            guarantee=guarantee,
            args_json=args_json,
            wait=wait,
            wait_timeout=wait_timeout,
            poll_interval=poll_interval,
        )
        if verify_outcome is not None:
            return verify_outcome
        # None -> the probe answered `present`; proceed to finalize committed.

    # Step 6 — finalize committed (audit append joins this transaction in P2.2).
    if store.finalize(key, epoch, LedgerState.COMMITTED, result, None):
        return CommitOutcome(
            key=key, state=LedgerState.COMMITTED, guarantee=guarantee, result=result
        )
    # Fenced: a takeover owns resolution — never override it. Report whatever
    # the ledger converges to.
    return _await_terminal(
        store, key, wait=wait, wait_timeout=wait_timeout, poll_interval=poll_interval
    )


def _warn_at_most_once(action_type: str) -> None:
    """Warn (once per action type per process) about at-most-once mode.

    The action type is registered only AFTER ``warnings.warn`` returns
    normally: under ``-W error::airlock.AtMostOnceWarning`` (the strict-mode
    escalation the ``errors.py`` docstring recommends) the warn call raises,
    so EVERY subsequent call for the action type must re-warn and re-raise —
    registering first would disarm strict mode after its first sighting and
    let a retry loop execute the unverifiable effect ops believed was blocked
    (SPEC section 5, scenario 7). When the warning is merely displayed or
    logged, the once-per-process dedup is unchanged.
    """
    if action_type in _at_most_once_warned:
        return
    warnings.warn(
        AtMostOnceWarning(
            f"action type {action_type!r} runs AT-MOST-ONCE: its Effect has neither "
            "key_param (downstream idempotency) nor verify (a probe), so exactly-once "
            "is refused (ADR-2). If a crash lands mid-execute, the ledger row is "
            "finalized 'unknown' and NEVER blind-retried (SPEC section 5, scenario 7). "
            "Provide Effect(key_param=...) or Effect(verify=...) to restore "
            "exactly-once. The 'none' guarantee is stamped durably on every ledger row "
            "this action writes."
        ),
        stacklevel=3,
    )
    _at_most_once_warned.add(action_type)


def _post_verify(
    store: Store,
    effect: Effect,
    *,
    key: str,
    epoch: int,
    guarantee: Guarantee,
    args_json: Mapping[str, JsonValue],
    wait: bool,
    wait_timeout: float,
    poll_interval: float,
) -> CommitOutcome | None:
    """Run the probe after a successful execute; ``None`` means proceed.

    - ``present`` → return ``None``: the caller finalizes ``committed``.
    - ``absent``  → finalize ``failed`` with the evidence recorded — executed
      and confirmed not to have taken effect (PLAN.md section 3.2).
    - ``unknown`` (or the probe itself raised / returned garbage) → the
      honest non-answer: leave the row ``executing`` with the evidence
      recorded and raise :class:`VerificationUnknown` naming the P1.3
      reconciler — consistent with how stale-loser waits behave. No terminal
      state would be truthful, so none is written.
    """
    assert effect.verify is not None  # caller-checked; narrows the type
    probe_error: Exception | None = None
    evidence: Any | None = None
    try:
        answer, evidence = effect.verify(**dict(args_json))
        verification = Verification(answer)
    except Exception as exc:  # a broken probe proves nothing => unknown
        verification = Verification.UNKNOWN
        probe_error = exc
        evidence = None

    if verification is Verification.PRESENT:
        return None

    if verification is Verification.ABSENT:
        error_payload: dict[str, JsonValue] = {
            "post_verify": Verification.ABSENT.value,
            "evidence": _json_safe(evidence),
        }
        # Two epoch-guarded writes; a fenced (or crashed-between) record_error
        # leaves evidence resolution to whoever owns the row. A record_error
        # that RAISES (transient infrastructure failure) must not veto the
        # truthful terminal state — the probe PROVED absence, so 'failed' is
        # the honest outcome (PLAN 4.1 step 5: absent -> finalize failed); the
        # evidence still reaches the caller on the outcome, flagged as not
        # having landed durably.
        try:
            store.record_error(key, epoch, error_payload)
        except Exception as record_exc:
            error_payload["evidence_write_failed"] = repr(record_exc)
        if store.finalize(key, epoch, LedgerState.FAILED, None, None):
            return CommitOutcome(
                key=key, state=LedgerState.FAILED, guarantee=guarantee, error=error_payload
            )
        # Fenced: a takeover owns resolution.
        return _await_terminal(
            store, key, wait=wait, wait_timeout=wait_timeout, poll_interval=poll_interval
        )

    # unknown — the honest non-answer (PLAN.md 4.1 step 5).
    unknown_payload: dict[str, JsonValue] = {"post_verify": Verification.UNKNOWN.value}
    if probe_error is not None:
        unknown_payload["probe_error"] = {
            "type": type(probe_error).__name__,
            "message": str(probe_error),
        }
    elif evidence is not None:
        unknown_payload["evidence"] = _json_safe(evidence)
    unknown_exc = VerificationUnknown(
        f"post-verify for key {key!r} answered 'unknown': the effect executed but the "
        "probe could not prove it present OR absent, so no terminal state would be "
        "truthful. The row stays 'executing' with the evidence recorded; resolve it "
        "with the verification-first reconciler (P1.3: python -m airlock reconcile). "
        "Do NOT retry — the ledger still holds the claim.",
        key=key,
        evidence=None if probe_error is not None else evidence,
    )
    try:
        # A fenced write is fine to ignore — the takeover owns the evidence trail.
        store.record_error(key, epoch, unknown_payload)
    except Exception as record_exc:
        unknown_exc.add_note(
            f"airlock: recording the probe evidence on the ledger row failed "
            f"({record_exc!r}); the row still stays 'executing' for the reconciler (P1.3)"
        )
    if probe_error is not None:
        raise unknown_exc from probe_error
    raise unknown_exc


def _json_safe(value: Any) -> JsonValue:
    """Best-effort JSON coercion for probe evidence headed to ``error_json``.

    Evidence should be JSON-safe; when it is not, its ``repr`` is recorded
    rather than losing the ledger write (the evidence trail must survive a
    sloppy probe). ``allow_nan=False`` is essential: ``json.dumps`` would
    otherwise certify ``float('nan')``/``inf`` evidence as safe, and the
    store's JSONB cast would then reject the bare ``NaN`` token — stranding
    the row ``executing`` on the absent path instead of finalizing ``failed``.
    """
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError):
        return repr(value)
    return cast(JsonValue, value)


def _outcome_from(record: CommitRecord) -> CommitOutcome:
    return CommitOutcome(
        key=record.idempotency_key,
        state=record.state,
        guarantee=record.guarantee,
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
