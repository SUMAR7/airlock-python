"""``apply_decision`` — the ensure-committed core of the durable pause (ADR-4).

ONE idempotent function, shared by EVERY path that receives a decision — the
transport wait-loop (``@guard``'s GATE path), a manual ``Airlock.resume``, the
P3.4 webhook receiver, and the reconciler's paused sweep (PLAN.md 4.3). Its
semantics are what make double / late / racing deliveries safe *and* live:

1. CAS ``proposed -> approved|rejected`` keyed on ``approval_ref``.
2. **Regardless of who won the CAS**, read the current status and drive it to
   terminal:

   - ``rejected``  -> transition ``rejected -> aborted`` (+ the chained
     ``pause_transition`` record AND the terminal ``action_event`` in the SAME
     transaction as the CAS), return the recorded outcome.
   - ``approved``  -> proceed into ``commit_once`` anyway — the commit LEDGER
     dedupes concurrent appliers (double-approval cannot double-commit,
     ADR-4), preconditions are re-validated inside (scenario 8: the
     propose-time snapshot lives in ``serialized_state`` and the registered
     ``preconditions`` callable gets the REHYDRATED args) — then
     ``approved -> committed`` (or ``-> aborted`` on precondition failure /
     any non-committed ledger terminal), setting ``resolved_at``.
   - ``committed | aborted`` -> pure no-op returning the recorded outcome
     (zero writes).

A lost CAS is **NOT** a no-op (PLAN.md 10, settled decision 3): "already
approved but never committed" — a crash between the approve CAS and the
commit, or a webhook receiver applying the status while the waiting agent
loses the race — must still drive to commit. The
``after_approve_cas_before_commit`` crashpoint test pins it, and the
reconciler's paused sweep (``airlock.reconcile``) closes the window when no
redelivery ever arrives.

Liveness vs. honesty: if ``commit_once`` cannot reach a truthful terminal
state (``VerificationUnknown``, a raising execute, a fenced wait), the
exception propagates and the run STAYS ``approved`` — redelivery or the next
sweep re-drives it once the ledger row is resolvable. An approved run only
leaves ``approved`` for a state that is actually true.

Event emission (PLAN.md 6.3): the gate's ONE terminal ``action_event``
(policy_decision=gate, human_decision, decided_by, decision_latency_ms,
outcome) is emitted at the terminal transition — inside ``commit_once``'s
finalize transaction on the approved path, inside the ``rejected -> aborted``
CAS transaction on the rejected path — by exactly the applier whose CAS won,
so double deliveries never double-emit. ``pause_transition`` audit events
additionally evidence every status edge, each atomic with its CAS.

Import-light: stdlib + pydantic + the airlock core (no extras).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, JsonValue

from airlock.audit import rfc3339_utc
from airlock.errors import AirlockError, StateVersionError, UnknownApprovalRef
from airlock.events import (
    ActionEventContext,
    EventSink,
    PostVerify,
    build_action_event,
    emit_action_event,
)
from airlock.registry import Registration, Registry
from airlock.registry import registry as default_registry
from airlock.types import (
    ActionOutcome,
    AuditEvent,
    BlastRadius,
    CommitOutcome,
    Decision,
    HumanDecision,
    LedgerState,
    Money,
    PausedRun,
    PauseStatus,
    Reversibility,
)

if TYPE_CHECKING:
    from airlock.store import Store
    from airlock.types import ApprovalDecision

__all__ = [
    "PAUSE_TRANSITION_EVENT_TYPE",
    "STATE_VERSION",
    "DecisionOutcome",
    "apply_decision",
    "build_serialized_state",
    "pause_transition_event",
]

#: The ``audit_events.event_type`` for pause status transitions (P2.3): one
#: chained row per ADR-4 edge, appended in the SAME transaction as the CAS.
PAUSE_TRANSITION_EVENT_TYPE = "pause_transition"

#: The serialized_state layout version THIS SDK writes and understands.
#: Rehydration refuses any other value loudly (StateVersionError) — an unknown
#: serialization is never misparsed into a subtly different action.
STATE_VERSION = 1


def _utcnow() -> datetime:
    return datetime.now(UTC)


class DecisionOutcome(BaseModel):
    """What one ``apply_decision`` call observed / produced.

    ``status`` is the paused run's status AFTER this call (terminal on every
    path except a decision-less drive of a still-``proposed`` run).
    ``applied`` says whether THIS call performed any durable transition —
    ``False`` means the recorded outcome was merely read back (the scenario-5
    duplicate delivery), which the no-op tests pin as zero writes.
    ``ledger_state`` / ``result`` surface the commit ledger's terminal row for
    the action, when one exists (a rejection never claims the ledger).
    """

    model_config = ConfigDict(frozen=True)

    run_id: str
    approval_ref: str
    action_type: str
    status: PauseStatus
    applied: bool
    human_decision: HumanDecision | None = None
    decided_by: str | None = None
    ledger_state: LedgerState | None = None
    result: JsonValue = None


def build_serialized_state(
    arg_map: dict[str, JsonValue],
    *,
    reversibility: Reversibility,
    cost: Money | None,
    blast_radius: BlastRadius | None,
    precondition_snapshot: dict[str, JsonValue] | None,
) -> dict[str, JsonValue]:
    """The ``serialized_state`` payload (STATE_VERSION 1) for one gated call.

    Canonical JSON only (never pickle — PLAN.md 3.3 call-time flow), so resume
    works across deploys and languages: the arg_map (the SAME canonical map the
    idempotency key was derived over), the resolved risk metadata (needed to
    rebuild the terminal ``action_event`` after a restart), and the
    propose-time precondition snapshot (scenario 8's "before" evidence).
    """
    risk: dict[str, JsonValue] = {
        "reversibility": reversibility.value,
        "cost": None if cost is None else {"amount": cost.amount, "currency": cost.currency},
        "blast_radius": None if blast_radius is None else blast_radius.value,
    }
    return {
        "arg_map": dict(arg_map),
        "risk": risk,
        "preconditions": precondition_snapshot,
    }


def pause_transition_event(
    run_id: str,
    *,
    approval_ref: str,
    action_type: str,
    idempotency_key: str,
    from_status: PauseStatus | None,
    to_status: PauseStatus,
    now_fn: Callable[[], datetime] = _utcnow,
    decided_by: str | None = None,
    detail: dict[str, JsonValue] | None = None,
) -> AuditEvent:
    """Build the chained audit event for one ADR-4 status edge.

    Small, fully-controlled vocabulary (statuses, ids, an optional detail
    object) so the payload always lies in the airlock-canon-1 domain — the
    same posture as the reconciler's ``reconcile`` events. ``from_status`` is
    ``None`` for the creation edge (nothing -> proposed).
    """
    payload: dict[str, JsonValue] = {
        "run_id": run_id,
        "approval_ref": approval_ref,
        "idempotency_key": idempotency_key,
        "from_status": None if from_status is None else from_status.value,
        "to_status": to_status.value,
        "decided_by": decided_by,
        "at": rfc3339_utc(now_fn()),
    }
    if detail is not None:
        payload["detail"] = detail
    return AuditEvent(
        event_type=PAUSE_TRANSITION_EVENT_TYPE,
        run_id=run_id,
        action_type=action_type,
        payload=payload,
        created_at=now_fn(),
    )


def apply_decision(
    store: Store,
    approval_ref: str,
    decision: ApprovalDecision | None,
    *,
    registry: Registry | None = None,
    event_sinks: Sequence[EventSink] = (),
    reconcile_after: timedelta | None = None,
    execute_timeout: timedelta | None = None,
    wait_timeout: float = 30.0,
    now_fn: Callable[[], datetime] = _utcnow,
) -> DecisionOutcome:
    """Apply (or re-apply) a decision to a paused run — idempotent, ensure-committed.

    See the module docstring for the semantics (PLAN.md 4.3). Every caller —
    transport wait-loop, manual resume, webhook, reconciler sweep — goes
    through here; there is no second implementation of "a decision arrived".

    Args:
        store: the customer's Store (pause rows + commit ledger + audit chain).
        approval_ref: the SDK-minted reference identifying the paused run —
            the only cross-boundary key (PLAN.md 6.1).
        decision: the fresh human decision, or ``None`` to drive the run's
            CURRENT status to terminal without one (the reconciler sweep's
            mode; also correct for redelivery when the payload was already
            consumed). With ``None`` a still-``proposed`` run is returned
            untouched — a decision is never invented.
        registry: where the run's ``action_type`` finds its recovery wiring
            (effect / execute / preconditions), exactly like the reconciler;
            defaults to the process-wide registry ``@guard`` populates. An
            approved run whose action_type is unregistered raises — guessing
            would execute the wrong code.
        event_sinks: best-effort mirrors for the terminal ``action_event``.
        reconcile_after: forwarded to ``commit_once`` (inline recovery of a
            stale in-flight ledger row while resuming).
        execute_timeout: forwarded to ``commit_once`` (the owner execute
            deadline; must be < reconcile_after when both are set).
        wait_timeout: how long a losing concurrent applier polls the ledger
            for the winner's terminal outcome (seconds).
        now_fn: the injectable clock (decision timestamps, event emitted_at).

    Returns:
        A :class:`DecisionOutcome` — the run's (usually terminal) status plus
        the ledger outcome where one exists. Duplicate deliveries return the
        SAME recorded outcome with ``applied=False``.

    Raises:
        UnknownApprovalRef: no paused run matches ``approval_ref``.
        StateVersionError: the run's ``state_version`` is not
            :data:`STATE_VERSION` — refused loudly, never misparsed.
        NotImplementedError: ``decision.edited_args`` is set (reserved until
            the edit-before-approve phase; also enforced at construction).
        AirlockError: the approved run's ``action_type`` has no registration,
            or its ``serialized_state`` is structurally broken.
        VerificationUnknown / ExecuteTimeout / CommitWaitTimeout / Exception:
            propagated from ``commit_once`` — the run STAYS ``approved`` and
            the next delivery / sweep re-drives it (ensure-committed).
    """
    run = store.load_paused_by_ref(approval_ref)
    if run is None:
        raise UnknownApprovalRef(
            f"no paused run exists for approval_ref {approval_ref!r} — the decision "
            "matched nothing in this database (wrong environment, or a fabricated "
            "reference). Nothing was changed.",
            approval_ref=approval_ref,
        )
    if run.state_version != STATE_VERSION:
        raise StateVersionError(
            f"paused run {run.run_id!r} (approval_ref {approval_ref!r}) has "
            f"state_version={run.state_version}, but this SDK understands only "
            f"{STATE_VERSION}. Refusing to rehydrate: parsing an unknown serialization "
            "could execute a different action than the one a human approved. The run "
            "was left untouched (scenario 6's loud-refusal gate).",
            run_id=run.run_id,
            approval_ref=run.approval_ref,
            found=run.state_version,
            supported=STATE_VERSION,
        )
    if decision is not None and decision.edited_args is not None:  # defense in depth
        raise NotImplementedError(
            "ApprovalDecision.edited_args is reserved for the edit-before-approve phase "
            "(post-MVP) and must be None in v1."
        )

    applied = False

    # Step 1 — the decision CAS: proposed -> approved|rejected, keyed on the
    # run the approval_ref resolved. Attempted whenever a fresh decision is in
    # hand; losing it is expected under double delivery and changes NOTHING
    # about what follows (step 2 drives whatever the recorded status is).
    if decision is not None:
        normalized = _normalize_decision(decision, run, now_fn)
        to_status = (
            PauseStatus.APPROVED
            if normalized.decision is HumanDecision.APPROVED
            else PauseStatus.REJECTED
        )
        cas_event = pause_transition_event(
            run.run_id,
            approval_ref=run.approval_ref,
            action_type=run.action_type,
            idempotency_key=run.idempotency_key,
            from_status=PauseStatus.PROPOSED,
            to_status=to_status,
            now_fn=now_fn,
            decided_by=normalized.decided_by,
        )
        if store.transition_paused(
            run.run_id,
            PauseStatus.PROPOSED,
            to_status,
            decision=normalized,
            audit=cas_event,
        ):
            applied = True

    # Step 2 — REGARDLESS of who won the CAS: read the current status and
    # drive it to terminal (PLAN.md 4.3 — a lost CAS is NOT a no-op).
    # Statuses only move forward along the ADR-4 DAG, so this loop reaches a
    # return in at most a handful of re-reads even under heavy racing.
    for _ in range(8):
        current = store.load_paused_by_ref(approval_ref)
        if current is None:  # rows are never deleted (ADR-4)
            raise AirlockError(
                f"paused run for approval_ref {approval_ref!r} disappeared mid-apply — "
                "paused_runs rows must never be deleted (ADR-4)"
            )
        if current.status is PauseStatus.PROPOSED:
            # No decision was (or could be) applied and none is recorded:
            # nothing to drive. Never invent a decision.
            return _outcome(current, applied=applied, store=store)
        if current.status is PauseStatus.REJECTED:
            reg = registry if registry is not None else default_registry
            if _drive_rejected(store, current, event_sinks, now_fn, reg):
                applied = True
            continue  # re-read: rejected -> aborted (ours or a racer's)
        if current.status is PauseStatus.APPROVED:
            drove = _drive_approved(
                store,
                current,
                registry=registry if registry is not None else default_registry,
                event_sinks=event_sinks,
                reconcile_after=reconcile_after,
                execute_timeout=execute_timeout,
                wait_timeout=wait_timeout,
                now_fn=now_fn,
            )
            if drove:
                applied = True
            continue  # re-read: approved -> committed|aborted
        # committed | aborted — terminal: return the recorded outcome.
        return _outcome(current, applied=applied, store=store)
    raise AirlockError(  # pragma: no cover — forward-only statuses make this unreachable
        f"apply_decision for approval_ref {approval_ref!r} did not settle after 8 "
        "re-reads; the paused run's status is not converging"
    )


def _normalize_decision(
    decision: ApprovalDecision, run: PausedRun, now_fn: Callable[[], datetime]
) -> ApprovalDecision:
    """Fill decided_at / decision_latency_ms so the persisted row is complete.

    ``decided_at`` defaults to the SDK clock. ``decision_latency_ms`` is
    recorded VERBATIM when the transport delivered one (the control plane
    computes it from its own clock pair — PLAN.md 6.2); when absent (the local
    console stub), it is computed from ``decided_at - run.created_at`` — both
    timestamps come from the SAME SDK/store clock, so no cross-host skew can
    pollute the signal.
    """
    decided_at = decision.decided_at if decision.decided_at is not None else now_fn()
    latency = decision.decision_latency_ms
    if latency is None:
        latency = max(0, int((decided_at - run.created_at).total_seconds() * 1000))
    return dataclasses.replace(decision, decided_at=decided_at, decision_latency_ms=latency)


def _drive_rejected(
    store: Store,
    run: PausedRun,
    event_sinks: Sequence[EventSink],
    now_fn: Callable[[], datetime],
    registry: Registry,
) -> bool:
    """rejected -> aborted: the CAS + BOTH audit records in one transaction.

    The terminal ``action_event`` (policy_decision=gate,
    human_decision=rejected, outcome=aborted — no ledger row is ever claimed
    for a rejection) and the ``pause_transition`` record ride INSIDE the CAS
    transaction, so exactly the applier whose CAS wins emits them — a double
    delivery cannot double-emit. Returns whether OUR CAS won.
    """
    ctx = _event_context_from(run, event_sinks)
    action_event = build_action_event(
        ctx,
        idempotency_key=run.idempotency_key,
        action_type=run.action_type,
        guarantee=_guarantee_for(run, registry),
        outcome=ActionOutcome.ABORTED,
        post_verify=PostVerify(ran=False),
        now_fn=now_fn,
    )
    transition = pause_transition_event(
        run.run_id,
        approval_ref=run.approval_ref,
        action_type=run.action_type,
        idempotency_key=run.idempotency_key,
        from_status=PauseStatus.REJECTED,
        to_status=PauseStatus.ABORTED,
        now_fn=now_fn,
        decided_by=run.decided_by,
        detail={"reason": "human_rejected"},
    )
    won = store.transition_paused(
        run.run_id,
        PauseStatus.REJECTED,
        PauseStatus.ABORTED,
        audit=(transition, action_event.to_audit_event()),
    )
    if won:
        emit_action_event(tuple(event_sinks), action_event)
    return won


def _drive_approved(
    store: Store,
    run: PausedRun,
    *,
    registry: Registry,
    event_sinks: Sequence[EventSink],
    reconcile_after: timedelta | None,
    execute_timeout: timedelta | None,
    wait_timeout: float,
    now_fn: Callable[[], datetime],
) -> bool:
    """approved -> committed|aborted, THROUGH the commit ledger (ensure-committed).

    Rehydrates the call from ``serialized_state`` + the action registry
    (scenario 6) and proceeds into ``commit_once`` unconditionally — the
    ledger's ``UNIQUE(idempotency_key)`` dedupes concurrent appliers and prior
    partial progress (a crash after the ledger finalize but before the pause
    CAS re-enters here and merely reads the recorded ledger outcome back).
    Preconditions are re-validated INSIDE ``commit_once`` (scenario 8), with
    the recheck verdict captured for the audit record. Returns whether OUR
    pause CAS won the terminal edge.
    """
    registration = registry.get(run.action_type)
    if registration is None:
        raise AirlockError(
            f"approved paused run {run.run_id!r} cannot resume: action_type "
            f"{run.action_type!r} has no registration in this process — import the "
            "module that defines the @guard'ed tool (or register it) before resuming. "
            "Guessing the execute/effect would run the wrong code (PLAN.md 4.2)."
        )
    arg_map = _rehydrated_arg_map(run)

    def execute(downstream_key: str | None) -> JsonValue:
        return registration.execute(downstream_key, **arg_map)

    recheck: dict[str, JsonValue] = {}
    preconditions = _recording_preconditions(registration, arg_map, recheck, now_fn)

    ctx = _event_context_from(run, event_sinks)
    outcome: CommitOutcome = commit_once_for_pause(
        store,
        run=run,
        execute=execute,
        registration=registration,
        preconditions=preconditions,
        arg_map=arg_map,
        reconcile_after=reconcile_after,
        execute_timeout=execute_timeout,
        wait_timeout=wait_timeout,
        event_context=ctx,
        now_fn=now_fn,
    )

    if outcome.state is LedgerState.COMMITTED:
        transition = pause_transition_event(
            run.run_id,
            approval_ref=run.approval_ref,
            action_type=run.action_type,
            idempotency_key=run.idempotency_key,
            from_status=PauseStatus.APPROVED,
            to_status=PauseStatus.COMMITTED,
            now_fn=now_fn,
            decided_by=run.decided_by,
            detail={"ledger_state": outcome.state.value},
        )
        return store.transition_paused(
            run.run_id, PauseStatus.APPROVED, PauseStatus.COMMITTED, audit=transition
        )

    # Non-committed terminal (aborted on precondition failure; failed/unknown
    # read back from a prior degraded attempt): the run resolves ABORTED — "we
    # chose not to execute / it did not commit" — with the ledger state and
    # BOTH precondition snapshots (propose-time + commit-time recheck) on the
    # chained record (scenario 8's evidence requirement).
    detail: dict[str, JsonValue] = {"ledger_state": outcome.state.value}
    if outcome.state is LedgerState.ABORTED:
        # 'aborted' with a recorded failing recheck is THIS call's stale-approval
        # abort (scenario 8); an aborted row read back from an earlier actor
        # (e.g. a reconciler OnAbsent.ABORT) carries no fresh recheck.
        detail["reason"] = (
            "precondition_failed" if recheck.get("held") is False else "ledger_aborted_previously"
        )
        detail["precondition_snapshot"] = _proposed_precondition_snapshot(run)
        detail["precondition_recheck"] = dict(recheck) if recheck else None
    transition = pause_transition_event(
        run.run_id,
        approval_ref=run.approval_ref,
        action_type=run.action_type,
        idempotency_key=run.idempotency_key,
        from_status=PauseStatus.APPROVED,
        to_status=PauseStatus.ABORTED,
        now_fn=now_fn,
        decided_by=run.decided_by,
        detail=detail,
    )
    return store.transition_paused(
        run.run_id, PauseStatus.APPROVED, PauseStatus.ABORTED, audit=transition
    )


def commit_once_for_pause(
    store: Store,
    *,
    run: PausedRun,
    execute: Callable[[str | None], JsonValue],
    registration: Registration,
    preconditions: Callable[[], bool] | None,
    arg_map: dict[str, JsonValue],
    reconcile_after: timedelta | None,
    execute_timeout: timedelta | None,
    wait_timeout: float,
    event_context: ActionEventContext,
    now_fn: Callable[[], datetime],
) -> CommitOutcome:
    """The one ``commit_once`` call every approved resume goes through.

    Split out (module-level, kwargs-only) so the crashpoint harness can wrap
    the store around exactly this boundary; behaviorally it is nothing but
    ``commit_once`` with the run's rehydrated wiring.
    """
    from airlock.commit import commit_once

    return commit_once(
        store,
        key=run.idempotency_key,
        action_type=run.action_type,
        execute=execute,
        effect=registration.effect,
        preconditions=preconditions,
        args_json=arg_map,
        wait_timeout=wait_timeout,
        reconcile_after=reconcile_after,
        execute_timeout=execute_timeout,
        event_context=event_context,
        now_fn=now_fn,
    )


def _recording_preconditions(
    registration: Registration,
    arg_map: dict[str, JsonValue],
    recheck: dict[str, JsonValue],
    now_fn: Callable[[], datetime],
) -> Callable[[], bool] | None:
    """Wrap the REGISTERED preconditions over the REHYDRATED args (scenario 8).

    The wrapper records the commit-time verdict into ``recheck`` so the
    aborted path's audit record can carry both snapshots. A precondition that
    RAISES is treated as not holding (the safe direction — same coercion as
    the reconciler). ``None`` when the action registered no preconditions.
    """
    if registration.preconditions is None:
        return None
    registered = registration.preconditions

    def preconditions() -> bool:
        try:
            held = bool(registered(**dict(arg_map)))
        except Exception as exc:
            recheck["held"] = False
            recheck["error"] = f"{type(exc).__name__}: {exc}"
            recheck["at"] = rfc3339_utc(now_fn())
            return False
        recheck["held"] = held
        recheck["at"] = rfc3339_utc(now_fn())
        return held

    return preconditions


def _rehydrated_arg_map(run: PausedRun) -> dict[str, JsonValue]:
    arg_map = run.serialized_state.get("arg_map")
    if not isinstance(arg_map, dict):
        raise AirlockError(
            f"paused run {run.run_id!r} has a structurally broken serialized_state: "
            f"'arg_map' is {type(arg_map).__name__}, expected an object. Refusing to "
            "resume from state that cannot be rehydrated faithfully."
        )
    return arg_map


def _proposed_precondition_snapshot(run: PausedRun) -> JsonValue:
    return run.serialized_state.get("preconditions")


def _event_context_from(run: PausedRun, event_sinks: Sequence[EventSink]) -> ActionEventContext:
    """Rebuild the decision-time event half from the persisted risk metadata.

    After a restart the original ``@guard`` context is gone; the resolved
    reversibility/cost/blast_radius were persisted in ``serialized_state`` for
    exactly this reconstruction, and the human half (decision, actor, latency)
    comes from the row itself.
    """
    risk = run.serialized_state.get("risk")
    risk_map: dict[str, Any] = risk if isinstance(risk, dict) else {}
    reversibility = Reversibility(risk_map.get("reversibility", Reversibility.UNKNOWN.value))
    raw_cost = risk_map.get("cost")
    cost = (
        Money(amount=raw_cost["amount"], currency=raw_cost["currency"])
        if isinstance(raw_cost, dict)
        else None
    )
    raw_blast = risk_map.get("blast_radius")
    blast = BlastRadius(raw_blast) if isinstance(raw_blast, str) else None
    human = _human_decision_for(run)
    return ActionEventContext(
        run_id=run.run_id,
        policy_decision=Decision.GATE,
        reversibility=reversibility,
        cost=cost,
        blast_radius=blast,
        human_decision=human,
        decided_by=run.decided_by,
        decision_latency_ms=run.decision_latency_ms,
        sinks=tuple(event_sinks),
    )


def _human_decision_for(run: PausedRun) -> HumanDecision | None:
    """The human decision for the run being DRIVEN (status approved/rejected).

    Only the two intermediate statuses reach the event-context builder — the
    approved path emits inside the ledger finalize, the rejected path inside
    the rejected->aborted CAS — so the mapping is direct.
    """
    if run.status in (PauseStatus.APPROVED, PauseStatus.COMMITTED):
        return HumanDecision.APPROVED
    if run.status is PauseStatus.REJECTED:
        return HumanDecision.REJECTED
    return None


def _guarantee_for(run: PausedRun, registry: Registry) -> Any:
    """The ADR-2 guarantee for the run's action, from the registry when known.

    The rejected path needs a guarantee for the action_event but never
    executes anything; when the action_type is not registered in this process
    (a receiver that rejects without the tool module imported), the honest
    floor is ``none``.
    """
    from airlock.types import Guarantee

    registration = registry.get(run.action_type)
    return registration.effect.guarantee if registration is not None else Guarantee.NONE


def _outcome(run: PausedRun, *, applied: bool, store: Store) -> DecisionOutcome:
    """Assemble the returned outcome, surfacing the ledger's terminal row if any."""
    ledger_state: LedgerState | None = None
    result: JsonValue = None
    if run.status in (PauseStatus.COMMITTED, PauseStatus.ABORTED):
        record = store.load(run.idempotency_key)
        if record is not None:
            ledger_state = record.state
            result = record.result_json
    return DecisionOutcome(
        run_id=run.run_id,
        approval_ref=run.approval_ref,
        action_type=run.action_type,
        status=run.status,
        applied=applied,
        human_decision=_recorded_human_decision(run, ledger_state),
        decided_by=run.decided_by,
        ledger_state=ledger_state,
        result=result,
    )


def _recorded_human_decision(
    run: PausedRun, ledger_state: LedgerState | None
) -> HumanDecision | None:
    """The recorded human decision for a (possibly terminal) run.

    committed / approved -> approved. aborted -> rejected when the ledger was
    never claimed for this key (a rejection never touches the ledger), else
    approved (approved-then-aborted: preconditions failed at commit time).
    proposed -> None (no decision yet).
    """
    if run.status is PauseStatus.PROPOSED:
        return None
    if run.status in (PauseStatus.APPROVED, PauseStatus.COMMITTED):
        return HumanDecision.APPROVED
    if run.status is PauseStatus.REJECTED:
        return HumanDecision.REJECTED
    # ABORTED: discriminate by the ledger.
    return HumanDecision.REJECTED if ledger_state is None else HumanDecision.APPROVED
