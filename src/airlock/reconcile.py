"""The reconciler — verify-first recovery of stale in-flight rows (PLAN.md 4.2).

A crash can leave a ``commit_records`` row stuck ``pending`` (claimed, effect
provably not started) or ``executing`` (effect may or may not have landed).
The reconciler recovers those rows WITHOUT ever blind-re-executing: recovery
starts with verification, and re-execution happens only where the ledger state
proves the effect never started, or a probe/preconditions prove it safe.

**One pure function, three invocation models.** :func:`reconcile` is the whole
engine; :mod:`airlock` ships three thin wrappers over it (PLAN.md 4.2):

- inline-targeted — a ``commit_once`` loser that hits a stale in-flight row
  runs :func:`reconcile_key` for that one key (``airlock.commit``), so the
  never-blind-re-execute guarantee holds on the hot path with zero operator
  setup;
- the CLI — ``python -m airlock reconcile`` (``airlock.__main__``) for
  cron/k8s;
- the startup hook — :func:`reconcile_on_startup`, a plain function callers
  may invoke from their boot sequence (opt-in; NOT an always-on daemon —
  a background thread is explicitly out of P1.3 scope).

**The takeover fence comes first, always.** For every stale row the reconciler
FIRST calls :meth:`~airlock.store.Store.bump_epoch`. If it returns ``None`` the
row was already resolved (terminal) or refreshed (another reconciler took it,
or the original owner is alive) — the reconciler skips it. Otherwise the epoch
is bumped and the original owner is fenced: its ``mark_executing`` /
``finalize`` / ``record_error`` all carry ``WHERE attempts = <its old epoch>``,
so it can no longer execute or finalize (PLAN.md section 10 point 2). The
residual race — the reconciler probes ``absent`` while a slow owner is
mid-execute — is bounded by the enforced ``execute_timeout < reconcile_after``
ordering (PLAN.md 4.1): :func:`reconcile` / :func:`reconcile_key` take an
``execute_timeout`` and validate it ``< older_than`` via :class:`ExecuteWindow`
BEFORE scanning (a misconfigured window is refused with ``ValueError``, never
run), and ``commit_once`` bounds each owner's ``execute`` by the same timeout so
an owner is provably out of ``execute`` before its row is recover-eligible. Both
halves are covered by the named slow-owner race test
(``tests/test_reconcile_race.py``, ``@pytest.mark.race``): a live owner blocked
inside ``execute`` while a reconciler bumps the epoch and retries yields exactly
one effect, and the fenced owner's ``finalize`` matches zero rows.

**The recovery table (PLAN.md 4.2), dispatched on (state, guarantee):**

======================  ======================  ================================
state                   guarantee               recovery
======================  ======================  ================================
``pending``             any                     provably effect-free — re-run
                                                 the execute path (retry) or
                                                 ``finalize('aborted')`` per
                                                 ``on_absent``. No probe.
``executing``           ``verifiable``          probe. present -> committed;
                                                 absent -> retry/abort;
                                                 unknown -> leave + escalate.
``executing``           ``downstream_idempotent`` preconditions hold -> re-issue
                                                 with the SAME downstream key
                                                 (downstream dedup IS the
                                                 verification); violated ->
                                                 ``finalize('unknown')``, loud.
``executing``           ``none``                ``finalize('unknown')``, loud,
                                                 never retried (scenario 7).
======================  ======================  ================================

For every path that re-validates preconditions or (re-)executes, the
:class:`~airlock.registry.Registry` supplies the ``effect`` / ``execute`` /
``preconditions`` for the row's ``action_type`` (rehydrated from the ledger).
A row whose ``action_type`` is not registered cannot be recovered by this
reconciler — it is left untouched and counted ``unregistered`` (the operator
forgot ``--import``; guessing would be a blind re-execute).
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any, cast

from pydantic import JsonValue

from airlock.effects import Effect
from airlock.registry import Registration, Registry
from airlock.registry import registry as default_registry
from airlock.types import AuditEvent, CommitRecord, Guarantee, LedgerState, Verification

if TYPE_CHECKING:
    from airlock.events import EventSink

__all__ = [
    "RECONCILE_EVENT_TYPE",
    "ExecuteWindow",
    "OnAbsent",
    "Outcome",
    "PausedSweepAction",
    "PausedSweepReport",
    "ReconcileAction",
    "ReconcileReport",
    "reconcile",
    "reconcile_key",
    "reconcile_on_startup",
    "reconcile_paused",
]

#: The ``audit_events.event_type`` for reconciler evidence rows (PLAN.md 4.2:
#: recovered / escalation events are audit events — chained as of P2.2).
RECONCILE_EVENT_TYPE = "reconcile"


def _utcnow() -> datetime:
    return datetime.now(UTC)


class OnAbsent(StrEnum):
    """What to do when an effect is PROVABLY absent (or provably not started).

    Applies to the ``pending`` path (effect never started) and the
    ``executing`` + ``verifiable`` + ``absent`` path (probe disproved the
    effect). It NEVER applies to ``unknown`` — an unproven effect is never
    retried or aborted-away; it is escalated.

    - ``RETRY`` — re-validate preconditions, then re-run the execute path
      under the bumped epoch. Safe precisely because absence is proven.
    - ``ABORT`` — do not execute; ``finalize('aborted')`` (we chose not to).
    """

    RETRY = "retry"
    ABORT = "abort"


class Outcome(StrEnum):
    """Per-row reconciler outcome (the report's tally keys).

    - ``committed`` — verified present (or re-executed to completion) and
      finalized committed.
    - ``retried_committed`` — an absent/effect-free row was re-executed and
      committed under the bumped epoch.
    - ``aborted`` — finalized aborted (``on_absent=abort``, or preconditions
      violated on a ``pending``/absent retry — recovery re-validates, never
      blind-retries).
    - ``failed`` — a re-execute's own post-verify proved the fresh attempt
      absent; finalized failed.
    - ``unknown`` — finalized unknown: can't prove absence and won't execute
      against a possibly-changed world (``none``, or
      ``downstream_idempotent`` with violated preconditions). Loud evidence.
    - ``escalated`` — left UNTOUCHED (state unchanged): a ``verifiable`` probe
      answered ``unknown``. Evidence recorded; a human/next pass resolves it.
    - ``skipped`` — ``bump_epoch`` returned ``None``: already resolved or
      taken over by another actor. Nothing done.
    - ``unregistered`` — the ``action_type`` has no registration; cannot be
      recovered here. Left untouched.
    - ``reexecute_fenced`` — a re-execute lost its own epoch mid-flight (a
      THIRD actor took over during recovery). Left to that new owner.
    """

    COMMITTED = "committed"
    RETRIED_COMMITTED = "retried_committed"
    ABORTED = "aborted"
    FAILED = "failed"
    UNKNOWN = "unknown"
    ESCALATED = "escalated"
    SKIPPED = "skipped"
    UNREGISTERED = "unregistered"
    REEXECUTE_FENCED = "reexecute_fenced"


@dataclass(frozen=True)
class ReconcileAction:
    """What the reconciler did to one row (for tests + observability)."""

    key: str
    action_type: str
    #: state observed BEFORE recovery (pending or executing).
    from_state: LedgerState
    guarantee: Guarantee
    outcome: Outcome
    #: the epoch bump_epoch assigned (None when skipped/unregistered).
    epoch: int | None = None
    #: JSON-safe evidence recorded on this row (probe result, escalation, ...).
    evidence: JsonValue = None
    #: human-readable note (why unknown/escalated/skipped/...).
    detail: str | None = None


@dataclass(frozen=True)
class ReconcileReport:
    """The result of one :func:`reconcile` pass.

    ``counts`` tallies :class:`Outcome` -> number of rows; ``actions`` is the
    per-key detail in scan order. Both feed the tests and, later, observability
    (the escalation counter especially).
    """

    counts: dict[Outcome, int] = field(default_factory=dict)
    actions: list[ReconcileAction] = field(default_factory=list)

    def _record(self, action: ReconcileAction) -> None:
        self.actions.append(action)
        self.counts[action.outcome] = self.counts.get(action.outcome, 0) + 1

    def count(self, outcome: Outcome) -> int:
        return self.counts.get(outcome, 0)

    @property
    def total(self) -> int:
        return len(self.actions)


@dataclass(frozen=True)
class ExecuteWindow:
    """The enforced ``execute_timeout < reconcile_after`` ordering (PLAN.md 4.1).

    A reconciler must never probe a row while its original owner might still be
    legitimately mid-execute — otherwise a verify-only effect can be probed
    ``absent`` during a live execution and wrongly retried. The library bounds
    that window structurally: an owner's execute must time out
    (``execute_timeout``) strictly before a row is even eligible for recovery
    (``reconcile_after`` == the reconciler's ``older_than``). This dataclass
    carries the pair, validates the ordering at construction, and is the single
    place the invariant is asserted (PLAN.md 4.2 residual-risk mitigation).
    """

    execute_timeout: timedelta
    reconcile_after: timedelta

    def __post_init__(self) -> None:
        if self.execute_timeout <= timedelta(0):
            raise ValueError(f"execute_timeout must be positive, got {self.execute_timeout!r}")
        if self.reconcile_after <= self.execute_timeout:
            raise ValueError(
                "execute_timeout must be < reconcile_after so a stale row is provably past "
                "any live execute before recovery (PLAN.md 4.1): got "
                f"execute_timeout={self.execute_timeout!r}, "
                f"reconcile_after={self.reconcile_after!r}"
            )


def _enforce_execute_window(older_than: timedelta, execute_timeout: timedelta | None) -> None:
    """Assert ``execute_timeout < older_than`` before scanning (PLAN.md 4.1/10.2).

    This is the runtime enforcement of the residual-race mitigation: a
    reconciler must never scan (and therefore never probe/retry) a row while its
    original owner might still be legitimately mid-execute. Constructing an
    :class:`ExecuteWindow` runs its ``__post_init__`` ordering check, which
    raises ``ValueError`` on a misconfigured (``older_than <= execute_timeout``)
    pair — so a bad configuration is refused BEFORE any recovery I/O, never after
    a wrong retry. ``execute_timeout=None`` means the caller has not supplied the
    bound (e.g. an in-process sweep whose owners it controls); the check is
    skipped, exactly as before this parameter existed.
    """
    if execute_timeout is not None:
        ExecuteWindow(execute_timeout=execute_timeout, reconcile_after=older_than)


def reconcile(
    store: Any,
    *,
    older_than: timedelta,
    on_absent: OnAbsent = OnAbsent.ABORT,
    execute_timeout: timedelta | None = None,
    now_fn: Callable[[], datetime] = _utcnow,
    registry: Registry | None = None,
) -> ReconcileReport:
    """Recover every stale in-flight row once, verify-first (PLAN.md 4.2).

    Pure orchestration: it scans (``store.stale_inflight``), and for each row
    takes over (``store.bump_epoch``) then dispatches on ``(state,
    guarantee)`` per the recovery table. It never blind-re-executes; every
    re-execute is gated on proven absence/effect-freeness plus re-validated
    preconditions.

    Args:
        store: the ledger. Must expose ``stale_inflight`` / ``bump_epoch``
            (P1.3) alongside the P1.1 surface, and its ``now_fn`` MUST be the
            same clock as ``now_fn`` here (the store computes the staleness
            cutoff; a divergent clock would scan the wrong rows).
        older_than: the reconcile timeout == ``reconcile_after``. A row is
            recoverable only once its ``last_attempt_at`` is older than
            ``now_fn() - older_than`` (SPEC.md section 5: the ONLY recovery
            trigger).
        on_absent: :class:`OnAbsent` — retry or abort a provably-absent /
            effect-free row. Default ``ABORT`` (fail safe: recovery that
            cannot prove the world unchanged should not re-execute; the
            operator opts INTO retry).
        execute_timeout: the owner's execute timeout. When given, it is
            validated ``execute_timeout < older_than`` via
            :class:`ExecuteWindow` BEFORE the scan (PLAN.md 4.1/10.2: a
            misconfigured window that lets a reconciler probe a live owner's
            row is refused with ``ValueError``, never silently run). ``None``
            skips the check (the caller vouches for the ordering — e.g. a
            controlled in-process sweep).
        now_fn: the fake/real clock, shared with the store. Used to timestamp
            escalation/recovery evidence.
        registry: the :class:`Registry` mapping ``action_type`` to its
            ``effect``/``execute``/``preconditions``; defaults to the
            process-wide :data:`airlock.registry.registry`.

    Returns:
        A :class:`ReconcileReport` — counts per :class:`Outcome` plus the
        per-key :class:`ReconcileAction` list.

    Raises:
        ValueError: ``execute_timeout`` is given and is not strictly less than
            ``older_than`` (the enforced ordering, PLAN.md 4.1).
    """
    _enforce_execute_window(older_than, execute_timeout)
    reg = registry if registry is not None else default_registry
    report = ReconcileReport()
    for record in store.stale_inflight(older_than):
        _reconcile_row(
            store,
            record,
            older_than=older_than,
            on_absent=on_absent,
            now_fn=now_fn,
            reg=reg,
            report=report,
        )
    return report


def reconcile_key(
    store: Any,
    key: str,
    *,
    older_than: timedelta,
    on_absent: OnAbsent = OnAbsent.ABORT,
    execute_timeout: timedelta | None = None,
    now_fn: Callable[[], datetime] = _utcnow,
    registry: Registry | None = None,
) -> ReconcileAction | None:
    """Reconcile a SINGLE key — the inline-targeted invocation (PLAN.md 4.2).

    Used by ``commit_once`` when a loser hits a stale in-flight row for
    exactly this ``key``: it runs the identical recovery logic as
    :func:`reconcile`, scoped to one row, so the loser never blind-re-executes
    and can return the recovered outcome. Returns the :class:`ReconcileAction`,
    or ``None`` if the row is absent / no longer stale-in-flight / already
    taken over (``bump_epoch`` returns ``None``).

    ``execute_timeout`` is enforced ``< older_than`` exactly as in
    :func:`reconcile` (PLAN.md 4.1): the same window bound holds whether the
    reconciler sweeps or a ``commit_once`` loser targets one key.

    Raises:
        ValueError: ``execute_timeout`` is given and is not strictly less than
            ``older_than``.
    """
    _enforce_execute_window(older_than, execute_timeout)
    reg = registry if registry is not None else default_registry
    record = store.load(key)
    if record is None or record.state not in _IN_FLIGHT:
        return None
    report = ReconcileReport()
    _reconcile_row(
        store,
        record,
        older_than=older_than,
        on_absent=on_absent,
        now_fn=now_fn,
        reg=reg,
        report=report,
    )
    return report.actions[0] if report.actions else None


def reconcile_on_startup(
    store: Any,
    *,
    older_than: timedelta,
    on_absent: OnAbsent = OnAbsent.ABORT,
    execute_timeout: timedelta | None = None,
    now_fn: Callable[[], datetime] = _utcnow,
    registry: Registry | None = None,
) -> ReconcileReport:
    """Opt-in startup sweep (PLAN.md 4.2): run one :func:`reconcile` pass.

    A plain function a caller MAY invoke from its boot sequence to sweep rows
    stranded by the previous process's crash. It is exactly one
    :func:`reconcile` pass — NOT a daemon, NOT a background thread (both out of
    P1.3 scope). Callers who want continuous recovery run the CLI on a cron.
    ``execute_timeout`` is forwarded and enforced as in :func:`reconcile`.
    """
    return reconcile(
        store,
        older_than=older_than,
        on_absent=on_absent,
        execute_timeout=execute_timeout,
        now_fn=now_fn,
        registry=registry,
    )


@dataclass(frozen=True)
class PausedSweepAction:
    """What the paused sweep did to one stale-approved run (tests + observability)."""

    approval_ref: str
    run_id: str
    action_type: str
    #: the run's status AFTER the drive: committed | aborted | approved
    #: ("approved" = still stranded — apply_decision could not reach a truthful
    #: terminal this pass, so the run is left for the next one), or "error".
    outcome: str
    detail: str | None = None


@dataclass(frozen=True)
class PausedSweepReport:
    """The result of one :func:`reconcile_paused` pass (mirrors :class:`ReconcileReport`)."""

    counts: dict[str, int] = field(default_factory=dict)
    actions: list[PausedSweepAction] = field(default_factory=list)

    def _record(self, action: PausedSweepAction) -> None:
        self.actions.append(action)
        self.counts[action.outcome] = self.counts.get(action.outcome, 0) + 1

    def count(self, outcome: str) -> int:
        return self.counts.get(outcome, 0)

    @property
    def total(self) -> int:
        return len(self.actions)


def reconcile_paused(
    store: Any,
    *,
    older_than: timedelta,
    registry: Registry | None = None,
    event_sinks: Sequence[EventSink] = (),
    reconcile_after: timedelta | None = None,
    execute_timeout: timedelta | None = None,
    now_fn: Callable[[], datetime] = _utcnow,
) -> PausedSweepReport:
    """Sweep stale ``approved`` paused runs through ``apply_decision`` (PLAN.md 4.2/4.3).

    Closes the crash-between-approve-CAS-and-commit window (settled decision 3):
    an approval whose ``commit_once`` never landed sits ``approved`` forever
    unless something re-drives it. This sweep scans
    ``store.stale_approved_paused(older_than)`` and drives each row through
    :func:`airlock.pause.apply_decision` with ``decision=None`` — the
    ensure-committed mode, which drives the recorded ``approved`` status to
    ``committed`` (or ``aborted`` if preconditions now fail; scenario 8) exactly
    once (the commit LEDGER dedupes concurrent appliers). It NEVER invents a
    decision and NEVER touches ``proposed`` rows — there is no TTL expiry in v1
    (ADR-4 is locked). This is the ONLY paused_runs reconcile behavior; it is
    deliberately separate from :func:`reconcile` (the in-flight ledger sweep) so
    a ``commit_once`` loser's inline reconciliation never pulls the pause layer
    onto the hot path.

    A run that ``apply_decision`` cannot resolve this pass (a
    :class:`~airlock.errors.VerificationUnknown`, a fenced wait, an unregistered
    ``action_type`` in this process, or any raise) is recorded and LEFT
    ``approved`` for the next pass — the sweep never aborts mid-scan on one bad
    row, exactly like the in-flight reconciler's best-effort evidence writes.

    Args:
        store: the customer's Store (paused rows + ledger + audit chain).
        older_than: the staleness threshold; a run is swept once its
            ``decided_at`` is older than ``now_fn() - older_than``.
        registry: the action :class:`Registry` supplying each run's recovery
            wiring (defaults to the process-wide one).
        event_sinks: best-effort mirrors for the terminal ``action_event``.
        reconcile_after / execute_timeout: forwarded to ``apply_decision`` ->
            ``commit_once`` (inline recovery of a stale in-flight ledger row
            while resuming; the enforced execute-window ordering still applies).
        now_fn: the injectable clock, shared with the store.

    Returns:
        A :class:`PausedSweepReport` — per-run actions plus a tally by outcome.
    """
    from airlock.pause import apply_decision  # lazy: avoid a module import cycle

    report = PausedSweepReport()
    for run in store.stale_approved_paused(older_than):
        try:
            outcome = apply_decision(
                store,
                run.approval_ref,
                None,
                registry=registry,
                event_sinks=event_sinks,
                reconcile_after=reconcile_after,
                execute_timeout=execute_timeout,
                now_fn=now_fn,
            )
        except Exception as exc:
            report._record(
                PausedSweepAction(
                    approval_ref=run.approval_ref,
                    run_id=run.run_id,
                    action_type=run.action_type,
                    outcome="error",
                    detail=f"{type(exc).__name__}: {exc}",
                )
            )
            continue
        report._record(
            PausedSweepAction(
                approval_ref=run.approval_ref,
                run_id=run.run_id,
                action_type=run.action_type,
                outcome=outcome.status.value,
            )
        )
    return report


_IN_FLIGHT = frozenset({LedgerState.PENDING, LedgerState.EXECUTING})


def _reconcile_row(
    store: Any,
    record: CommitRecord,
    *,
    older_than: timedelta,
    on_absent: OnAbsent,
    now_fn: Callable[[], datetime],
    reg: Registry,
    report: ReconcileReport,
) -> None:
    """Take over and recover ONE stale row (the recovery table dispatch)."""
    key = record.idempotency_key
    action_type = record.action_type
    from_state = record.state
    guarantee = record.guarantee

    registration = reg.get(action_type)
    if registration is None:
        # No recovery logic for this action_type: the operator forgot to
        # --import the defining module. Guessing execute/verify would be a
        # blind re-execute; leave the row untouched (do NOT bump the epoch —
        # bumping would strand it at a higher epoch with no owner).
        report._record(
            ReconcileAction(
                key=key,
                action_type=action_type,
                from_state=from_state,
                guarantee=guarantee,
                outcome=Outcome.UNREGISTERED,
                detail=(
                    f"action_type {action_type!r} is not registered; cannot recover "
                    "(did the reconciler --import the module that registers it?)"
                ),
            )
        )
        return

    # THE FENCE, FIRST: take durable ownership before any probe/execute. None
    # means already resolved or taken over since the stale scan — skip.
    epoch = store.bump_epoch(key, older_than)
    if epoch is None:
        report._record(
            ReconcileAction(
                key=key,
                action_type=action_type,
                from_state=from_state,
                guarantee=guarantee,
                outcome=Outcome.SKIPPED,
                detail="bump_epoch returned None: row already terminal or taken over",
            )
        )
        return

    if from_state is LedgerState.PENDING:
        # Provably effect-free: the executing marker commits before the effect
        # is ever invoked (PLAN.md 10 point 1), so a pending row never started
        # its effect — safe to retry or abort for EVERY guarantee. No probe.
        _recover_effect_free(
            store,
            record,
            epoch=epoch,
            on_absent=on_absent,
            now_fn=now_fn,
            registration=registration,
            report=report,
        )
        return

    # from_state is EXECUTING — dispatch on the guarantee.
    if guarantee is Guarantee.VERIFIABLE:
        _recover_executing_verifiable(
            store,
            record,
            epoch=epoch,
            on_absent=on_absent,
            now_fn=now_fn,
            registration=registration,
            report=report,
        )
    elif guarantee is Guarantee.DOWNSTREAM_IDEMPOTENT:
        _recover_executing_downstream_idempotent(
            store,
            record,
            epoch=epoch,
            now_fn=now_fn,
            registration=registration,
            report=report,
        )
    else:  # Guarantee.NONE
        _recover_executing_none(
            store,
            record,
            epoch=epoch,
            now_fn=now_fn,
            report=report,
        )


def _recover_effect_free(
    store: Any,
    record: CommitRecord,
    *,
    epoch: int,
    on_absent: OnAbsent,
    now_fn: Callable[[], datetime],
    registration: Registration,
    report: ReconcileReport,
) -> None:
    """pending (any guarantee), or executing+verifiable proven absent.

    The effect provably did not take place, so ``on_absent`` decides: retry
    (re-validate preconditions, re-run the execute path under the bumped
    epoch) or abort (``finalize('aborted')``). Recovery RE-VALIDATES
    preconditions — a changed world since the crash means abort, never a blind
    retry (SPEC scenario 8 applied to recovery).
    """
    from_state = record.state
    if on_absent is OnAbsent.ABORT:
        _finalize(
            store,
            record,
            epoch=epoch,
            state=LedgerState.ABORTED,
            result=None,
            evidence={"reconciled": "aborted", "reason": on_absent.value, "at": _now_iso(now_fn)},
            outcome=Outcome.ABORTED,
            report=report,
            now_fn=now_fn,
        )
        return

    # RETRY — re-validate preconditions against the current world first.
    arg_map = dict(record.args_json)
    if not _preconditions_hold(registration, arg_map):
        _finalize(
            store,
            record,
            epoch=epoch,
            state=LedgerState.ABORTED,
            result=None,
            evidence={
                "reconciled": "aborted",
                "reason": "preconditions_violated_on_retry",
                "at": _now_iso(now_fn),
            },
            outcome=Outcome.ABORTED,
            report=report,
            now_fn=now_fn,
            detail="preconditions no longer hold on retry — aborting rather than blind-retrying",
        )
        return

    _reexecute(
        store,
        record,
        epoch=epoch,
        from_state=from_state,
        now_fn=now_fn,
        registration=registration,
        arg_map=arg_map,
        report=report,
    )


def _recover_executing_verifiable(
    store: Any,
    record: CommitRecord,
    *,
    epoch: int,
    on_absent: OnAbsent,
    now_fn: Callable[[], datetime],
    registration: Registration,
    report: ReconcileReport,
) -> None:
    """executing + verifiable: probe first (PLAN.md 4.2, SPEC scenarios 3/4).

    present -> the effect happened: finalize committed with the probe result
    (scenario 3: recovered, effect count unchanged). absent -> retry/abort as
    an effect-free row (scenario 4). unknown (incl. probe raising / malformed
    verdict — reused P1.2 coercion) -> LEAVE the row untouched, record an
    escalation evidence event, count escalated.
    """
    key = record.idempotency_key
    arg_map = dict(record.args_json)
    verification, evidence = _probe(registration.effect, arg_map)

    if verification is Verification.PRESENT:
        _finalize(
            store,
            record,
            epoch=epoch,
            state=LedgerState.COMMITTED,
            result=_json_safe(evidence),
            evidence={"reconciled": "committed", "post_verify": "present", "at": _now_iso(now_fn)},
            outcome=Outcome.COMMITTED,
            report=report,
            now_fn=now_fn,
            detail="probe confirmed the effect present; recovered without re-executing",
        )
        return

    if verification is Verification.ABSENT:
        # Effect proven absent: recover it like an effect-free row.
        _recover_effect_free(
            store,
            record,
            epoch=epoch,
            on_absent=on_absent,
            now_fn=now_fn,
            registration=registration,
            report=report,
        )
        return

    # UNKNOWN — the honest non-answer. NEVER finalize (no terminal state would
    # be truthful): record escalation evidence, append the loud escalation
    # audit event (PLAN.md 4.2 "unknown -> leave, escalate via audit event" —
    # a chained row as of P2.2), and leave the row for a human/next pass.
    # record_error is epoch-guarded; a fenced write is fine to ignore.
    escalation: dict[str, JsonValue] = {
        "reconciled": "escalated",
        "post_verify": Verification.UNKNOWN.value,
        "evidence": _json_safe(evidence),
        "at": _now_iso(now_fn),
    }
    with contextlib.suppress(Exception):  # evidence is best-effort; escalation still counts
        store.record_error(key, epoch, escalation)
    _append_escalation(
        store,
        record,
        epoch=epoch,
        now_fn=now_fn,
        reason="verify answered 'unknown'; row left executing",
    )
    report._record(
        ReconcileAction(
            key=key,
            action_type=record.action_type,
            from_state=record.state,
            guarantee=record.guarantee,
            outcome=Outcome.ESCALATED,
            epoch=epoch,
            evidence=_json_safe(evidence),
            detail="verify answered 'unknown'; row left executing, escalated (never finalized)",
        )
    )


def _recover_executing_downstream_idempotent(
    store: Any,
    record: CommitRecord,
    *,
    epoch: int,
    now_fn: Callable[[], datetime],
    registration: Registration,
    report: ReconcileReport,
) -> None:
    """executing + downstream_idempotent (PLAN.md 4.2).

    Preconditions still hold -> re-issue the effect with the SAME stored
    downstream key: downstream dedup IS the verification (a re-issue with the
    original key either returns the first response or lands the effect once).
    Preconditions violated -> finalize('unknown') with loud evidence: cannot
    prove absence, and will not execute against a changed world.
    """
    arg_map = dict(record.args_json)
    if not _preconditions_hold(registration, arg_map):
        _finalize(
            store,
            record,
            epoch=epoch,
            state=LedgerState.UNKNOWN,
            result=None,
            evidence={
                "reconciled": "unknown",
                "reason": "preconditions_violated_downstream_idempotent",
                "detail": (
                    "cannot prove the effect absent and the world changed since the crash; "
                    "refusing to re-issue against a changed world"
                ),
                "at": _now_iso(now_fn),
            },
            outcome=Outcome.UNKNOWN,
            report=report,
            now_fn=now_fn,
            detail="downstream_idempotent but preconditions violated — finalized unknown, loud",
        )
        return

    # Re-issue with the SAME downstream key (the row is already 'executing' at
    # the bumped epoch, so no mark_executing is needed; downstream dedup makes
    # the re-issue safe).
    _reexecute(
        store,
        record,
        epoch=epoch,
        from_state=LedgerState.EXECUTING,
        now_fn=now_fn,
        registration=registration,
        arg_map=arg_map,
        report=report,
    )


def _recover_executing_none(
    store: Any,
    record: CommitRecord,
    *,
    epoch: int,
    now_fn: Callable[[], datetime],
    report: ReconcileReport,
) -> None:
    """executing + none: finalize('unknown'), loud, NEVER retried (scenario 7).

    The effect may or may not have happened and there is no way to find out
    (neither idempotent nor verifiable). Exactly-once is impossible, so the
    honest terminal state is ``unknown`` — and because it is terminal, this
    row is never picked up by a future reconcile pass (the honesty is a
    feature).
    """
    _finalize(
        store,
        record,
        epoch=epoch,
        state=LedgerState.UNKNOWN,
        result=None,
        evidence={
            "reconciled": "unknown",
            "reason": "at_most_once_no_probe",
            "detail": (
                "guarantee=none: the effect may have executed and cannot be verified; "
                "finalized unknown and NEVER retried (SPEC scenario 7)"
            ),
            "at": _now_iso(now_fn),
        },
        outcome=Outcome.UNKNOWN,
        report=report,
        now_fn=now_fn,
        detail="guarantee=none stuck executing — finalized unknown, loud, never retried",
    )


def _reexecute(
    store: Any,
    record: CommitRecord,
    *,
    epoch: int,
    from_state: LedgerState,
    now_fn: Callable[[], datetime],
    registration: Registration,
    arg_map: Mapping[str, JsonValue],
    report: ReconcileReport,
) -> None:
    """Re-run the execute path under the bumped epoch (retry / re-issue).

    Mirrors ``commit_once`` steps 3-6 for the recovery context:

    - from ``pending``: transition pending -> executing under the bumped epoch
      (``mark_executing``) BEFORE executing — a fenced mark means a third actor
      took over; bail.
    - from ``executing`` (absent-retry or downstream re-issue): the row is
      already executing at the bumped epoch, so no mark is needed.

    Then execute(downstream_key, **arg_map); post-verify if the effect has a
    probe (absent -> failed, unknown -> escalate/leave); finalize committed.
    Every ledger write is epoch-guarded, so a third-actor takeover mid-recovery
    is fenced, not overridden.
    """
    key = record.idempotency_key
    effect = registration.effect
    downstream_key = record.downstream_key

    if from_state is LedgerState.PENDING and not store.mark_executing(key, epoch):
        _record_fenced(record, epoch, report, "mark_executing fenced during re-execute")
        return

    try:
        result = registration.execute(downstream_key, **dict(arg_map))
    except Exception as exc:  # honest failure: status unknown, leave executing
        with contextlib.suppress(Exception):  # evidence best-effort
            store.record_error(
                key,
                epoch,
                {
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "phase": "reconcile_reexecute",
                },
            )
        _append_escalation(
            store,
            record,
            epoch=epoch,
            now_fn=now_fn,
            reason=f"re-execute raised {type(exc).__name__}; row left executing",
        )
        report._record(
            ReconcileAction(
                key=key,
                action_type=record.action_type,
                from_state=record.state,
                guarantee=record.guarantee,
                outcome=Outcome.ESCALATED,
                epoch=epoch,
                detail=(
                    f"re-execute raised ({type(exc).__name__}); left executing for the next pass"
                ),
            )
        )
        return

    # Post-verify the FRESH attempt if the effect has a probe.
    if effect.verify is not None:
        verification, evidence = _probe(effect, dict(arg_map))
        if verification is Verification.ABSENT:
            error_payload: dict[str, JsonValue] = {
                "post_verify": Verification.ABSENT.value,
                "evidence": _json_safe(evidence),
                "phase": "reconcile_reexecute",
            }
            with contextlib.suppress(Exception):  # evidence best-effort
                store.record_error(key, epoch, error_payload)
            _finalize(
                store,
                record,
                epoch=epoch,
                state=LedgerState.FAILED,
                result=None,
                evidence=error_payload,
                outcome=Outcome.FAILED,
                report=report,
                now_fn=now_fn,
                detail="re-execute post-verify proved the fresh attempt absent — failed",
            )
            return
        if verification is Verification.UNKNOWN:
            with contextlib.suppress(Exception):  # evidence best-effort
                store.record_error(
                    key,
                    epoch,
                    {
                        "post_verify": Verification.UNKNOWN.value,
                        "evidence": _json_safe(evidence),
                        "phase": "reconcile_reexecute",
                    },
                )
            _append_escalation(
                store,
                record,
                epoch=epoch,
                now_fn=now_fn,
                reason="re-execute post-verify answered 'unknown'; row left executing",
            )
            report._record(
                ReconcileAction(
                    key=key,
                    action_type=record.action_type,
                    from_state=record.state,
                    guarantee=record.guarantee,
                    outcome=Outcome.ESCALATED,
                    epoch=epoch,
                    evidence=_json_safe(evidence),
                    detail=("re-execute post-verify answered 'unknown'; left executing, escalated"),
                )
            )
            return

    # present (or no probe) -> finalize committed under the bumped epoch, with
    # the reconciler's chained audit event in the same transaction (P2.2).
    retried_event = _reconcile_audit_event(
        record,
        outcome=Outcome.RETRIED_COMMITTED,
        epoch=epoch,
        now_fn=now_fn,
        to_state=LedgerState.COMMITTED,
        reason="re-executed and committed under the bumped epoch",
    )
    if store.finalize(key, epoch, LedgerState.COMMITTED, _json_safe(result), retried_event):
        report._record(
            ReconcileAction(
                key=key,
                action_type=record.action_type,
                from_state=record.state,
                guarantee=record.guarantee,
                outcome=Outcome.RETRIED_COMMITTED,
                epoch=epoch,
                evidence=_json_safe(result),
                detail="re-executed and committed under the bumped epoch",
            )
        )
        return
    _record_fenced(record, epoch, report, "finalize fenced during re-execute")


def _reconcile_audit_event(
    record: CommitRecord,
    *,
    outcome: Outcome,
    epoch: int,
    now_fn: Callable[[], datetime],
    to_state: LedgerState | None = None,
    reason: str | None = None,
) -> AuditEvent:
    """Build the chained audit event for one recovery action (PLAN.md 4.2).

    ``event_type='reconcile'`` — the recovered/escalation evidence PLAN 4.2
    calls audit events, hash-chained as of P2.2. The payload is deliberately
    a small, fully-controlled vocabulary (states, outcome, epoch, reason) so
    it always lies in the airlock-canon-1 domain; free-form probe evidence
    stays on ``commit_records.error_json`` where it always lived — the chain
    records WHAT the reconciler concluded, the ledger row keeps the raw why.
    """
    payload: dict[str, JsonValue] = {
        "key": record.idempotency_key,
        "from_state": record.state.value,
        "to_state": None if to_state is None else to_state.value,
        "outcome": outcome.value,
        "epoch": epoch,
        "guarantee": record.guarantee.value,
        "reason": reason,
        "at": _now_iso(now_fn),
    }
    return AuditEvent(
        event_type=RECONCILE_EVENT_TYPE,
        run_id=record.run_id,
        action_type=record.action_type,
        payload=payload,
        created_at=now_fn(),
    )


def _append_escalation(
    store: Any,
    record: CommitRecord,
    *,
    epoch: int,
    now_fn: Callable[[], datetime],
    reason: str,
) -> None:
    """Append the loud escalation audit row (PLAN.md 4.2: "escalate via audit event").

    Standalone append (no state changed, so there is no finalize transaction
    to ride). Best-effort like every other evidence write in this module: a
    transient append failure must not abort the sweep mid-pass — the
    escalation is still counted on the report, and the row is still left
    ``executing`` for the next pass to escalate again.
    """
    event = _reconcile_audit_event(
        record, outcome=Outcome.ESCALATED, epoch=epoch, now_fn=now_fn, reason=reason
    )
    with contextlib.suppress(Exception):
        store.append_audit(event)


def _finalize(
    store: Any,
    record: CommitRecord,
    *,
    epoch: int,
    state: LedgerState,
    result: JsonValue,
    evidence: JsonValue,
    outcome: Outcome,
    report: ReconcileReport,
    now_fn: Callable[[], datetime],
    detail: str | None = None,
) -> None:
    """Record evidence (best-effort) then epoch-guarded finalize to ``state``.

    The finalize carries the reconciler's chained audit event (P2.2): the
    terminal transition and its audit row land in ONE transaction, exactly
    like ``commit_once``'s own finalize.

    A fenced finalize (rowcount 0) means a third actor took over mid-recovery
    — never override; count it fenced (the store appends nothing for a fenced
    finalize, so no false transition reaches the chain).
    """
    key = record.idempotency_key
    if evidence is not None:
        with contextlib.suppress(
            Exception
        ):  # evidence best-effort; the terminal state is the point
            store.record_error(key, epoch, evidence)
    audit_event = _reconcile_audit_event(
        record, outcome=outcome, epoch=epoch, now_fn=now_fn, to_state=state, reason=detail
    )
    if store.finalize(key, epoch, state, result, audit_event):
        report._record(
            ReconcileAction(
                key=key,
                action_type=record.action_type,
                from_state=record.state,
                guarantee=record.guarantee,
                outcome=outcome,
                epoch=epoch,
                evidence=evidence,
                detail=detail,
            )
        )
        return
    _record_fenced(record, epoch, report, f"finalize->{state.value} fenced during recovery")


def _record_fenced(record: CommitRecord, epoch: int, report: ReconcileReport, detail: str) -> None:
    report._record(
        ReconcileAction(
            key=record.idempotency_key,
            action_type=record.action_type,
            from_state=record.state,
            guarantee=record.guarantee,
            outcome=Outcome.REEXECUTE_FENCED,
            epoch=epoch,
            detail=detail,
        )
    )


def _preconditions_hold(registration: Registration, arg_map: Mapping[str, JsonValue]) -> bool:
    """Re-validate preconditions with the arg_map splatted as kwargs.

    ``None`` preconditions are always-satisfied. A precondition that RAISES is
    treated as NOT holding — the safe direction (abort/unknown rather than
    execute against an unknowable world).
    """
    if registration.preconditions is None:
        return True
    try:
        return bool(registration.preconditions(**dict(arg_map)))
    except Exception:
        return False


def _probe(effect: Effect, arg_map: Mapping[str, JsonValue]) -> tuple[Verification, Any | None]:
    """Call ``effect.verify(**arg_map)``, coercing anything unprovable to UNKNOWN.

    Reuses the P1.2 coercion contract: a probe that raises, or returns a
    malformed verdict (not a ``(Verification, evidence)`` tuple, or a verdict
    outside the enum), proves nothing -> ``(UNKNOWN, None)``.
    """
    if effect.verify is None:
        return Verification.UNKNOWN, None
    try:
        answer, evidence = effect.verify(**dict(arg_map))
        return Verification(answer), evidence
    except Exception:
        return Verification.UNKNOWN, None


def _now_iso(now_fn: Callable[[], datetime]) -> str:
    return now_fn().isoformat()


def _json_safe(value: Any) -> JsonValue:
    """Best-effort JSON coercion for evidence headed to ``error_json``.

    Mirrors ``airlock.commit._json_safe``: non-JSON evidence is recorded as its
    ``repr`` rather than losing the evidence write; ``allow_nan=False`` so a
    NaN cannot be certified safe and then rejected by the JSONB cast.
    """
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError):
        return repr(value)
    return cast(JsonValue, value)
