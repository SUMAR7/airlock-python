"""``@guard`` + the ambient runtime (P2.1) — where a tool call meets the policy.

``@guard`` wraps a tool function so that every call first takes the auto / gate
/ deny decision (PURE, in-process, I/O-free — SPEC.md 3 / ADR-3), then:

- **AUTO**  → commit the effect exactly once via ``commit_once`` (P1.1), the
  key derived from the call args (P1.2), the ``Effect`` and preconditions
  passed through; the terminal ``action_event.v1`` is appended to the hash
  chain INSIDE the finalize transaction (P2.2).
- **DENY**  → append the ``action_event`` (outcome='denied') durably to the
  hash chain + mirror it to the sinks, then raise :class:`ActionDenied`
  BEFORE any ledger claim — block, no side effect (PLAN.md "Deny = block +
  audit event"; PLAN.md 4.4 "DENY = decision + one local audit append").
- **GATE**  → surface the gate cleanly WITHOUT executing (fail-safe). The
  durable pause + resume + transport are P2.3 and OUT OF SCOPE here (see
  "The GATE seam" below); the gate's ``action_event`` is emitted at its
  terminal state, which P2.3 owns — P2.2 emits nothing for GATE.

**Decoration is side-effect-free except one registration.** Applying ``@guard``
does not touch the store, the policy, or the network; it only records
``action_type -> (fn, effect, preconditions)`` in the shared
:class:`~airlock.registry.Registry` (default: the process-wide one), so the
reconciler and a resumed run can reconstruct the call from a bare ledger row
(the exact shape P1.3 already consumes). The runtime (store + policy + sinks)
is resolved LAZILY at call time from an ambient contextvar set by :func:`init`
— so a module can define guarded tools at import time and be wired to a store
later, and tests can swap runtimes per context.

The GATE seam (P2.1 is deliberately minimal)
--------------------------------------------
A GATE decision here does exactly three things and no more: it does NOT execute
the side effect, it DOES emit the policy-decision event, and it raises
:class:`ActionPending` (specifically :class:`GateNotSupported`, which names
P2.3). It never builds a ``paused_runs`` row, never calls a transport, never
resumes — those are P2.3. The seam is :meth:`_Runtime` carrying an optional
``pause`` hook that is ``None`` in P2.1; when P2.3 lands it plugs the durable
pause + ``ConsoleApprovalTransport`` in HERE, replacing the raise with a
persist-then-send/wait (or a plain ``ActionPending(run_id=...)`` for async
agents). Until then, GATE surfacing is honest about the missing layer rather
than silently executing or dropping the action.

The audit seam (P2.2)
---------------------
The durable, hash-chained ``audit_events`` row IS the record of truth now:
deny events are appended at decision time (``Store.append_audit``), auto
events inside the finalize transaction (``commit_once`` → ``Store.finalize``).
``EventSink`` is the best-effort mirror of the same :class:`ActionEvent`
object — sink failures are isolated and can never perturb the guarded call
(see ``airlock.events``).
"""

from __future__ import annotations

import functools
import inspect
import uuid
import warnings
from collections.abc import Callable, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, ParamSpec, TypeVar, cast

from pydantic import JsonValue

from airlock.effects import Effect
from airlock.errors import (
    ActionDenied,
    AirlockError,
    CommitFailed,
    GateNotSupported,
    PreconditionFailed,
)
from airlock.events import (
    ActionEventContext,
    EventSink,
    PostVerify,
    build_action_event,
    emit_action_event,
)
from airlock.idempotency import build_arg_map, derive_key, namespace_user_key
from airlock.policy import ActionContext, Policy, PolicyBackend
from airlock.registry import Registry
from airlock.registry import registry as default_registry
from airlock.types import (
    ActionOutcome,
    BlastRadius,
    Decision,
    LedgerState,
    Money,
    Reversibility,
)

if TYPE_CHECKING:
    from airlock.store import Store
    from airlock.types import CommitOutcome

__all__ = ["Airlock", "current_runtime", "guard", "init"]

P = ParamSpec("P")
R = TypeVar("R")

# The reversibility default matches PLAN.md 3.3: an unclassified guarded action
# is treated as irreversible (the conservative posture).
_DEFAULT_REVERSIBILITY = Reversibility.IRREVERSIBLE


@dataclass(frozen=True)
class _Runtime:
    """The ambient runtime a ``@guard`` call resolves at invocation time.

    Set by :func:`init`, read from :data:`_runtime_var`. Holds the store, the
    policy backend, the event sinks, the shared registry, and the recovery
    knobs ``commit_once`` needs. ``pause`` is the P2.3 seam — ``None`` in P2.1
    (a GATE decision raises :class:`GateNotSupported`); P2.3 sets it to the
    durable-pause + transport hook without changing this call site.
    """

    store: Store
    policy: PolicyBackend
    event_sinks: tuple[EventSink, ...]
    registry: Registry
    reconcile_after: timedelta | None
    execute_timeout: timedelta | None
    #: P2.3 seam: the durable-pause/transport hook. None in P2.1 → GATE raises.
    pause: Callable[..., Any] | None = None


#: The ambient runtime. A ContextVar (not a module global) so nested/async
#: contexts and tests can scope their own runtime; @guard resolves it lazily.
_runtime_var: ContextVar[_Runtime | None] = ContextVar("airlock_runtime", default=None)


def current_runtime() -> _Runtime | None:
    """The ambient runtime, or ``None`` if :func:`init` has not run in this context."""
    return _runtime_var.get()


@dataclass(frozen=True)
class Airlock:
    """The handle :func:`init` returns — a thin holder over the ambient runtime.

    Exists so callers have an explicit object to keep (and so P2.3 can hang
    ``resume``/reconciler helpers off it) without reaching into the contextvar.
    In P2.1 it just exposes the wired ``store`` and ``policy``.
    """

    _runtime: _Runtime

    @property
    def store(self) -> Store:
        return self._runtime.store

    @property
    def policy(self) -> PolicyBackend:
        return self._runtime.policy


def init(
    *,
    store: Store,
    policy: PolicyBackend | None = None,
    event_sinks: Sequence[EventSink] = (),
    registry: Registry | None = None,
    reconcile_after: timedelta | None = None,
    execute_timeout: timedelta | None = None,
) -> Airlock:
    """Wire the ambient runtime for ``@guard`` and return an :class:`Airlock`.

    Sets a contextvar that every subsequently-invoked ``@guard`` resolves at
    call time — so guarded tools defined at import time bind to this runtime
    without re-decoration.

    Args:
        store: the commit ledger (P1.1). Required in P2.1 — the zero-config
            SqliteStore default is P4.1 (PLAN.md 3.3 / 10.10), so there is no
            implicit store here.
        policy: the :class:`PolicyBackend`. ``None`` installs
            ``Policy(default=GATE)`` — fail safe: with no rules every action
            gates for a human (PLAN.md 3.3).
        event_sinks: best-effort :class:`EventSink` mirrors of the
            ``action_event.v1`` records; the durable hash-chained
            ``audit_events`` row is the record of truth (P2.2).
        registry: the shared action :class:`Registry`; defaults to the
            process-wide one ``@guard`` populates and the reconciler reads.
        reconcile_after: forwarded to ``commit_once`` on the AUTO path — the
            inline reconcile staleness threshold (PLAN.md 4.2). ``None`` keeps
            the P1.1 poll-then-raise loser behavior.
        execute_timeout: forwarded to ``commit_once`` — the owner execute
            deadline, enforced ``< reconcile_after`` (PLAN.md 4.1). Requires
            ``reconcile_after`` when set (``commit_once`` rejects the lone one).

    Returns:
        An :class:`Airlock` handle over the runtime just installed.
    """
    runtime = _Runtime(
        store=store,
        policy=policy if policy is not None else Policy(),
        event_sinks=tuple(event_sinks),
        registry=registry if registry is not None else default_registry,
        reconcile_after=reconcile_after,
        execute_timeout=execute_timeout,
    )
    _runtime_var.set(runtime)
    return Airlock(_runtime=runtime)


@dataclass(frozen=True)
class _GuardSpec:
    """The frozen decorator metadata for one guarded tool (no runtime state)."""

    fn: Callable[..., Any]
    action_type: str
    reversibility: Reversibility
    cost: Money | Callable[..., Money] | None
    blast_radius: BlastRadius | Callable[..., BlastRadius] | None
    key: Callable[..., str] | None
    key_ignore: tuple[str, ...]
    effect: Effect
    preconditions: Callable[..., bool] | None


def guard(
    action_type: str,
    *,
    cost: Money | Callable[..., Money] | None = None,
    reversibility: Reversibility = _DEFAULT_REVERSIBILITY,
    blast_radius: BlastRadius | Callable[..., BlastRadius] | None = None,
    key: Callable[..., str] | None = None,
    key_ignore: tuple[str, ...] = (),
    effect: Effect | None = None,
    preconditions: Callable[..., bool] | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorate a tool fn: decide auto/gate/deny per call, commit AUTO once.

    Decoration itself is side-effect-free except registering
    ``action_type -> (fn, effect, preconditions)`` in the shared registry (so
    resume/reconcile can find it). The runtime is resolved lazily at CALL time
    from :func:`init`'s contextvar.

    Args:
        action_type: the stable action identifier (ledger + policy + registry
            key). Must be non-empty and, since the key-override path namespaces
            with ``"{action_type}:{user_key}"``, must not contain ``:``.
        cost: the action's :class:`~airlock.types.Money` cost, or a callable of
            the SAME arguments as the tool that returns one (resolved per call,
            in ``@guard``, BEFORE the pure policy sees it — so a callable may
            read the args but the decision layer stays I/O-free). ``None`` =
            no/unknown cost.
        reversibility: :class:`~airlock.types.Reversibility`; default
            ``irreversible`` (conservative, PLAN.md 3.3).
        blast_radius: :class:`~airlock.types.BlastRadius` or a callable of the
            args returning one (resolved per call like ``cost``). ``None`` =
            unknown.
        key: override key derivation — a callable of the args returning the
            user key, namespaced to ``"{action_type}:{user_key}"`` (PLAN.md
            3.3). ``None`` derives the key from the canonical arg_map (P1.2).
        key_ignore: volatile arg names excluded from the derived key (P1.2).
        effect: the ADR-2 :class:`~airlock.effects.Effect`. ``None`` means a
            bare ``Effect()`` — at-most-once (``commit_once`` warns loudly when
            an AUTO call runs under it).
        preconditions: re-checked after the claim on the AUTO path and on
            reconciler retry (SPEC.md scenario 8); called with the canonical
            arg_map as kwargs.

    Returns:
        A decorator that returns a wrapper with the same call signature; the
        wrapper's return value is the tool's ``execute`` result (AUTO), and it
        raises :class:`ActionDenied` / :class:`ActionPending` for deny / gate.
    """
    if not action_type:
        raise ValueError("action_type must be a non-empty string")
    if ":" in action_type:
        # The key-override path namespaces as "{action_type}:{user_key}"; a
        # colon in action_type would make that encoding ambiguous (P1.2).
        raise ValueError(
            f"action_type {action_type!r} must not contain ':' (it is the namespace "
            "delimiter for key overrides; see contracts/idempotency.md §4)"
        )
    resolved_effect = effect if effect is not None else Effect()

    def decorate(fn: Callable[P, R]) -> Callable[P, R]:
        spec = _GuardSpec(
            fn=fn,
            action_type=action_type,
            reversibility=reversibility,
            cost=cost,
            blast_radius=blast_radius,
            key=key,
            key_ignore=key_ignore,
            effect=resolved_effect,
            preconditions=preconditions,
        )
        # The ONLY decoration side effect: register recovery wiring (PLAN.md
        # 3.3 / the P1.3 registry). execute/preconditions are adapted to the
        # registry's (downstream_key, **arg_map) / (**arg_map) convention so a
        # cross-process reconciler can reconstruct this call from a ledger row.
        default_registry.register(
            action_type,
            resolved_effect,
            _registry_execute(spec),
            _registry_preconditions(spec),
        )

        @functools.wraps(fn)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            return cast(R, _invoke(spec, args, kwargs))

        return wrapper

    return decorate


def _invoke(spec: _GuardSpec, args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> Any:
    """The per-call flow: build context → decide (pure) → auto/deny/gate."""
    runtime = _runtime_var.get()
    if runtime is None:
        raise AirlockError(
            f"@guard({spec.action_type!r}) was called before airlock.init(...): no ambient "
            "runtime (store + policy) is configured in this context. Call airlock.init(store=...) "
            "during startup."
        )

    # Resolve callable cost/blast_radius against the args, in @guard, so the
    # policy layer only ever sees plain values (keeps evaluate() I/O-free even
    # if a cost callable is expensive). This happens BEFORE any policy call.
    resolved_cost = _resolve(spec.cost, args, kwargs, "cost", Money)
    resolved_blast = _resolve(spec.blast_radius, args, kwargs, "blast_radius", BlastRadius)

    ctx = ActionContext(
        action_type=spec.action_type,
        reversibility=spec.reversibility,
        cost=resolved_cost,
        blast_radius=resolved_blast,
    )

    # THE HOT PATH: pure, in-process, zero I/O (SPEC.md 3 / ADR-3).
    decision = runtime.policy.evaluate(ctx)

    # The decision-time half of THE one action_event.v1 (PLAN.md 6.3). run_id
    # identifies this guarded invocation; the terminal half (outcome,
    # post_verify) is filled where the outcome becomes known — deny right
    # here, auto inside commit_once's finalize transaction, gate at the P2.3
    # terminal state (P2.2 emits nothing for gate — see airlock.events).
    event_ctx = ActionEventContext(
        run_id=f"run_{uuid.uuid4().hex}",
        policy_decision=decision,
        reversibility=spec.reversibility,
        cost=resolved_cost,
        blast_radius=resolved_blast,
        sinks=runtime.event_sinks,
    )

    if decision is Decision.DENY:
        # Block before any ledger claim: no side effect. DENY = the pure
        # decision + one local audit append (PLAN.md 4.4): the action_event
        # (outcome='denied') is written durably to the hash chain, then
        # mirrored to the sinks — see _handle_deny for the failure posture.
        _handle_deny(runtime, spec, args, kwargs, event_ctx)
        raise AssertionError("unreachable: _handle_deny always raises")  # pragma: no cover

    if decision is Decision.GATE:
        # Fail-safe: surface the gate WITHOUT executing. The durable pause +
        # transport are P2.3 (see module docstring); the gate's action_event
        # is emitted at its terminal state, which P2.3 owns.
        return _handle_gate(runtime, spec, args, kwargs)

    # AUTO — commit the effect exactly once (P1.1); the terminal action_event
    # rides inside commit_once's finalize transaction (P2.2).
    return _commit_auto(runtime, spec, args, kwargs, event_ctx)


def _handle_deny(
    runtime: _Runtime,
    spec: _GuardSpec,
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
    event_ctx: ActionEventContext,
) -> None:
    """The DENY path: one durable audit append + the sink mirror, then raise.

    PLAN.md 4.4: "DENY = decision + one local audit append." The DECISION was
    already taken purely in-process; what happens here is data-plane I/O to
    the customer's own store — never a control-plane call. The action_event
    (outcome='denied', post_verify never ran) is appended as a hash-chained
    ``audit_events`` row in its own transaction; the idempotency key on the
    event is derived from the call args exactly as the AUTO path would have
    (pure computation), so a later retry of the same call is joinable.

    Failure posture: the block is the fail-safe and it stands regardless.
    If the durable append fails (audit store unreachable), the deny STILL
    raises :class:`ActionDenied` — converting a deny into an infrastructure
    error could only make a blocked action less blocked — but the failure is
    never silent: a warning fires and the failure is attached to the raised
    error as a note. The sink mirror fires either way (best-effort).
    """
    arg_map = _arg_map(spec, args, kwargs)
    ledger_key = _ledger_key(spec, args, kwargs, arg_map)
    event = build_action_event(
        event_ctx,
        idempotency_key=ledger_key,
        action_type=spec.action_type,
        guarantee=spec.effect.guarantee,
        outcome=ActionOutcome.DENIED,
        post_verify=PostVerify(ran=False),
        now_fn=lambda: datetime.now(UTC),
    )
    append_error: Exception | None = None
    try:
        runtime.store.append_audit(event.to_audit_event())
    except Exception as exc:
        append_error = exc
        warnings.warn(
            f"airlock: the durable deny audit append for {spec.action_type!r} failed "
            f"({exc!r}); the deny itself stands (no side effect ran), but the "
            "tamper-evident record did not land — investigate the audit store.",
            stacklevel=4,
        )
    emit_action_event(event_ctx.sinks, event)
    denied = ActionDenied(
        f"policy denied action {spec.action_type!r}; the action was blocked and no side "
        "effect ran (the deny was recorded as a hash-chained action_event audit row).",
        action_type=spec.action_type,
    )
    if append_error is not None:
        denied.add_note(
            f"airlock: the durable deny audit append failed ({append_error!r}); "
            "the deny record reached only the best-effort event sinks."
        )
    raise denied


def _handle_gate(
    runtime: _Runtime, spec: _GuardSpec, args: tuple[Any, ...], kwargs: Mapping[str, Any]
) -> Any:
    """Surface a GATE decision. P2.1: raise; P2.3 plugs the pause layer in here."""
    if runtime.pause is not None:  # P2.3 seam — not built in P2.1
        return runtime.pause(spec, args, kwargs)
    raise GateNotSupported(
        f"policy gated action {spec.action_type!r}, but no pause layer is configured: the "
        "durable pause, resume, and approval transport are P2.3 and are not built in P2.1. "
        "The side effect was NOT executed (fail-safe) and a policy-decision event was emitted. "
        "Wire the P2.3 pause layer to resolve gated actions.",
        action_type=spec.action_type,
        run_id=None,
    )


def _commit_auto(
    runtime: _Runtime,
    spec: _GuardSpec,
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
    event_ctx: ActionEventContext,
) -> Any:
    """The AUTO path: derive the key, then ``commit_once`` (exactly-once).

    On this LIVE path the actual ``args``/``kwargs`` are in hand, so the tool
    and the preconditions are invoked with them directly (only the downstream
    key is injected into the ``effect.key_param`` kwarg). That is faithful even
    for a ``key_ignore``'d volatile arg, which is deliberately absent from the
    persisted ``arg_map`` — the registry-recovery adapters, which have ONLY the
    persisted ``arg_map``, use the arg_map convention instead (a recovered call
    genuinely cannot see a value that was never persisted).
    """
    from airlock.commit import commit_once

    arg_map = _arg_map(spec, args, kwargs)
    ledger_key = _ledger_key(spec, args, kwargs, arg_map)

    def execute(downstream_key: str | None) -> JsonValue:
        return cast(JsonValue, _call_tool_live(spec, args, kwargs, downstream_key))

    preconditions = None
    if spec.preconditions is not None:
        precond = spec.preconditions

        def preconditions() -> bool:
            return bool(precond(*args, **dict(kwargs)))

    outcome: CommitOutcome = commit_once(
        runtime.store,
        key=ledger_key,
        action_type=spec.action_type,
        execute=execute,
        effect=spec.effect,
        preconditions=preconditions,
        args_json=arg_map,
        reconcile_after=runtime.reconcile_after,
        execute_timeout=runtime.execute_timeout,
        event_context=event_ctx,
    )
    if outcome.state is LedgerState.COMMITTED:
        return outcome.result
    if outcome.state is LedgerState.ABORTED:
        # Preconditions failed after the claim (SPEC scenario 8): surface it as
        # PreconditionFailed rather than a silent None, so the caller sees the
        # action did not run.
        raise PreconditionFailed(
            f"action {spec.action_type!r} was aborted: its preconditions did not hold at "
            "commit time; no side effect ran.",
            action_type=spec.action_type,
            key=ledger_key,
        )
    # FAILED (post-verify proved the effect absent) or UNKNOWN (a duplicate call
    # read back a row the reconciler / an at-most-once crash left unknown). The
    # prime directive is "always provable": returning outcome.result (None) here
    # would let the caller mistake a non-landed effect for a successful commit,
    # so surface the non-committed terminal state explicitly. (A live
    # post-verify 'unknown' raises VerificationUnknown from commit_once before a
    # terminal state exists; that propagates unchanged and never reaches here.)
    raise CommitFailed(
        f"action {spec.action_type!r} finalized {outcome.state.value!r}, not committed: the "
        "side effect did not provably take effect (see the error/evidence on the ledger row "
        f"for key {ledger_key!r}). Airlock never blind-retries a non-committed row.",
        action_type=spec.action_type,
        key=ledger_key,
        state=outcome.state.value,
        error=outcome.error,
    )


# ---------------------------------------------------------------------------
# arg_map / key derivation / tool invocation (shared call-time + registry).
# ---------------------------------------------------------------------------


def _arg_map(spec: _GuardSpec, args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> dict[str, Any]:
    """The canonical arg_map for this call (P1.2 build_arg_map, key_param excluded)."""
    return build_arg_map(
        spec.fn,
        args,
        kwargs,
        key_ignore=spec.key_ignore,
        key_param=spec.effect.key_param,
    )


def _ledger_key(
    spec: _GuardSpec,
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
    arg_map: Mapping[str, Any],
) -> str:
    """The idempotency key: the ``key`` override (namespaced) or the derived key."""
    if spec.key is not None:
        user_key = spec.key(*args, **dict(kwargs))
        return namespace_user_key(spec.action_type, user_key)
    return derive_key(spec.action_type, arg_map)


def _call_tool_live(
    spec: _GuardSpec,
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
    downstream_key: str | None,
) -> Any:
    """Invoke the tool with the ORIGINAL call args, injecting the downstream key.

    The live path has the real ``args``/``kwargs``, so it calls the tool with
    them verbatim and only sets the ``effect.key_param`` kwarg to the derived
    ``downstream_key`` (ADR-2 passthrough). This is faithful even for a
    ``key_ignore``'d volatile arg (absent from the persisted ``arg_map`` but
    present in ``kwargs`` here). Setting ``key_param`` requires it to be
    passable as a keyword — an ``Effect(key_param=...)`` names a kwarg the tool
    accepts, which it must for the downstream key to reach it.
    """
    call_kwargs = dict(kwargs)
    key_param = spec.effect.key_param
    if key_param is not None and downstream_key is not None:
        call_kwargs[key_param] = downstream_key
    return spec.fn(*args, **call_kwargs)


def _call_tool_from_map(
    spec: _GuardSpec, arg_map: Mapping[str, Any], downstream_key: str | None
) -> Any:
    """Reconstruct + invoke the tool from the persisted arg_map (RECOVERY path).

    Used only by the registry adapter, where a cross-process reconciler has
    ONLY ``args_json`` (the canonical arg_map: defaults applied, ``key_param``
    and any ``key_ignore`` names removed) to work with. It rebinds the map onto
    the tool's signature (:func:`_bind_from_map`) and adds back the
    ``effect.key_param`` kwarg with ``downstream_key`` — so a recovered call is
    as close to the original as the persisted data allows. A ``key_ignore``'d
    volatile arg cannot be reconstructed (it was never persisted) — that is the
    documented cost of ignoring it in the key.
    """
    call_kwargs = dict(arg_map)
    key_param = spec.effect.key_param
    if key_param is not None and downstream_key is not None:
        call_kwargs[key_param] = downstream_key
    bound = _bind_from_map(spec.fn, call_kwargs)
    return spec.fn(*bound.args, **bound.kwargs)


def _bind_from_map(
    fn: Callable[..., Any], call_kwargs: Mapping[str, Any]
) -> inspect.BoundArguments:
    """Bind a flat name→value map back onto ``fn``'s signature.

    The inverse of :func:`airlock.idempotency.build_arg_map`. It reconstructs a
    valid ``(*args, **kwargs)`` call from the flat map, handling every parameter
    kind:

    - ``POSITIONAL_ONLY`` and ``POSITIONAL_OR_KEYWORD`` params (and the
      ``*args`` list) go into ``args`` **in declaration order** — passing a
      positional-or-keyword param by keyword while a later ``*args`` is passed
      positionally would make ``Signature.bind`` see two values for it, so
      everything up to and including ``*args`` must be positional;
    - ``KEYWORD_ONLY`` params and ``**kwargs`` extras go into ``kwargs``.

    A param absent from the map (e.g. a defaulted one that ``build_arg_map``
    dropped, though it normally applies defaults) is simply skipped and left to
    ``apply_defaults``.
    """
    signature = inspect.signature(fn)
    parameters = signature.parameters
    remaining = dict(call_kwargs)

    positional: list[Any] = []
    keyword: dict[str, Any] = {}

    for name, parameter in parameters.items():
        if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
            positional.extend(remaining.pop(name, []))
        elif name not in remaining:
            continue  # a defaulted param the map omitted; apply_defaults fills it
        elif parameter.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            positional.append(remaining.pop(name))
        elif parameter.kind is inspect.Parameter.KEYWORD_ONLY:
            keyword[name] = remaining.pop(name)
        # VAR_KEYWORD is handled by the leftover sweep below.

    # Anything left is a **kwargs extra (build_arg_map merged them to the top
    # level); pass them through as keywords.
    keyword.update(remaining)

    bound = signature.bind(*positional, **keyword)
    bound.apply_defaults()
    return bound


def _registry_execute(spec: _GuardSpec) -> Callable[..., JsonValue]:
    """The registry adapter: ``execute(downstream_key, **arg_map)`` → the tool.

    Matches the registry calling convention (PLAN.md registry docs) so a
    reconciler that only holds ``args_json`` can re-run this action. It routes
    through the SAME :func:`_call_tool` the live path uses, so recovery is
    byte-identical to the original call.
    """

    def execute(downstream_key: str | None, **arg_map: JsonValue) -> JsonValue:
        return cast(JsonValue, _call_tool_from_map(spec, arg_map, downstream_key))

    return execute


def _registry_preconditions(spec: _GuardSpec) -> Callable[..., bool] | None:
    """The registry adapter for preconditions: ``preconditions(**arg_map)``."""
    if spec.preconditions is None:
        return None
    precond = spec.preconditions

    def preconditions(**arg_map: JsonValue) -> bool:
        return bool(precond(**dict(arg_map)))

    return preconditions


def _resolve[T](
    value: T | Callable[..., T] | None,
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
    label: str,
    expected: type[T],
) -> T | None:
    """Resolve a static-or-callable decorator arg against the call args.

    A plain value is returned as-is; a callable is invoked with the tool's
    ``*args, **kwargs`` and must return an ``expected`` instance. Resolution
    happens in ``@guard`` (never in the policy layer) so ``evaluate`` stays
    I/O-free even when a cost/blast_radius callable is expensive.
    """
    if value is None:
        return None
    if callable(value) and not isinstance(value, expected):
        produced = value(*args, **dict(kwargs))
        if not isinstance(produced, expected):
            raise TypeError(
                f"{label} callable for a guarded action returned {type(produced).__name__}, "
                f"expected {expected.__name__}"
            )
        return produced
    if not isinstance(value, expected):
        raise TypeError(
            f"{label} must be a {expected.__name__} or a callable returning one, "
            f"got {type(value).__name__}"
        )
    return value
