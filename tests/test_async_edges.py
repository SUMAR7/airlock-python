"""Async edge cases a real user will hit (ASYNC-DESIGN.md G1/G2/G6/G7).

The happy path is covered in ``test_guard_async.py``; the durable-pause and
crash promises in ``test_async_pause_crash.py``. This file pins the awkward
corners — the ones that would each be a bad afternoon for somebody:

- an async effect that RAISES (must propagate verbatim, not become an opaque
  bridge error);
- a guarded async tool calling ANOTHER guarded async tool (must not deadlock);
- cancellation mid-effect (must not hang);
- contextvars surviving the worker-thread hop;
- DENY / GATE on async tools (must not execute);
- ``execute_timeout`` on an async effect;
- the loud refusal when a SYNC entry point is called from inside a running loop.
"""

from __future__ import annotations

import asyncio
import contextvars
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from airlock import guard, init
from airlock.effects import Effect
from airlock.errors import ActionDenied, ActionPending, ExecuteTimeout
from airlock.policy import Policy, Rule
from airlock.types import Decision, HumanDecision

if TYPE_CHECKING:
    from airlock.store.postgres import PostgresStore
    from tests.conftest import EffectsLog

pytestmark = [pytest.mark.matrix, pytest.mark.usefixtures("guard_isolation")]

REQUEST_ID: contextvars.ContextVar[str] = contextvars.ContextVar("airlock_test_req", default="none")


def _policy(decision: Decision = Decision.AUTO) -> Policy:
    return Policy(rules=[Rule(match="edge.*", decision=decision)])


async def test_async_effect_exception_propagates_verbatim(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """The bridge must not swallow, wrap or mangle the tool's own exception —
    debugging a real failure through a thread hop is hard enough already."""
    init(store=store, policy=_policy())

    @guard("edge.boom", effect=Effect(key_param="idempotency_key"))
    async def boom(x: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0)
        raise ValueError("downstream exploded")

    with pytest.raises(ValueError, match="downstream exploded"):
        await boom("a")


async def test_nested_guarded_async_calls_do_not_deadlock(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """A guarded async tool calling ANOTHER guarded async tool.

    Entirely plausible in agent code, and the obvious way to get this wrong is a
    deadlock: the outer call occupies a worker thread, so if the inner one needed
    a loop on THAT thread it would wedge. It does not, because a bridged
    coroutine body always runs on the real event loop — only the sync ledger work
    sits on the worker. Both effects still commit exactly once.
    """
    init(store=store, policy=_policy())

    @guard("edge.inner", effect=Effect(key_param="idempotency_key"))
    async def inner(x: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0)
        effects.log(f"inner:{x}")
        return f"inner:{x}"

    @guard("edge.outer", effect=Effect(key_param="idempotency_key"))
    async def outer(x: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0)
        got = await inner(x)
        effects.log(f"outer:{x}")
        return f"outer({got})"

    # wait_for turns a deadlock into a clear failure instead of a hung suite
    result = await asyncio.wait_for(outer("v"), timeout=30)
    assert result == "outer(inner:v)"
    assert effects.count("inner:v") == 1
    assert effects.count("outer:v") == 1


async def test_cancelling_an_async_guarded_call_does_not_hang(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """G1: the caller cancels mid-effect. It must surface CancelledError rather
    than wedge. (Cancellation is NOT proof the effect did not land — the ledger
    row is left for the verify-first reconciler, per ASYNC-DESIGN.md §4.3.)"""
    init(store=store, policy=_policy())

    @guard("edge.slow", effect=Effect(key_param="idempotency_key"))
    async def slow(x: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(5)
        effects.log(x)
        return x

    task = asyncio.create_task(slow("a"))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=20)


async def test_contextvars_survive_the_worker_thread_hop(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """G7: the sync core runs on a worker thread, so the caller's context is
    explicitly copied across. Request-scoped state (trace ids, tenant, auth) must
    still be visible inside the effect."""
    init(store=store, policy=_policy())
    seen: list[str] = []

    @guard("edge.ctx", effect=Effect(key_param="idempotency_key"))
    async def act(x: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0)
        seen.append(REQUEST_ID.get())
        effects.log(x)
        return x

    REQUEST_ID.set("req-42")
    await act("a")
    assert seen == ["req-42"], f"the context did not cross the thread hop: {seen}"


async def test_async_deny_raises_without_executing(
    store: PostgresStore, effects: EffectsLog
) -> None:
    init(store=store, policy=_policy(Decision.DENY))

    @guard("edge.denied", effect=Effect(key_param="idempotency_key"))
    async def denied(x: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0)
        effects.log(x)
        return x

    with pytest.raises(ActionDenied):
        await denied("a")
    assert effects.total() == 0, "DENY executed the async effect"


async def test_async_gate_pauses_without_executing(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """The fail-safe on the async path: a gated action must pause, not run."""
    init(store=store, policy=_policy(Decision.GATE), gate_wait=False)

    @guard("edge.gated", effect=Effect(key_param="idempotency_key"))
    async def gated(x: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0)
        effects.log(x)
        return x

    with pytest.raises(ActionPending):
        await gated("a")
    assert effects.total() == 0, "GATE executed the async effect before a decision"


async def test_execute_timeout_surfaces_on_an_async_effect(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """G2: an overrunning async effect raises ExecuteTimeout instead of hanging.
    The row is deliberately left for the reconciler — a cancelled ``await`` may
    already have sent the request, so cancellation proves nothing.

    On overrun the owner ABANDONS the worker (it cannot interrupt work already in
    flight; see ``commit.py::_run_execute``), so that worker keeps running and
    will still write to the store. This test therefore waits for the abandoned
    work to DRAIN before returning: otherwise the fixture closes the store while
    that thread is mid-write, and closing a SQLite connection under an active
    statement on another thread crashes the interpreter. Real deployments keep
    the store open for the process lifetime, but a test must not race its own
    teardown.
    """
    init(
        store=store,
        policy=_policy(),
        execute_timeout=timedelta(seconds=0.1),
        reconcile_after=timedelta(seconds=60),
    )
    drained = asyncio.Event()

    @guard("edge.overrun", effect=Effect(key_param="idempotency_key"))
    async def overrun(x: str, *, idempotency_key: str | None = None) -> str:
        try:
            await asyncio.sleep(0.3)  # longer than execute_timeout -> abandoned
            effects.log(x)
            return x
        finally:
            drained.set()  # runs on the test's loop; signals the abandoned work is done

    with pytest.raises(ExecuteTimeout):
        await asyncio.wait_for(overrun("a"), timeout=20)

    # Let the abandoned effect finish and its worker complete its store writes.
    await asyncio.wait_for(drained.wait(), timeout=20)
    for _ in range(200):  # yield until the worker's trailing ledger write lands
        await asyncio.sleep(0.01)
        if effects.total() >= 1:
            break


async def test_sync_resume_from_inside_a_running_loop_refuses_loudly(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """G6: calling the SYNC resume from async code, for an async tool, cannot
    work — we must neither block the caller's loop nor await from sync code. It
    refuses with a message that names the fix, rather than deadlocking."""
    app = init(store=store, policy=_policy(Decision.GATE), gate_wait=False)

    @guard("edge.resume", effect=Effect(key_param="idempotency_key"))
    async def gated(x: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0)
        effects.log(x)
        return x

    approval_ref = None
    try:
        await gated("a")
    except ActionPending as pending:
        approval_ref = pending.approval_ref
    assert approval_ref is not None

    with pytest.raises(RuntimeError, match="cannot drive an async effect"):
        app.resume(approval_ref, HumanDecision.APPROVED)
    assert effects.total() == 0
