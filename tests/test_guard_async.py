"""``@guard`` on ``async def`` tools — the promises, defended by CI.

Async support is a FACADE over the ONE proven synchronous commit core
(ASYNC-DESIGN.md): the sync ``commit_once`` runs on a worker thread and the
tool's coroutine is bridged back to the caller's loop. There is no second
ledger, so these tests exist to prove the facade never weakens what the core
already guarantees:

- exactly-once on an awaited effect, and a retry returns the first result;
- the event loop is NOT blocked while the guarded call runs (the whole point);
- concurrent calls on one key collapse to ONE effect (the USP under async);
- the hash-chained audit still verifies;
- async ``Effect.verify`` / ``preconditions`` are awaited (D1/G9/G10);
- the refusals are loud: async generators (no single result to commit) and async
  hot-path policy inputs (``cost`` / ``blast_radius``, SPEC.md 3);
- the SYNC path is completely undisturbed.

The durable-pause (P2) and crash-recovery (P3) promises for async effects live in
``test_guard_async_pause.py`` and ``test_async_crash.py`` — they need a fresh
process, so they cannot be asserted here.

``effects`` is the ground truth: a real autocommit table, so an effect that
happened is visible even if the run later fails.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

from airlock import guard, init
from airlock.audit import verify_chain
from airlock.effects import Effect
from airlock.errors import PreconditionFailed
from airlock.policy import Policy, Rule
from airlock.types import BlastRadius, Decision, Money, Verification

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from airlock.store.postgres import PostgresStore
    from tests.conftest import EffectsLog

#: ``matrix``: run on BOTH backends — the bridge hops threads, and SQLite's
#: per-thread connections are the interesting case (ASYNC-DESIGN.md G8).
#: ``guard_isolation``: reset the ambient runtime + the process-wide registry
#: around each test, or the parametrized backends collide on one action_type.
pytestmark = [pytest.mark.matrix, pytest.mark.usefixtures("guard_isolation")]


def _auto(match: str = "async.*") -> Policy:
    return Policy(rules=[Rule(match=match, decision=Decision.AUTO)])


# --- the AUTO path ----------------------------------------------------------


async def test_async_auto_commits_exactly_once_and_dedupes(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """P1: an awaited effect commits once; the retry returns the first result."""
    init(store=store, policy=_auto())
    seen: list[str | None] = []

    @guard("async.refund", effect=Effect(key_param="idempotency_key"))
    async def refund(invoice: str, *, idempotency_key: str | None = None) -> dict[str, Any]:
        await asyncio.sleep(0)  # a real suspension point, like a network call
        seen.append(idempotency_key)
        effects.log(idempotency_key or "none")
        return {"refunded": invoice, "dk": idempotency_key}

    first = await refund("inv_1")
    downstream = seen[0]
    assert downstream is not None and len(downstream) == 64  # the derived ledger key
    assert effects.count(downstream) == 1

    second = await refund("inv_1")
    assert second == first
    assert effects.count(downstream) == 1  # NO second effect
    assert seen == [downstream]  # the tool body ran exactly once


async def test_async_guard_does_not_block_the_event_loop(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """The sync core runs OFF the loop — otherwise async support would be a lie
    (and the bridge would deadlock, since the loop must stay free to run the
    coroutine the worker is waiting on)."""
    init(store=store, policy=_auto())

    @guard("async.slow", effect=Effect(key_param="idempotency_key"))
    async def slow(job: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0.02)
        effects.log(idempotency_key or "none")
        return job

    ticks = 0

    async def heartbeat() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(0.001)
            ticks += 1

    beat = asyncio.create_task(heartbeat())
    try:
        assert await slow("j1") == "j1"
    finally:
        beat.cancel()
    assert ticks > 0, "the event loop was blocked for the whole guarded call"


async def test_async_concurrent_calls_on_one_key_produce_one_effect(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """The USP under async: 25 concurrent awaits on the SAME key => ONE effect,
    and every caller gets the identical result."""
    init(store=store, policy=_auto())
    keys: list[str] = []

    @guard("async.burst", effect=Effect(key_param="idempotency_key"))
    async def burst(order: str, *, idempotency_key: str | None = None) -> dict[str, Any]:
        await asyncio.sleep(0.005)
        keys.append(idempotency_key or "none")
        effects.log(idempotency_key or "none")
        return {"order": order, "dk": idempotency_key}

    results = await asyncio.gather(*(burst("ord_1") for _ in range(25)))

    assert len({r["dk"] for r in results}) == 1, "callers disagreed on the outcome"
    assert all(r == results[0] for r in results)
    downstream = results[0]["dk"]
    assert effects.count(downstream) == 1, "the side effect fired more than once"
    assert len(keys) == 1, f"the tool body ran {len(keys)} times, expected 1"


async def test_async_distinct_keys_all_commit_without_starvation(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """G3: many DISTINCT keys in flight at once all complete — the dedicated
    executor must not deadlock or starve (that would read to a user as a hang)."""
    init(store=store, policy=_auto())

    @guard("async.many", effect=Effect(key_param="idempotency_key"))
    async def many(order: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0.005)
        effects.log(idempotency_key or "none")
        return order

    out = await asyncio.gather(*(many(f"ord_{i}") for i in range(20)))
    assert sorted(out) == sorted(f"ord_{i}" for i in range(20))
    assert effects.total() == 20


async def test_async_audit_chain_verifies(store: PostgresStore, effects: EffectsLog) -> None:
    """P4: the audit append still happens inside finalize, so the chain holds."""
    init(store=store, policy=_auto())

    @guard("async.audited", effect=Effect(key_param="idempotency_key"))
    async def audited(x: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0)
        effects.log(idempotency_key or "none")
        return x

    await audited("a")
    await audited("b")
    verify_chain(store)


# --- async verify / preconditions (D1, G9, G10) -----------------------------


async def test_async_post_verify_probe_is_awaited(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """G9: an async ``Effect.verify`` returns ONE coroutine wrapping the
    ``(Verification, evidence)`` tuple — it must be resolved BEFORE the core
    unpacks it, or post-verify would explode on a coroutine."""
    init(store=store, policy=_auto())
    probed: list[str] = []

    async def averify(x: str, **_: object) -> tuple[Verification, Any]:
        await asyncio.sleep(0)
        probed.append(x)
        return Verification.PRESENT, {"probed": x}

    @guard("async.probed", effect=Effect(key_param="idempotency_key", verify=averify))
    async def probed_tool(x: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0)
        effects.log(idempotency_key or "none")
        return x

    assert await probed_tool("v1") == "v1"
    assert probed == ["v1"], "the async post-verify probe never ran"


async def test_async_precondition_that_passes_allows_the_effect(
    store: PostgresStore, effects: EffectsLog
) -> None:
    init(store=store, policy=_auto())

    async def ok(x: str, **_: object) -> bool:
        await asyncio.sleep(0)
        return True

    @guard("async.precond_ok", effect=Effect(key_param="idempotency_key"), preconditions=ok)
    async def act(x: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0)
        effects.log(idempotency_key or "none")
        return x

    assert await act("go") == "go"
    assert effects.total() == 1


async def test_async_precondition_that_fails_blocks_the_effect(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """G10 + the bug this caught: ``bool(coroutine)`` is ALWAYS True, so an
    un-awaited async precondition would silently PASS — a fail-OPEN in the layer
    whose whole job is to fail safe. It must block, with zero side effects."""
    init(store=store, policy=_auto())

    async def blocked(x: str, **_: object) -> bool:
        await asyncio.sleep(0)
        return False

    @guard("async.precond_no", effect=Effect(key_param="idempotency_key"), preconditions=blocked)
    async def act(x: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0)
        effects.log(idempotency_key or "none")
        return x

    with pytest.raises(PreconditionFailed):
        await act("nope")
    assert effects.total() == 0, "a failing async precondition let the effect run"


# --- the refusals must be loud (§6) -----------------------------------------


def test_async_generator_refused_at_decoration() -> None:
    """A stream has no single outcome to commit exactly once, so this is refused
    permanently rather than half-supported."""
    with pytest.raises(TypeError, match="does not support async generators"):

        @guard("async.stream")
        async def stream(x: str) -> AsyncIterator[int]:
            yield 1


@pytest.mark.parametrize("label", ["cost", "blast_radius"])
def test_async_hot_path_policy_callable_refused_at_decoration(label: str) -> None:
    """G11: ``cost``/``blast_radius`` resolve on the PURE I/O-free hot path taken
    by every call (SPEC.md 3). An async one is refused loudly at decoration —
    not left to fail later with a puzzling 'returned coroutine' TypeError."""

    async def acost(*_a: object, **_k: object) -> Money:
        await asyncio.sleep(0)
        return Money(amount="1.00", currency="USD")

    async def ablast(*_a: object, **_k: object) -> BlastRadius:
        await asyncio.sleep(0)
        return BlastRadius.LOW

    kwargs: dict[str, Any] = {label: acost if label == "cost" else ablast}
    with pytest.raises(TypeError, match=f"async {label}= callable"):

        @guard("async.hotpath", **kwargs)
        async def tool(x: str) -> str:
            return x


# --- the sync path must be untouched ---------------------------------------


def test_sync_tool_still_returns_a_sync_callable(store: PostgresStore, effects: EffectsLog) -> None:
    """Async support must not change sync tools: no coroutine, no thread hop."""
    init(store=store, policy=_auto("sync.*"))

    @guard("sync.plain", effect=Effect(key_param="idempotency_key"))
    def plain(x: str, *, idempotency_key: str | None = None) -> str:
        effects.log(idempotency_key or "none")
        return x

    assert not asyncio.iscoroutinefunction(plain)
    assert plain("a") == "a"
    assert plain("a") == "a"  # deduped
    assert effects.total() == 1
