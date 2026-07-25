"""The async worker pool: sizing knob + the saturation warning (ASYNC-DESIGN.md D2).

The pool bounds how many guarded async calls can be in flight. Exhausting it does
NOT break anything — calls queue and still complete exactly once — but from the
outside a saturated pool looks like the agent stalled. Silence there is as
dishonest as a silent double-commit, so Airlock says so once and names the knob.

These tests manipulate module-global pool state, so each one restores it.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from airlock import guard, init
from airlock._guard import _default_workers
from airlock.effects import Effect
from airlock.errors import AirlockError, AsyncPoolSaturated
from airlock.policy import Policy, Rule
from airlock.types import Decision

if TYPE_CHECKING:
    from collections.abc import Iterator

    from airlock.store.postgres import PostgresStore
    from tests.conftest import EffectsLog

pytestmark = [pytest.mark.matrix, pytest.mark.usefixtures("guard_isolation")]


def _reset_pool() -> None:
    """Tear down any live async pool and return the globals to pristine state.

    Resetting to pristine (rather than restoring a previous pool object) is both
    simpler and sufficient: the pool is created lazily on the next async guarded
    call, so the following test gets a correctly-sized one either way.
    """
    from airlock import _guard

    if _guard._EXECUTOR is not None:
        # wait=True: a worker still writing to the ledger must finish before the
        # store fixture closes underneath it (see conftest.drain_async_pool).
        _guard._EXECUTOR.shutdown(wait=True)
    _guard._EXECUTOR = None
    _guard._EXECUTOR_WORKERS = None
    _guard._INFLIGHT = 0
    _guard._SATURATION_WARNED = False


@pytest.fixture(autouse=True)
def _pool_isolation() -> Iterator[None]:
    """These tests mutate process-wide pool state, so isolate it on both sides."""
    _reset_pool()
    try:
        yield
    finally:
        _reset_pool()


def _auto() -> Policy:
    return Policy(rules=[Rule(match="pool.*", decision=Decision.AUTO)])


def test_default_pool_is_io_shaped_not_cpu_shaped() -> None:
    """The workers WAIT on the bridged coroutine rather than compute, so a
    CPU-count-sized pool would throttle ordinary agent concurrency."""
    assert _default_workers() >= 32


async def test_saturating_the_pool_warns_once_and_still_commits_everything(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """G3/D2: with a deliberately tiny pool, more concurrent calls than workers
    must (a) warn, naming the knob, and (b) STILL all complete exactly once —
    saturation is a latency problem, never a correctness one."""
    init(store=store, policy=_auto(), async_workers=2)

    @guard("pool.charge", effect=Effect(key_param="idempotency_key"))
    async def charge(order: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0.01)
        effects.log(idempotency_key or "none")
        return order

    with pytest.warns(AsyncPoolSaturated, match="async_workers"):
        out = await asyncio.gather(*(charge(f"ord_{i}") for i in range(8)))

    assert sorted(out) == sorted(f"ord_{i}" for i in range(8)), "a queued call was lost"
    assert effects.total() == 8, "saturation changed the effect count"


async def test_saturation_warning_fires_only_once_per_process(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """A warning per queued call would be its own kind of noise."""
    init(store=store, policy=_auto(), async_workers=1)

    @guard("pool.once", effect=Effect(key_param="idempotency_key"))
    async def act(order: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0.005)
        effects.log(idempotency_key or "none")
        return order

    with pytest.warns(AsyncPoolSaturated) as first:
        await asyncio.gather(*(act(f"a_{i}") for i in range(4)))
    assert len([w for w in first if w.category is AsyncPoolSaturated]) == 1

    import warnings as _w

    with _w.catch_warnings(record=True) as second:
        _w.simplefilter("always")
        await asyncio.gather(*(act(f"b_{i}") for i in range(4)))
    assert not [w for w in second if w.category is AsyncPoolSaturated], (
        "the saturation warning repeated instead of firing once per process"
    )


async def test_a_generous_pool_does_not_warn(store: PostgresStore, effects: EffectsLog) -> None:
    """The default must stay quiet for ordinary agent concurrency, or the warning
    becomes noise nobody reads."""
    init(store=store, policy=_auto())

    @guard("pool.quiet", effect=Effect(key_param="idempotency_key"))
    async def act(order: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0)
        effects.log(idempotency_key or "none")
        return order

    import warnings as _w

    with _w.catch_warnings(record=True) as caught:
        _w.simplefilter("always")
        await asyncio.gather(*(act(f"q_{i}") for i in range(10)))
    assert not [w for w in caught if w.category is AsyncPoolSaturated]


def test_async_workers_must_be_positive(store: PostgresStore) -> None:
    with pytest.raises(ValueError, match="async_workers must be >= 1"):
        init(store=store, policy=_auto(), async_workers=0)


async def test_resizing_a_live_pool_is_refused_loudly(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """Silently ignoring a resize would leave the caller believing they had tuned
    something they had not."""
    init(store=store, policy=_auto(), async_workers=4)

    @guard("pool.live", effect=Effect(key_param="idempotency_key"))
    async def act(order: str, *, idempotency_key: str | None = None) -> str:
        await asyncio.sleep(0)
        effects.log(idempotency_key or "none")
        return order

    await act("first")  # the pool now exists

    with pytest.raises(AirlockError, match="already running with 4 workers"):
        init(store=store, policy=_auto(), async_workers=64)


def test_reconfiguring_to_the_same_size_is_a_no_op(store: PostgresStore) -> None:
    """Re-init with an unchanged value must not raise — apps call init() more than
    once (tests, worker bootstraps)."""
    init(store=store, policy=_auto(), async_workers=8)
    init(store=store, policy=_auto(), async_workers=8)
