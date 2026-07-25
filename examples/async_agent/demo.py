"""Airlock with an ASYNC agent tool — exactly-once, without blocking your loop.

Most agent code is async (LangGraph, MCP, the OpenAI Agents SDK, LangChain's
`ainvoke`). This shows that an `async def` tool needs nothing special: same
decorator, same guarantees.

    pip install airlock-sdk
    python demo.py

No database, no cloud account, no API key.
"""

from __future__ import annotations

import asyncio
import os
import tempfile

import airlock
from airlock import Decision, Effect, Money, Policy, Rule
from airlock.audit import verify_chain

# The real side effect we are protecting: each call charges the customer once.
payment_api_calls: list[str] = []


@airlock.guard(
    "refund.issue",
    cost=Money(amount="50.00", currency="USD"),
    # Exactly-once: Airlock derives an idempotency key from the args and passes
    # it downstream. The model never sets this.
    effect=Effect(key_param="idempotency_key"),
)
async def refund(charge_id: str, amount_cents: int, *, idempotency_key: str | None = None) -> dict:
    """Refund a charge on the customer's card."""
    await asyncio.sleep(0.05)  # stands in for the real network call
    payment_api_calls.append(charge_id)
    return {"refund_id": f"re_{len(payment_api_calls):04d}", "charge_id": charge_id}


async def heartbeat(stop: asyncio.Event) -> int:
    """Proves the event loop keeps running while a guarded call is in flight."""
    ticks = 0
    while not stop.is_set():
        await asyncio.sleep(0.005)
        ticks += 1
    return ticks


async def main() -> None:
    app = airlock.init(
        store=f"sqlite:///{os.path.join(tempfile.mkdtemp(), 'airlock.db')}",
        policy=Policy(rules=[Rule(match="refund.issue", decision=Decision.AUTO)]),
    )

    print("=" * 66)
    print("Airlock + async — the same refund, retried and run concurrently")
    print("=" * 66)

    # 1. The agent issues a refund, then retries the SAME call.
    stop = asyncio.Event()
    beat = asyncio.create_task(heartbeat(stop))

    first = await refund("ch_demo", 5000)
    retry = await refund("ch_demo", 5000)

    stop.set()
    ticks = await beat

    print("\n1. retry of the same call")
    print(f"   first: {first}")
    print(f"   retry: {retry}   (identical — deduped by the commit ledger)")
    print(f"   payment API calls: {len(payment_api_calls)}  (exactly once)")
    assert retry == first and len(payment_api_calls) == 1

    print("\n2. your event loop was never blocked")
    print(f"   other tasks ticked {ticks}x while the guarded calls ran")
    assert ticks > 0

    # 3. The model emits the same tool call several times at once — the classic
    #    duplicate-parallel-tool-call failure. The ledger collapses them.
    before = len(payment_api_calls)
    results = await asyncio.gather(*(refund("ch_parallel", 2500) for _ in range(5)))
    print("\n3. FIVE concurrent identical calls")
    print(f"   payment API calls added: {len(payment_api_calls) - before}  (exactly once)")
    print(f"   every caller got the same result: {results[0]}")
    assert len(payment_api_calls) - before == 1
    assert all(r == results[0] for r in results)

    verify_chain(app.store)
    print("\n4. the hash-chained audit verifies ✔")
    app.store.close()

    print("\npip install airlock-sdk   ·   MIT   ·   exactly-once for AI agents")


if __name__ == "__main__":
    asyncio.run(main())
