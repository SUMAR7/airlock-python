"""Airlock + CrewAI: make an agent's tool call exactly-once.

CrewAI gives an agent a `@tool` to call. If the agent retries — a duplicated
call, a resumed crew, an over-eager model — the customer gets refunded twice.
Stack Airlock's `@guard` under CrewAI's `@tool` and the refund commits once.

    pip install -r requirements.txt
    python demo.py

No API key needed — this exercises the tool the way CrewAI invokes it
(`tool.run(...)`), so you see the guarantee without running a full crew.
"""

from __future__ import annotations

import os
import tempfile

import airlock
from airlock import Decision, Effect, Money, Policy, Rule
from crewai.tools import tool

# The real side effect we are protecting: each call appends one refund.
charged: list[str] = []


@tool("refund")
@airlock.guard(
    "payment.refund",
    cost=Money(amount="50.00", currency="USD"),
    # Exactly-once: Airlock derives an idempotency key from the args and passes
    # it downstream as `idempotency_key`. The model never sets this.
    effect=Effect(key_param="idempotency_key"),
)
def refund(charge_id: str, amount_cents: int, idempotency_key: str | None = None) -> dict:
    """Refund a charge on the customer's card."""
    charged.append(charge_id)
    return {"refund_id": f"re_{len(charged):04d}", "charge_id": charge_id}


def main() -> None:
    airlock.init(
        store=f"sqlite:///{os.path.join(tempfile.mkdtemp(), 'airlock.db')}",
        policy=Policy(rules=[Rule(match="payment.refund", decision=Decision.AUTO)]),
    )

    # The agent calls the tool — then retries the SAME call.
    first = refund.run(charge_id="ch_demo", amount_cents=5000)
    retry = refund.run(charge_id="ch_demo", amount_cents=5000)

    print(f"tool registered: {refund.name}")
    print(f"first call:  {first}")
    print(f"retry call:  {retry}   (same result, deduped)")
    print(f"refunds actually issued: {len(charged)}  (exactly once)")
    assert retry == first and len(charged) == 1, charged

    # Give `refund` to your CrewAI Agent(tools=[refund]); every call is now
    # exactly-once. Running the full crew needs an LLM key.


if __name__ == "__main__":
    main()
