"""Airlock + LangChain: make an agent's tool call exactly-once.

LangChain lets an LLM call `refund` as a `@tool`. If the agent retries — a
duplicated tool call, a resumed graph, an over-eager model — nothing stops the
customer being refunded twice. Stack Airlock's `@guard` under `@tool` and the
refund commits exactly once: the retry returns the same result, no second charge.

    pip install -r requirements.txt
    python demo.py

No API key needed — this exercises the tool exactly the way LangChain invokes it
(`tool.invoke(...)`), so you see the guarantee without running a full LLM loop.
"""

from __future__ import annotations

import os
import tempfile

import airlock
from airlock import Decision, Effect, Money, Policy, Rule
from langchain_core.tools import tool

# The real side effect we are protecting: each call appends one refund.
charged: list[str] = []


@tool
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

    # The agent calls the tool — then the graph retries the SAME call.
    first = refund.invoke({"charge_id": "ch_demo", "amount_cents": 5000})
    retry = refund.invoke({"charge_id": "ch_demo", "amount_cents": 5000})

    print(f"first call:  {first}")
    print(f"retry call:  {retry}   (same result, deduped)")
    print(f"refunds actually issued: {len(charged)}  (exactly once)")
    assert retry == first and len(charged) == 1, charged

    # Give `refund` to your agent as an ordinary tool; every call it makes is now
    # exactly-once. With an LLM key you'd run the full loop, e.g.:
    #   from langgraph.prebuilt import create_react_agent
    #   agent = create_react_agent(model, tools=[refund])
    #   agent.invoke({"messages": [("user", "Refund charge ch_demo for $50")]})


if __name__ == "__main__":
    main()
