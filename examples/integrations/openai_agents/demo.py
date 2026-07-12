"""Airlock + OpenAI Agents SDK: make an agent's tool call exactly-once.

The Agents SDK exposes `refund` to the model as a `function_tool`. If the agent
retries — a duplicated tool call, a resumed run, an over-eager model — the
customer gets refunded twice. Wrap the tool's function with Airlock's `@guard`
and the refund commits exactly once.

    pip install -r requirements.txt
    python demo.py

No API key needed — the agent Runner ultimately calls the guarded function, so
we call that same function to show the guarantee without a live LLM loop.
"""

from __future__ import annotations

import os
import tempfile

from agents import function_tool

import airlock
from airlock import Decision, Effect, Money, Policy, Rule

# The real side effect we are protecting: each call appends one refund.
charged: list[str] = []


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


# Give THIS to your Agent(tools=[...]); the Runner calls the guarded `refund`.
refund_tool = function_tool(refund)


def main() -> None:
    airlock.init(
        store=f"sqlite:///{os.path.join(tempfile.mkdtemp(), 'airlock.db')}",
        policy=Policy(rules=[Rule(match="payment.refund", decision=Decision.AUTO)]),
    )

    # The agent calls the tool — then retries the SAME call.
    first = refund(charge_id="ch_demo", amount_cents=5000)
    retry = refund(charge_id="ch_demo", amount_cents=5000)

    print(f"tool registered: {refund_tool.name}")
    print(f"first call:  {first}")
    print(f"retry call:  {retry}   (same result, deduped)")
    print(f"refunds actually issued: {len(charged)}  (exactly once)")
    assert retry == first and len(charged) == 1, charged

    # Full agent loop (needs OPENAI_API_KEY):
    #   from agents import Agent, Runner
    #   agent = Agent(name="Support", tools=[refund_tool])
    #   Runner.run_sync(agent, "Refund charge ch_demo for $50")


if __name__ == "__main__":
    main()
