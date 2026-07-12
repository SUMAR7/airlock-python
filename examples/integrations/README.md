# Airlock + your agent framework

Airlock makes a tool call **exactly-once**: if your agent retries a side-effecting
tool — a duplicated tool call, a resumed run, an over-eager model — the effect
still happens once. The integration is one line: stack `@guard` **under** your
framework's tool decorator, on the function that does the real work.

Each folder is a runnable, **no-API-key** demo of the same story — the same
refund, retried once: without Airlock the customer is refunded twice; with it,
exactly once.

- [`langchain/`](langchain/) — LangChain / LangGraph `@tool`
- [`openai_agents/`](openai_agents/) — OpenAI Agents SDK `function_tool`
- [`crewai/`](crewai/) — CrewAI `@tool`

## The pattern (identical everywhere)

```python
@framework_tool          # LangChain @tool · OpenAI @function_tool · CrewAI @tool
@airlock.guard("payment.refund", effect=Effect(key_param="idempotency_key"))
def refund(charge_id: str, amount_cents: int, idempotency_key: str | None = None):
    ...  # idempotency_key is INJECTED by Airlock — the model never sets it
```

Two things worth knowing:

- **Exactly-once needs `Effect(key_param=...)`** (a downstream idempotency key
  Airlock derives from the args and passes through) or `Effect(verify=...)` (a
  probe that asks the provider "did this already happen?"). Keep that key
  parameter out of what the model sees — it's Airlock's to fill, not the LLM's.
- **Human-in-the-loop**: change the policy rule to `Decision.GATE` and the tool
  call pauses durably for a human to approve or reject — see
  [`../hosted_gated/`](../hosted_gated/). On reject the agent gets a structured
  `reason_code` it can branch on instead of a dead end.
