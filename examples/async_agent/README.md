# Async agent tools

Most agent code is async — LangGraph, MCP, the OpenAI Agents SDK, LangChain's
`ainvoke`. An `async def` tool needs nothing special from Airlock: same
decorator, same guarantees.

```python
@airlock.guard("refund.issue", effect=Effect(key_param="idempotency_key"))
async def refund(charge_id: str, amount_cents: int, *, idempotency_key: str | None = None):
    await asyncio.sleep(0)      # your real network call
    ...
```

## Run it

```bash
pip install airlock-sdk
python demo.py
```

No database, no cloud account, no API key. You'll see:

1. **a retried call refunds the customer once** — the ledger dedupes it;
2. **your event loop is never blocked** — other tasks keep ticking while the
   guarded call is in flight (Airlock's ledger work runs on a worker pool);
3. **five concurrent identical calls produce one effect** — the classic
   duplicate-parallel-tool-call failure, collapsed at the ledger;
4. the hash-chained audit verifies.

## What else carries over

Everything. A gated async action pauses durably and can be resumed later by an
ordinary **synchronous** webhook receiver or cron reconciler — in a different
process, after a restart — and still commits exactly once.

`Effect(verify=...)` and `preconditions=` may be `async` too. The two hot-path
inputs (`cost=`, `blast_radius=`) may not: they're resolved on every call before
the auto/gate/deny decision, and that path is deliberately I/O-free. Making one
`async` is refused at decoration with a message saying so.
