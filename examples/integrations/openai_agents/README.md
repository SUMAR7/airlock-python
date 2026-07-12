# Airlock + OpenAI Agents SDK

Make an Agents SDK tool exactly-once by wrapping its function with `@guard`:

```python
@airlock.guard("payment.refund", effect=Effect(key_param="idempotency_key"))
def refund(charge_id: str, amount_cents: int, idempotency_key: str | None = None) -> dict:
    "Refund a charge on the customer's card."
    ...

refund_tool = function_tool(refund)   # give this to Agent(tools=[...])
```

## Run it

```bash
pip install -r requirements.txt
python demo.py
```

No API key needed — the Runner ultimately calls the guarded `refund`, so the demo
calls that same function and shows a retried call refund the customer **once**:

```
refunds actually issued: 1  (exactly once)
```

`idempotency_key` is injected by Airlock, not the model. To require human approval
before a refund, switch the policy rule to `Decision.GATE` (see
[`../../hosted_gated/`](../../hosted_gated/)).
