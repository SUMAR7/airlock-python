# Airlock + LangChain

Make a LangChain tool exactly-once by stacking `@guard` under `@tool`:

```python
@tool
@airlock.guard("payment.refund", effect=Effect(key_param="idempotency_key"))
def refund(charge_id: str, amount_cents: int, idempotency_key: str | None = None) -> dict:
    "Refund a charge on the customer's card."
    ...
```

## Run it

```bash
pip install -r requirements.txt
python demo.py
```

No API key needed — the demo invokes the tool the way LangChain does
(`refund.invoke({...})`) and shows a retried call refund the customer **once**:

```
refunds actually issued: 1  (exactly once)
```

`idempotency_key` is injected by Airlock, not the model — it stays out of the
tool schema the LLM sees. To require human approval before a refund, switch the
policy rule to `Decision.GATE` (see [`../../hosted_gated/`](../../hosted_gated/)).
