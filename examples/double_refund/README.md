# The double-refund demo

The fastest way to see what Airlock buys you. One script, zero infrastructure,
under a minute. It shows the **same refund, retried once**, told two ways:
without Airlock the customer is refunded twice; with Airlock, exactly once.

## Run it

```bash
pip install airlock
# (until the PyPI release lands, install from TestPyPI:)
# pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ airlock

python demo.py
```

No database to set up, no cloud account, no API keys. `airlock.init()` with no
store argument uses a local SQLite file (`./airlock.db`), which the script
creates and cleans up for you.

## What you'll see

**ACT 1 — without Airlock.** A naive agent issues a refund, then a retry (a
duplicated tool call, a crash-and-resume, an over-eager agent) fires the same
refund again. Nothing dedupes it:

```
❌ Customer refunded TWICE ($50.00 charged back 2 times, $100.00 total)
```

**ACT 2 — with Airlock.** The exact same tool, wrapped in `@guard`. The retry
is caught and returns the first result — the payment API is not even called a
second time:

```
✅ Refunded exactly once (the retry was deduped by the commit ledger)
```

## Why it works (2 sentences)

`@guard` derives one deterministic **idempotency key** from the call arguments
and uses a **commit ledger** (a `UNIQUE(idempotency_key)` row) as the source of
truth for whether the side effect has happened — the first call claims the key
and runs the refund; the retry sees the conflict and returns the recorded
result instead of re-executing (SPEC.md **ADR-1**, exactly-once ledger). The
same key is passed *downstream* to the payment API via `Effect(key_param=...)`,
so you get two independent layers of dedup end-to-end (SPEC.md **ADR-2**).

## Files

- `demo.py` — the runnable two-act story (`python demo.py`).
- `fake_payment_api.py` — a ~40-line in-memory stand-in for a Stripe-shaped
  payment provider (no network); it records real refund side effects so the
  demo can count them, and dedupes on an idempotency key like a real API.

For the full story — the API surface, the durable pause + human approval path,
and the tamper-evident audit chain — see the [top-level README](../../README.md).
