# The hosted-gate demo — reviewer context + reject reason codes

Some actions are too risky to auto-commit. Airlock **gates** them: the run is
durably paused, a human is shown *what* they are approving, and the side effect
runs only if — and exactly once after — they approve. This demo shows a gate with
the two human-facing features layered on top, all against the file-backed
`ConsoleApprovalTransport` — **no server, no network, no cloud account.**

## Run it

```bash
pip install airlock-sdk        # the import name is `airlock`

python demo.py
```

`airlock.init()` with no store argument uses a local SQLite file (`./airlock.db`),
and the reviewer "inbox" is a JSONL file (`hosted-gated-approvals.jsonl`) — both
created and cleaned up by the script.

## What you'll see

**ACT 1 — approved.** The agent proposes a `$4,200` vendor payout. The demo
prints exactly what the reviewer was delivered — a one-line **summary** and a
curated **context** panel — then a reviewer approves and the payout commits:

```
[airlock] approval requested: Pay acme-cloud $4,200.00 (action=payout.send, …)
          context:
          - vendor: acme-cloud
          - amount: $4,200.00
          - category: vendor payout
…
✅ Committed exactly once — even though the approval was delivered twice.
```

Notice what is **not** there: the `card_number` the tool receives is nowhere in
the reviewer's view. Raw tool args never auto-transit — you expose only what you
put in `summary` / `context`. That is a security boundary, not a formatting
choice.

**ACT 2 — rejected.** The agent proposes another payout; the reviewer rejects it
with one of the **codes the action offered** plus a note. The agent branches on
the code:

```
reason_code = 'unverified_vendor'   reason = 'bank details not on file'
the agent branched on the code -> 'route to vendor onboarding'
✅ A rejection is control flow, not a dead end — and no money moved.
```

## How it works

The single decorator carries all three human-facing fields:

```python
@airlock.guard(
    "payout.send",
    effect=Effect(key_param="idempotency_key"),   # real exactly-once
    summary=lambda vendor, amount_cents, **_: f"Pay {vendor} ${amount_cents/100:,.2f}",
    context=lambda vendor, amount_cents, **_: {"vendor": vendor, "amount": ...},
    reject_reasons={
        "unverified_vendor": "Vendor bank details not verified",
        "over_budget": "Over this month's payout budget",
        "needs_more_info": "Needs more information",
    },
)
def send_payout(vendor, amount_cents, *, card_number, idempotency_key=None): ...
```

- **The gate is durable first.** The `paused_runs` row is written *before* the
  transport is called, so the pause survives a crash or restart — resume it later
  with the `approval_ref`.
- **A decision drives the run home.** The agent re-invokes the same action; it
  re-attaches to the paused run, sees the reviewer's decision, and either commits
  (returning the result) or raises `ApprovalRejected` with the chosen
  `reason_code`. A second delivery of an approval is a no-op — the ledger
  guarantees the payout runs **exactly once** (SPEC.md **ADR-1** / **ADR-4**).
- **Deterministic on the console path.** The demo drives the transport with
  `gate_timeout=0.0`, so each wait scans the approvals file exactly once and
  never sleeps — the whole run is a straight line with no clocks.

## Files

- `demo.py` — the runnable two-act story (`python demo.py`), with
  `act1_approved()` / `act2_rejected()` the test drives directly.

For the full API surface — `@guard`, `Policy`, `Store`, `ApprovalTransport` — and
the reviewer-context / reject-reason references, see the
[top-level README](../../README.md) and [`docs/api.md`](../../docs/api.md).
