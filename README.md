# Airlock

**Gate irreversible agent actions, commit each one exactly once, and prove what happened.**

Airlock is a drop-in Python SDK that wraps an agent's tool calls and makes the
dangerous ones safe: it classifies each call, auto-runs the safe ones, pauses
the risky ones for human approval, blocks the forbidden ones — and commits every
side effect **exactly once** against a durable ledger, recording each step in a
tamper-evident, hash-chained audit trail.

> **The one principle that overrides everything:** *never cause a side effect
> more than once, and always be able to prove what happened.* Every design
> choice serves that. If something risks a double-commit or a gap in the audit
> trail, it is wrong — however convenient.

- **Import name:** `airlock` · **PyPI distribution:** `airlock-sdk` · **License:** MIT · **Status:** pre-1.0, correctness core complete and adversarially tested.

---

## The problem

An agent issues a refund. The call times out, or the process crashes and
resumes, or the model just retries — and the refund fires **again**. The
customer is refunded twice. Swap "refund" for payout, wire transfer, email
blast, ticket purchase: the moment a tool call is not exactly-once, an agent
that retries moves money (or sends messages) more than once.

You cannot fix this by asking the model to be careful. Retries are a feature of
every robust system; the fix has to live *below* the tool call, in something
that remembers whether the effect already happened.

```
Without Airlock:  refund(ch_123)  →  refund(ch_123)  →  ❌ customer refunded TWICE
With Airlock:     refund(ch_123)  →  refund(ch_123)  →  ✅ refunded exactly ONCE
```

That is literally the [`examples/double_refund`](examples/double_refund) demo —
one script, zero infrastructure, under a minute. Run it first.

---

## Quickstart

```bash
pip install airlock-sdk        # the import name is `airlock`
```

> Pre-release: until the first PyPI publish lands you can install from TestPyPI —
> `pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ airlock-sdk`.

The smallest thing that shows exactly-once — no database to set up, no cloud
account. `airlock.init()` with no store uses a local SQLite file (`./airlock.db`):

<!-- airlock:test id=quickstart -->
```python
import airlock
from airlock import Decision, Effect, Money, Policy, Reversibility, Rule

calls = []  # so we can see how many times the side effect actually ran

# A guarded tool. Airlock derives one deterministic idempotency key from the
# call args and passes it downstream to your payment provider (Effect.key_param).
@airlock.guard(
    "payment.refund",
    cost=Money(amount="50.00", currency="USD"),
    reversibility=Reversibility.IRREVERSIBLE,
    effect=Effect(key_param="idempotency_key"),
)
def issue_refund(charge_id, amount_cents, *, idempotency_key=None):
    calls.append(charge_id)  # the real side effect (your Stripe call goes here)
    return {"charge_id": charge_id, "amount_cents": amount_cents}

# Zero-config: no store => a local SQLite file. AUTO commits small refunds inline.
airlock.init(policy=Policy(rules=[Rule(match="payment.*", decision=Decision.AUTO)]))

first = issue_refund("ch_123", 5000)  # claims the ledger key, runs the refund
retry = issue_refund("ch_123", 5000)  # SAME args -> deduped, never re-runs

assert first == retry     # the retry returns the recorded result...
assert calls == ["ch_123"]  # ...and the side effect ran exactly ONCE
```

That is the whole value in fifteen lines: the second call sees the ledger
conflict and returns the first result instead of moving money again.

---

## How it works

Every guarded call takes one of three paths, decided **locally, in-process, in
well under a millisecond — with no network call**:

```
agent → @guard(tool) ─► policy decision (LOCAL, sub-ms, no I/O)
                              │
              ┌───────────────┼────────────────┐
            auto             deny              gate
              │               │                 │
        commit once        block +      durable pause ──► human approval
        (the ledger)       audit                │
                                        on approve: resume ──► commit once
                                                                  │
                                    every step ──► append-only hash-chained audit
```

- **The hot path is boring on purpose.** The auto/deny decision is pure Python —
  no socket, no database, no LLM (ADR-3). ~95% of calls decide here and never
  leave your process. Only a **gated** action touches anything remote, and it is
  already waiting on a human, so that latency is free.
- **Exactly-once is enforced by a ledger, not by hope** (ADR-1). A
  `commit_records` row with `UNIQUE(idempotency_key)` is the source of truth for
  whether a side effect has happened. The first caller claims the key with
  `INSERT ... ON CONFLICT DO NOTHING` and runs the effect; a retry or a second
  process sees the conflict and returns the recorded result.
- **Durable pause is a persisted state machine, not a webhook** (ADR-4). A gated
  run is written to `paused_runs` before anyone is asked, so it survives a crash,
  a deploy, or a restart. Resume is idempotent: a double-delivered approval
  cannot double-commit — the ledger guards it.
- **Audit is append-only and hash-chained** (ADR-5). Each row stores
  `row_hash = SHA256(prev_hash ‖ canonical(event))`, so any tampering,
  truncation, or reordering is detectable with `verify_chain` — no external
  crypto infrastructure.
- **The customer's data never leaves the customer's boundary.** The commit
  ledger and the audit-of-record live in *your* database (data plane). Only
  approval requests and minimal metadata ever transit the optional hosted
  control plane — never tool payloads, never the idempotency key, never audit
  rows (see [`/contracts`](contracts)).

---

## The four surfaces

The entire public API is four small, stable pieces.

### 1. `@guard` — wrap a tool

`@guard` is the only thing most integrations touch. It decides auto/gate/deny
per call and, on AUTO, commits the effect exactly once. Decoration is
side-effect-free; the runtime is resolved lazily from `init()` at call time, so
you can decorate tools at import and wire the store later. (See the
[Quickstart](#quickstart) for a full runnable `@guard`.)

### 2. `Policy` — decide auto / gate / deny

A `Policy` is an ordered list of declarative `Rule`s (first match wins) plus a
default. It is pure and deterministic — no I/O, ever — so it stays on the hot
path and a Rego/OPA backend can slot in later without touching call sites.

<!-- airlock:test id=policy -->
```python
from airlock import ActionContext, Decision, Money, Policy, Reversibility, Rule

policy = Policy(
    rules=[
        # Small refunds commit automatically:
        Rule(match="payment.refund", decision=Decision.AUTO,
             max_cost=Money(amount="100.00", currency="USD")),
        # Payouts are blocked outright:
        Rule(match="payout.*", decision=Decision.DENY),
    ],
    default=Decision.GATE,  # everything else pauses for a human (fail safe)
)

small  = ActionContext("payment.refund", Reversibility.IRREVERSIBLE,
                       cost=Money(amount="50.00", currency="USD"))
big    = ActionContext("payment.refund", Reversibility.IRREVERSIBLE,
                       cost=Money(amount="5000.00", currency="USD"))
payout = ActionContext("payout.send", Reversibility.IRREVERSIBLE)

assert policy.evaluate(small)  is Decision.AUTO  # under the ceiling
assert policy.evaluate(big)    is Decision.GATE  # over it -> falls through to default
assert policy.evaluate(payout) is Decision.DENY
```

The default `default` is `GATE`: an action no rule matches **fails safe** — it
pauses for a human rather than auto-committing.

### 3. `Store` — the commit ledger

The `Store` protocol is where the ledger, the pauses, and the audit chain live.
Two backends ship: SQLite (stdlib, zero-config, single host) and Postgres
(multi-host production). Pick one with a DSN — same guarantees either way.

<!-- airlock:test id=store -->
```python
import airlock
from airlock.store import from_url

# SQLite — zero-config, single host (quickstart & dev):
store = from_url("sqlite:///airlock.db")

# Postgres — multi-host production (pip install 'airlock-sdk[postgres]'):
#   store = from_url("postgresql://user@host/dbname")

app = airlock.init(store=store)  # wire it as the commit ledger for @guard
assert app.store is store
store.close()
```

### 4. `ApprovalTransport` — reach a human on a gate

When a policy gates an action, Airlock durably pauses it and delivers it through
an `ApprovalTransport`. The built-in `ConsoleApprovalTransport` is a file-backed
stub — perfect for local dev and the MVP: a human (or a script) appends a
decision line, and the paused run resumes and commits **exactly once**.

<!-- airlock:test id=gate -->
```python
import airlock
from airlock import Decision, Effect, HumanDecision, Money, Policy, Reversibility, Rule
from airlock.transport.console import ConsoleApprovalTransport

sent = []

@airlock.guard(
    "payout.send",
    cost=Money(amount="5000.00", currency="USD"),
    reversibility=Reversibility.IRREVERSIBLE,
    effect=Effect(key_param="idempotency_key"),
)
def send_payout(vendor, amount_cents, *, idempotency_key=None):
    sent.append(vendor)  # the money-moving side effect
    return {"vendor": vendor, "amount_cents": amount_cents}

transport = ConsoleApprovalTransport("airlock-approvals.jsonl")
app = airlock.init(
    policy=Policy(rules=[Rule(match="payout.*", decision=Decision.GATE)]),
    transport=transport,
    gate_wait=False,  # don't block: raise ActionPending and resume out of band
)

# The gated call durably pauses instead of executing:
try:
    send_payout("acme", 500_000)
except airlock.ActionPending as pending:
    ref = pending.approval_ref  # the resume handle (survives a crash/restart)

assert sent == []  # nothing ran yet — the side effect is fenced behind approval

# ...a human reviews the request in the inbox and approves. Drive it home:
outcome = app.resume(ref, HumanDecision.APPROVED)  # commits exactly once
app.resume(ref, HumanDecision.APPROVED)            # duplicate delivery: a no-op

assert sent == ["acme"]  # the payout ran exactly ONCE, after approval
app.store.close()
```

The pause is written to `paused_runs` **before** the transport is ever called,
so the approval outlives the process — resume it hours later, on a fresh
deploy, with the same `approval_ref`.

---

## What the human sees on a gate — reviewer context

A reviewer can only make a good decision if they can *see* what they are
approving. So `@guard` lets you attach two integrator-authored, human-facing
fields to a gate:

- **`summary`** — a one-line description the reviewer reads first ("Refund
  $5,000 to acme@co for charge ch_9"), a plain string or a callable of the tool
  args.
- **`context`** — a small, curated key/value panel shown alongside it
  (`{"customer": "acme@co", "charge": "ch_9", "amount": "$5,000.00"}`).

The point is control: **raw tool args never auto-transit.** A card number, a PII
blob, or a full request body passed to your tool does *not* leak to the approval
inbox — the reviewer sees only what you deliberately put in `summary` / `context`.
That is a security boundary, not a formatting nicety (it is the same
data-plane/control-plane line the wire contract enforces in [`/contracts`](contracts)).

<!-- airlock:test id=reviewer_context -->
```python
import io
import airlock
from airlock import Decision, Effect, Money, Policy, Reversibility, Rule
from airlock.transport.console import ConsoleApprovalTransport

@airlock.guard(
    "payment.refund",
    cost=Money(amount="5000.00", currency="USD"),
    reversibility=Reversibility.IRREVERSIBLE,
    effect=Effect(key_param="idempotency_key"),
    # What the human READS — an integrator-authored one-liner (of the tool args):
    summary=lambda charge_id, amount_cents, **_: (
        f"Refund ${amount_cents / 100:,.2f} for charge {charge_id}"
    ),
    # ...and a curated context panel. YOU pick what the reviewer sees; the raw
    # tool args (here the card number) never auto-transit — that is the boundary.
    context=lambda charge_id, amount_cents, **_: {
        "customer": "acme@example.com",
        "charge": charge_id,
        "amount": f"${amount_cents / 100:,.2f}",
    },
)
def issue_refund(charge_id, amount_cents, *, card_number, idempotency_key=None):
    return {"charge_id": charge_id}

# Capture what the transport actually delivers to the human:
seen_by_reviewer = io.StringIO()
transport = ConsoleApprovalTransport("approvals.jsonl", out=seen_by_reviewer)
app = airlock.init(
    policy=Policy(rules=[Rule(match="payment.*", decision=Decision.GATE)]),
    transport=transport,
    gate_wait=False,  # deliver + durably pause; don't block this example
)

try:
    issue_refund("ch_9", 500_000, card_number="4111-1111-1111-1111")
except airlock.ActionPending:
    pass  # durably paused, awaiting a human — as expected

shown = seen_by_reviewer.getvalue()
assert "Refund $5,000.00 for charge ch_9" in shown   # the summary the human reads
assert "customer: acme@example.com" in shown          # the curated context panel
assert "charge: ch_9" in shown
assert "4111-1111-1111-1111" not in shown  # the raw card arg NEVER auto-transits
app.store.close()
```

Both fields are **strings-only and size-capped** at the wire boundary (`summary`
≤ 500 chars; `context` ≤ 20 keys, key ≤ 64, value ≤ 500) — an over-limit or
non-string value raises there and *nothing* is sent, so a gate can never quietly
smuggle a payload past the boundary.

---

## A rejection is control flow, not a dead end — reason codes

When a human rejects a gated action, the agent shouldn't just fail — it should
*react*. `@guard(reject_reasons=...)` declares the structured codes this action
offers a reviewer (`code -> human label`). The reviewer picks one, and the chosen
code comes back on `ApprovalRejected.reason_code` so the calling agent can branch
on it — retry with more detail, escalate, or give up, deterministically.

<!-- airlock:test id=reject_reasons -->
```python
import airlock
from airlock import Decision, Money, Policy, Reversibility, Rule
from airlock.transport.console import ConsoleApprovalTransport

charged = []  # so we can prove the side effect never ran on a rejection

@airlock.guard(
    "payment.charge",
    cost=Money(amount="900.00", currency="USD"),
    reversibility=Reversibility.IRREVERSIBLE,
    # The codes THIS action offers a reviewer who rejects (code -> human label):
    reject_reasons={
        "suspected_fraud": "Suspected fraud",
        "needs_more_info": "Needs more information",
        "over_limit": "Over the customer's limit",
    },
)
def charge_card(customer_id, amount_cents):
    charged.append(customer_id)  # the money-moving side effect
    return {"customer_id": customer_id, "amount_cents": amount_cents}

transport = ConsoleApprovalTransport("approvals.jsonl")
app = airlock.init(
    policy=Policy(rules=[Rule(match="payment.*", decision=Decision.GATE)]),
    transport=transport,
    gate_wait=True,
    gate_timeout=0.0,  # scan the approvals file once, never block (deterministic)
)

# 1) The agent calls the tool; with no decision yet, it durably pauses.
try:
    charge_card("cus_42", 90_000)
except airlock.ActionPending as pending:
    ref = pending.approval_ref  # the resume handle

# 2) A human reviews it and REJECTS, picking one of the offered codes + a note.
#    (Scripted here by appending to the console approvals file.)
transport.record_decision(
    ref, "rejected", reason_code="suspected_fraud", reason="card reported stolen"
)

# 3) The agent retries the SAME action. It re-attaches to the paused run, sees
#    the decision, and the rejection comes back as CONTROL FLOW, not a dead end:
handled = None
try:
    charge_card("cus_42", 90_000)
except airlock.ApprovalRejected as rej:
    if rej.reason_code == "needs_more_info":
        handled = "resubmit with more detail"
    elif rej.reason_code == "suspected_fraud":
        handled = "escalate to the fraud team"  # branch on the coded reason
    else:
        handled = "give up"
    note = rej.reason  # the optional free-text the reviewer left

assert handled == "escalate to the fraud team"
assert note == "card reported stolen"
assert charged == []  # the card was NEVER charged — the effect stayed fenced
app.store.close()
```

The codes are **your** vocabulary — Airlock never invents or validates them, it
just carries the reviewer's choice back verbatim. Because the code is persisted
on the paused run, a *fresh-process* resume (a webhook, a reconciler sweep) still
surfaces the same `reason_code`, not only the inline path. Like `context`,
`reject_reasons` is integrator-authored only and never populated from tool args.

---

## Exactly-once, or honest about it

Airlock can only *guarantee* exactly-once when the downstream effect is either
**idempotent** (it accepts a key you pass through — Stripe's `Idempotency-Key`)
or **verifiable** (you give it a probe that answers "did this happen?"). That is
ADR-2, and you declare it per action with `Effect`.

When a tool is **neither** idempotent nor verifiable, Airlock refuses to pretend.
It degrades to **at-most-once** (fail safe — it never blind-retries an
unprovable effect), stamps that `none` guarantee durably on every ledger row,
and says so **loudly** with an `AtMostOnceWarning`:

<!-- airlock:test id=at_most_once -->
```python
import warnings
import airlock
from airlock import AtMostOnceWarning, Decision, Policy, Reversibility, Rule

# No key_param, no verify probe => Airlock cannot prove a retry is safe.
@airlock.guard("demo.email", reversibility=Reversibility.IRREVERSIBLE)
def send_email(to, body):
    return {"to": to}

airlock.init(policy=Policy(rules=[Rule(match="demo.*", decision=Decision.AUTO)]))

with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always")
    send_email("ada@example.com", "hi")

assert any(isinstance(w.message, AtMostOnceWarning) for w in caught)
```

This is a **feature**, not a limitation. The honest failure mode — "I could not
prove this is safe to retry, so I ran it at most once and told you" — is exactly
what keeps a retry loop from quietly double-sending. Escalate it to an error in
strict environments with `-W error::airlock.AtMostOnceWarning`.

---

## Postgres for production, SQLite for quickstart

Both backends enforce the **same** exactly-once / durable-pause / audit-chain
guarantees. The only difference is scope.

| | SQLite (default) | Postgres |
|---|---|---|
| Setup | zero-config — `airlock.init()` | `pip install 'airlock-sdk[postgres]'` |
| Wire it | `init()` or `init(store="sqlite:///airlock.db")` | `init(store="postgresql://…")` |
| Scope | single host, one volume | multi-host, production |
| Guarantees | ADR-1 / ADR-4 / ADR-5, in full | ADR-1 / ADR-4 / ADR-5, in full |

`airlock.init()` with no store installs the SQLite dev store and warns once that
it is single-host — move to Postgres the moment more than one machine touches the
ledger. Nothing else in your code changes.

---

## The hosted control plane (optional)

The SDK is complete on its own — gate, commit, durable pause, and audit all work
with zero hosted infrastructure. When you want a real approval **inbox** instead
of a JSONL file, an optional hosted control plane provides one, reached through
`HttpApprovalTransport`. Only approval requests and minimal metadata cross that
boundary; the wire contract is open and versioned in
[`/contracts`](contracts) (OpenAPI + HMAC signing spec + pinned fixtures) so you
can verify exactly what transits.

This is the **open-core** line (ADR-7): the commit path — the part trust depends
on — is **OSS forever**. The hosted tier adds the human-facing approval UI, the
audit warehouse, and multi-team policy. A core-correctness feature will never
move behind the paywall.

### Point the SDK at it

Swap the `ConsoleApprovalTransport` for `HttpApprovalTransport`. Everything else
— `@guard`, the durable pause, `resume` — is identical.

```python
import airlock
from airlock import Decision, HttpApprovalTransport, Policy, Rule

transport = HttpApprovalTransport(
    base_url="https://airlock.example.com",   # your control plane
    key_id="ak_live_…",                        # from the inbox Settings page
    secret="sk_live_…",                        # shown once — keep it as a secret
)

app = airlock.init(
    store="postgresql://…/airlock",            # durable pauses live here
    policy=Policy(rules=[Rule(match="payment.*", decision=Decision.GATE)]),
    transport=transport,
    gate_wait=False,   # don't block: the gate raises ActionPending; resume later
)
```

A gated call POSTs a signed request to the inbox, writes a durable `paused_runs`
row, and raises `ActionPending`. **There is no expiry** — a human can decide in a
minute or in three weeks, and the pause simply waits.

### How the decision reaches your agent

When a human approves or rejects, the decision comes back one of two ways — and
both funnel into the same idempotent `resume`, so the effect runs **exactly
once** no matter which arrives first or how many times it is delivered.

**Push — a webhook (lowest latency).** Mount the dependency-light receiver at a
URL; it verifies the HMAC on the raw body *before* parsing, then drives the
paused run home:

```python
# asgi.py — serve with uvicorn/hypercorn at your public webhook URL
from airlock import webhook_app
from airlock.store import from_url

app = webhook_app(store=from_url("postgresql://…/airlock"), secret="sk_live_…")
```

Set that URL on the inbox **Settings** page; the control plane then POSTs each
`approval.decided` to it, retrying for ~25 hours. A redelivery is a safe no-op.

**Pull — a backstop poll (no inbound endpoint).** Run a periodic sweep that asks
the control plane for decisions still pending locally. It needs no public
endpoint and covers every gap the push can't — you run no receiver, it was down,
or the retries were exhausted:

```python
from datetime import timedelta
from airlock.reconcile import backstop_poll_paused

# on a cron/scheduler: every few minutes, or hourly for week-long waits
backstop_poll_paused(app.store, transport, older_than=timedelta(minutes=2))
```

Leave the Settings webhook URL **blank** to run poll-only — the simplest setup
and inherently resilient to downtime; add the webhook later purely to cut
latency. Either way the decision is always readable at
`GET /api/v1/approvals/{id}`, so nothing is ever lost. Configure the endpoint
and rotate credentials from the inbox's **Settings** page (no console needed).

---

## Status & maturity

Pre-1.0. The **correctness core is complete and adversarially tested**:
exactly-once under concurrency and crash-injection, verify-first crash recovery,
durable pause that survives restart, idempotent resume under double-delivered
approvals, and a hash-chained audit that detects tampering — all pinned by a
Hypothesis property suite and a multi-process concurrency matrix on both SQLite
and Postgres. The API surface (`@guard`, `Policy`, `Store`, `ApprovalTransport`)
is small and intended to stay stable.

Not yet: a `1.0` API-stability promise, and the polish that comes with
design-partner mileage. See [`CHANGELOG.md`](CHANGELOG.md).

## Links

- [`examples/`](examples) — runnable, zero-infrastructure examples (start with
  [`double_refund`](examples/double_refund)).
- [`docs/api.md`](docs/api.md) — the four surfaces + `init` / `Airlock.resume` /
  `verify_chain`, with signatures.
- [`docs/architecture.md`](docs/architecture.md) — the auto/gate/deny flow, the
  data/control-plane split, and the ADRs.
- [`docs/event-schema.md`](docs/event-schema.md) — the versioned `action_event.v1`
  day-one event contract.
- [`contracts/`](contracts) — the wire contract, signing spec, canonical-JSON and
  idempotency specs, and pinned fixtures.

## License

[MIT](LICENSE).
