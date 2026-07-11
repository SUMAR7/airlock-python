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
