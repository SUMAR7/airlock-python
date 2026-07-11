# API reference

The public surface of Airlock is small and stable: four types you compose
(`@guard`, `Policy`, `Store`, `ApprovalTransport`), the `init()` that wires them,
and a couple of operational functions (`Airlock.resume`, `verify_chain`).
Everything is re-exported from the top-level `airlock` package, so `import
airlock` is all you need — imports stay light (optional extras load lazily).

> Runnable snippets below are executed verbatim in CI
> (`tests/test_readme_examples.py`), so they always match the shipped API.

- [`airlock.init`](#airlockinit) — wire the runtime
- [`@airlock.guard`](#airlockguard) — wrap a tool
- [`Policy` / `Rule` / `ActionContext`](#policy--rule--actioncontext) — the decision
- [`Effect`](#effect) — the ADR-2 exactly-once mechanism
- [`Store`](#store) — the commit ledger
- [`ApprovalTransport`](#approvaltransport) — reach a human on a gate
- [`Airlock.resume`](#airlockresume) — drive a paused run home
- [`verify_chain`](#verify_chain) — audit-chain integrity
- [Errors](#errors)

---

## `airlock.init`

```python
def init(
    *,
    store: Store | str | None = None,       # Store, DSN, or None -> SQLite ./airlock.db
    policy: PolicyBackend | None = None,    # None -> Policy(default=GATE): fail safe
    transport: ApprovalTransport | None = None,  # None -> ConsoleApprovalTransport()
    event_sinks: Sequence[EventSink] = (),
    registry: Registry | None = None,
    reconcile_after: timedelta | None = None,
    execute_timeout: timedelta | None = None,
    gate_wait: bool = True,                 # block on approval inline, else raise ActionPending
    gate_timeout: float = 30.0,             # seconds the inline gate wait polls
    now_fn: Callable[[], datetime] = ...,   # injectable clock (deterministic tests)
) -> Airlock: ...
```

`init()` installs an ambient runtime (a `contextvar`) that every subsequently
invoked `@guard` resolves at call time — so you can decorate tools at import and
wire the store during startup. It returns an `Airlock` handle exposing `.store`,
`.policy`, `.transport`, and `.resume(...)`.

Defaults are all fail-safe: no store gives you the zero-config SQLite dev store
(with a one-time "use Postgres in production" warning); no policy gives you
`Policy(default=GATE)` (unknown actions pause for a human); no transport gives
you the file-backed `ConsoleApprovalTransport`.

- `store`: a `Store`, a DSN string (`postgresql://…` or `sqlite:///…`, built via
  [`from_url`](#store)), or `None` for the SQLite quickstart default.
- `gate_wait`: when `True` (default), a gated call blocks on `transport.wait`
  for up to `gate_timeout` seconds; when `False` (or on timeout) it persists the
  pause, delivers it, and raises `ActionPending` for an async
  [`resume`](#airlockresume).
- `reconcile_after` / `execute_timeout`: the recovery knobs forwarded to the
  commit path (`execute_timeout` must be `< reconcile_after`; see
  [architecture](architecture.md)). Leave both unset for the simple inline
  behavior.

---

## `@airlock.guard`

```python
def guard(
    action_type: str,
    *,
    cost: Money | Callable[..., Money] | None = None,
    reversibility: Reversibility = Reversibility.IRREVERSIBLE,
    blast_radius: BlastRadius | Callable[..., BlastRadius] | None = None,
    key: Callable[..., str] | None = None,        # override key derivation
    key_ignore: tuple[str, ...] = (),             # volatile kwargs excluded from the key
    effect: Effect | None = None,                 # ADR-2 passthrough + probe
    preconditions: Callable[..., bool] | None = None,  # re-checked at commit time
) -> Callable[[Callable], Callable]: ...
```

Decorate a tool function. On each call `@guard`:

1. builds an [`ActionContext`](#policy--rule--actioncontext) from the decorator
   metadata and the call args (resolving any callable `cost` / `blast_radius`
   *before* the policy runs, so the decision stays I/O-free);
2. asks the policy for a `Decision` — **the hot path: pure, in-process, sub-ms**;
3. dispatches:
   - **AUTO** → `commit_once` runs the effect exactly once and returns the tool's
     result;
   - **DENY** → appends a hash-chained audit event, then raises `ActionDenied`
     (no side effect);
   - **GATE** → durably pauses, delivers via the transport, and either waits
     inline (returns the result on approval) or raises `ActionPending`.

Decoration itself is side-effect-free apart from one registration (into the
shared `Registry`) so a reconciler or a resumed run can reconstruct the call from
a bare ledger row. `action_type` must be non-empty and must not contain `:` (the
namespace delimiter for `key` overrides).

- `cost` / `reversibility` / `blast_radius`: the risk inputs the policy filters
  on. `reversibility` defaults to `irreversible` (conservative). `cost` and
  `blast_radius` may be callables of the same args as the tool.
- `key` / `key_ignore`: override or trim the derived idempotency key (see
  [`contracts/idempotency.md`](../contracts/idempotency.md)). Two *intentionally*
  identical calls collide by default — carry a natural unique id in the args, or
  override `key`.
- `effect`: how exactly-once is achievable for this action ([`Effect`](#effect)).
- `preconditions`: re-checked after the claim on AUTO and at commit time on a
  resumed gate (SPEC scenario 8) — a stale approval that no longer holds aborts
  rather than executing.

See the [README quickstart](../README.md#quickstart) for a full runnable `@guard`.

---

## `Policy` / `Rule` / `ActionContext`

```python
@dataclass(frozen=True)
class ActionContext:
    action_type: str
    reversibility: Reversibility
    cost: Money | None = None
    blast_radius: BlastRadius | None = None

@dataclass(frozen=True)
class Rule:
    match: str = "*"                         # fnmatch glob over action_type
    decision: Decision = Decision.GATE
    max_cost: Money | None = None            # only compares when currencies match
    reversibility_in: frozenset[Reversibility] | None = None
    max_blast_radius: BlastRadius | None = None

@dataclass(frozen=True)
class Policy:
    rules: Sequence[Rule] = ()
    default: Decision = Decision.GATE        # unmatched actions fail safe
    def evaluate(self, ctx: ActionContext) -> Decision: ...
```

`Policy.evaluate` is **first-match-wins** over `rules`, falling back to `default`.
It is pure — no I/O, no clock, no captured state — which is what keeps it on the
hot path and lets a Rego/OPA backend implement the same `PolicyBackend` protocol
later without touching call sites.

A `Rule`'s conditions are conjunctive; a condition left at its default is
unconstrained. Fail-safe by construction: a `None` cost never satisfies a
`max_cost`, a cross-currency cost never satisfies it (there is no FX on the hot
path), and a `None` blast radius never satisfies a `max_blast_radius`.

<!-- airlock:test id=policy_reference -->
```python
from airlock import ActionContext, BlastRadius, Decision, Money, Policy, Reversibility, Rule

policy = Policy(
    rules=[
        Rule(
            match="payment.refund",
            decision=Decision.AUTO,
            max_cost=Money(amount="100.00", currency="USD"),
            reversibility_in=frozenset({Reversibility.REVERSIBLE, Reversibility.IRREVERSIBLE}),
            max_blast_radius=BlastRadius.MEDIUM,
        ),
    ],
    default=Decision.GATE,
)

ok = ActionContext("payment.refund", Reversibility.IRREVERSIBLE,
                   cost=Money(amount="40.00", currency="USD"), blast_radius=BlastRadius.LOW)
too_wide = ActionContext("payment.refund", Reversibility.IRREVERSIBLE,
                         cost=Money(amount="40.00", currency="USD"), blast_radius=BlastRadius.HIGH)

assert policy.evaluate(ok) is Decision.AUTO          # every condition holds
assert policy.evaluate(too_wide) is Decision.GATE    # blast radius over the ceiling -> default
```

`Decision` is `auto | gate | deny`; `Reversibility` is `reversible |
irreversible | unknown`; `BlastRadius` is the **ordered** enum `low < medium <
high`; `Money` is `{amount: decimal-string, currency: ISO-4217}` — never a float,
so keys and audit hashes match across languages.

---

## `Effect`

```python
@dataclass(frozen=True)
class Effect:
    key_param: str | None = None            # kwarg the tool accepts a downstream key on
    map_key: Callable[[str], str] | None = None    # transform for downstream length/charset
    verify: Callable[..., tuple[Verification, Any]] | None = None  # "did this happen?" probe
```

`Effect` declares how ADR-2 exactly-once is achievable for an action, and its
`guarantee` follows from what you provide:

| You provide | `guarantee` | Recovery behavior |
|---|---|---|
| `key_param` (downstream idempotency) | `downstream_idempotent` | safe to re-issue with the same key |
| `verify` only | `verifiable` | probe first, re-run only if provably absent |
| neither | `none` | **at-most-once** — never blind-retried; warned loudly |

`verify` is called with the canonical arg_map splatted as kwargs
(`verify(**arg_map)`), both by the post-verify step and by the reconciler after
rehydrating a crashed row — so write it against the arg_map values and accept
`**_` for args it ignores. An `Effect()` with neither degrades to at-most-once
(see [the README](../README.md#exactly-once-or-honest-about-it)).

---

## `Store`

```python
def from_url(url: str) -> Store: ...
```

The `Store` protocol is the persistence seam for the ledger, the pauses, and the
audit chain. Two backends ship, selected by DSN via `from_url` (or passed to
`init(store=...)`):

- `sqlite:///airlock.db` → `SqliteStore` (stdlib `sqlite3`, no extra) — the
  single-host quickstart / dev store. `sqlite:///rel.db` is relative,
  `sqlite:////abs.db` absolute; `?busy_timeout_ms=` tunes lock waiting.
- `postgresql://user@host/db` → `PostgresStore` (needs
  `pip install 'airlock-sdk[postgres]'`) — the multi-host production substrate.

Both enforce the same ADR-1/4/5 guarantees. Call `store.close()` to release
connections when you are done.

<!-- airlock:test id=store_from_url -->
```python
from airlock.store import from_url
from airlock.store.sqlite import SqliteStore

store = from_url("sqlite:///airlock.db")   # schema auto-created
assert isinstance(store, SqliteStore)
store.close()
```

You will not normally call the `Store` methods (`claim` / `mark_executing` /
`finalize` / `save_paused` / `append_audit` / …) directly — `@guard`, the commit
core, and the reconciler drive them. Implement the protocol only to add a new
backend.

---

## `ApprovalTransport`

```python
class ApprovalTransport(Protocol):
    def send(self, request: PauseRequest) -> SendReceipt: ...   # redelivery-safe
    def wait(self, approval_ref: str, timeout: float) -> ApprovalDecision | None: ...
```

The transport is touched **only** on the gate path (a human is already the
latency floor). `send` delivers a boundary-safe summary — a `PauseRequest`
carries identifiers and risk metadata but *structurally cannot* carry tool args,
the idempotency key, or results — and must be redelivery-safe (the durable pause
already exists). `wait` polls for up to `timeout` seconds and returns the
decision, or `None` on timeout (the caller then raises `ActionPending`; the pause
stays durable).

The bundled `ConsoleApprovalTransport` reads/writes a JSONL approvals file:

```python
from airlock.transport.console import ConsoleApprovalTransport

transport = ConsoleApprovalTransport("airlock-approvals.jsonl")
# A human (or a script) records a decision by appending one line:
transport.record_decision(approval_ref, "approved", decided_by="usr_ada")
```

`HttpApprovalTransport` (in `airlock.transport.http`, needs the `http` extra)
targets the hosted control plane over the signed wire contract in
[`/contracts`](../contracts). See the [README gate example](../README.md#4-approvaltransport--reach-a-human-on-a-gate)
for a full runnable pause → approve → commit-once.

---

## `Airlock.resume`

```python
class Airlock:
    def resume(
        self,
        approval_ref: str,
        decision: ApprovalDecision | HumanDecision | None = None,
    ) -> DecisionOutcome: ...
```

The post-restart entry into the idempotent, ensure-committed core (ADR-4). A
fresh process — a deploy, a crash-recovered worker, a webhook receiver —
rehydrates a paused run by `approval_ref` and drives it to its terminal state,
committing **exactly once** however many times the same decision is delivered,
re-validating preconditions at commit time.

- pass a `HumanDecision` (`APPROVED` / `REJECTED`) or a full `ApprovalDecision`
  to apply a fresh decision;
- pass `None` to drive an *already-approved* run home (the reconciler-sweep mode
  — an approval whose commit never landed).

A duplicate delivery returns the same recorded `DecisionOutcome` with
`applied=False`. See the [README gate example](../README.md#4-approvaltransport--reach-a-human-on-a-gate),
which resumes and then resumes again to show the no-op.

---

## `verify_chain`

```python
def verify_chain(
    store: AuditStore,
    *,
    from_seq: int | None = None,     # checkpoint seq (with from_hash) -> O(delta)
    from_hash: bytes | None = None,
) -> ChainReport: ...
```

Stream the hash-chained `audit_events` table `ORDER BY seq` and verify every
link (ADR-5): the genesis constant, gapless `seq`, `prev_hash` linkage, the
recomputed `row_hash`, and the chain-head match — O(n), constant memory. A
tamper, truncation, or reorder raises `AuditChainError` naming the offending
`seq`. `ChainReport` carries `rows_verified`, `from_seq`, `head_seq`, and
`head_hash`.

<!-- airlock:test id=verify_chain -->
```python
import airlock
from airlock import Decision, Effect, Money, Policy, Reversibility, Rule, verify_chain

@airlock.guard("invoice.pay", cost=Money(amount="10.00", currency="USD"),
               reversibility=Reversibility.IRREVERSIBLE,
               effect=Effect(key_param="idempotency_key"))
def pay(invoice, *, idempotency_key=None):
    return {"invoice": invoice}

app = airlock.init(policy=Policy(rules=[Rule(match="invoice.*", decision=Decision.AUTO)]))
pay("inv_42")  # commits once and appends a hash-chained action_event

report = verify_chain(app.store)   # raises AuditChainError if anything was tampered with
assert report.head_seq >= 1        # genesis (seq 0) + the committed action_event
app.store.close()
```

The same check is available operationally as
`python -m airlock audit verify --store $DSN [--from-seq N --from-hash HEX]`
(exit 0 = verified, 1 = tamper detected).

---

## Errors

All Airlock errors subclass `AirlockError`. The ones a `@guard` caller sees:

| Exception | Raised when |
|---|---|
| `ActionDenied` | policy returned `deny` — blocked, no side effect (has `.action_type`) |
| `ActionPending` | gated and not resolved inline — durably paused (has `.approval_ref`, `.run_id`) |
| `ApprovalRejected` | a human rejected the gated action — aborted, no side effect |
| `PreconditionFailed` | preconditions did not hold at commit time (SPEC scenario 8) — aborted |
| `CommitFailed` | the effect finalized non-`committed` (`failed`/`unknown`) — never blind-retried |
| `VerificationUnknown` | a live post-verify probe could not prove present/absent |

`AtMostOnceWarning` (a `UserWarning`, **not** an error) fires once per action
type when an AUTO effect runs with `guarantee='none'`. Escalate it in strict
environments with `-W error::airlock.AtMostOnceWarning`.
