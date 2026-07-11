# Event schema — `action_event.v1`

Airlock emits **one** event schema, and it emits it for **every** guarded call.
This is deliberate. The event stream is the day-one signal for the future
intelligence layer (threshold recalibration, preference learning, predictive
risk) — signal that is *unrecoverable* if you don't capture it from the start —
so it ships as a stable, versioned contract even though nothing consumes it for
learning yet (SPEC §7).

- **Source of truth:** [`contracts/events/action_event.v1.json`](../contracts/events/action_event.v1.json)
  (JSON Schema). The pydantic model in `airlock.events` is validated against it
  by a fixture round-trip test in CI — the model, the schema, and the pinned
  [example fixtures](../contracts/events/examples) never drift.
- **Where it lives:** every event is written durably as a hash-chained
  `audit_events` row (`event_type='action_event'`), so it inherits the ADR-5
  chain integrity and **never leaves the customer's database**. The
  `idempotency_key` is part of the event and is one of the fields that, by the
  boundary rule ([`contracts`](../contracts), PLAN §6.1), must never transit the
  hosted control plane. An optional `EventSink` mirrors the same object
  best-effort for your own telemetry.
- **When it fires:** at the point the outcome becomes known — a **deny** at
  decision time; an **auto** inside the commit's finalize transaction; a **gate**
  at its terminal transition. Exactly one terminal event per guarded call.

## Fields

| Field | Type | Notes |
|---|---|---|
| `schema_version` | `1` (const) | frozen for this document |
| `event_id` | string | unique per emission (uuid4 hex in the Python SDK) |
| `emitted_at` | RFC 3339 UTC, µs + `Z` | the airlock-canon-1 timestamp; also the hashed `created_at` of the audit row |
| `run_id` | string | the guarded invocation (joins `paused_runs.run_id`) |
| `idempotency_key` | string | the ledger key ([`contracts/idempotency.md`](../contracts/idempotency.md)); **never transits** the control plane |
| `action_type` | string | the stable action identifier |
| `policy_decision` | `auto \| gate \| deny` | `airlock.types.Decision` |
| `cost` | `Money \| null` | `{amount, currency}` — never a JSON float |
| `reversibility` | `reversible \| irreversible \| unknown` | `airlock.types.Reversibility` |
| `blast_radius_estimate` | `low \| medium \| high \| null` | `airlock.types.BlastRadius` (ordered) |
| `guarantee` | `downstream_idempotent \| verifiable \| none` | ADR-2; `none` == ran at-most-once |
| `human_decision` | `approved \| rejected \| null` | `null` when no human was involved |
| `decision_latency_ms` | `int ≥ 0 \| null` | control-plane-computed from its own clock pair, recorded verbatim (PLAN §6.2) |
| `decided_by` | `string \| null` | opaque actor id (`usr_…`), **never** an email (PLAN §10.6) |
| `action_diff` | `null` | **reserved** for the edit-before-approve preference signal (SPEC §7); always `null` in v1 |
| `outcome` | `committed \| aborted \| failed \| unknown \| denied` | `airlock.types.ActionOutcome` |
| `post_verify` | `{ran: bool, result: present\|absent\|unknown\|null}` | whether a probe ran, and its answer |

All the enum value lists are **generated from `airlock.types`** — the single
vocabulary source — and CI-asserted against both this schema and the DDL CHECK
constraints. There is exactly one definition of `Decision`, `Money`,
`BlastRadius`, etc., across the API, the database, the event, and the wire
contract; a fork would be a silent contract break (PLAN §10.5).

## Terminal-state semantics

The `outcome` field distinguishes the honest failure modes that make the "always
provable" guarantee real:

- `committed` — the effect took place exactly once.
- `aborted` — we chose **not** to execute (precondition failure, rejection, config).
- `failed` — executed and **confirmed not** to have taken effect.
- `unknown` — may have executed; cannot prove either way. Never retried, loudly
  audited (the ADR-2 at-most-once outcome).
- `denied` — a policy block that never reached the ledger.

## Versioning rule

The contract is **additive within a major version**:

- adding an **optional** field does **not** bump the version — consumers ignore
  unknown fields;
- any rename, type change, or semantic change ⇒ a new `action_event.v2.json`,
  and these **v1 fixtures stay green forever** (a failing old fixture is the
  "never break it silently" tripwire that both repos run in CI).

That is why `action_diff` ships now as a reserved `null`: the *shape* is stable
from day one, so the preference-learning signal can populate it later without a
v2 or an unjoinable history.
