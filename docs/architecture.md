# Architecture

A tight tour of how Airlock is put together. This is the skimmable version; the
authoritative, exhaustive record of the locked decisions and the failure cases
they defend lives in the project's build spec (`SPEC.md` §§1, 3, 4, 5) and
implementation plan (`PLAN.md` §4). This page does not restate them — it
summarizes and cross-references by section.

## The one principle

> Never cause a side effect more than once, and always be able to prove what
> happened.

Everything below serves that single constraint. Where a design choice traded
convenience against it, correctness won.

## The auto / gate / deny flow

Every guarded call takes exactly one path, chosen by a **local, in-process,
sub-millisecond** policy decision:

```
agent → @guard(tool) ─► policy decision (LOCAL, no I/O)
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

- **auto** — the effect is committed exactly once via the ledger and the result
  returned.
- **deny** — the call is blocked before any ledger claim; a hash-chained audit
  event records it and `ActionDenied` is raised. No side effect.
- **gate** — the run is durably persisted, delivered to a human, and — on
  approval — resumed and committed exactly once. A rejection aborts it.

### The hot-path rule (SPEC §3)

The auto/deny **decision** is pure Python: no socket, no database, no LLM, no
file, no clock-dependent branching. ~95% of calls decide here and never leave
the customer's process; a no-socket test pins it. Only a **gated** action ever
touches the network — and it is already waiting on a human, so that latency is
free. AUTO's subsequent ledger writes are customer-VPC data-plane I/O required by
the ledger, not a control-plane call.

## The data-plane / control-plane split (SPEC §3, compliance-critical)

The commit ledger and the audit-of-record live in the **customer's** database
(the data plane, in their VPC). Only approval requests and minimal metadata ever
transit the optional hosted control plane. Tool payloads, the idempotency key
(a digest of the payload), results, and audit rows **never** cross that boundary.

The boundary is structural, not aspirational: the SDK-minted `approval_ref` UUID
is the sole cross-boundary identifier, the transport accepts only a frozen,
allowlisted `PauseRequest` shape (raw payloads have no code path to it), and both
sides test pinned fixtures. The wire contract is open in
[`/contracts`](../contracts) so anyone can verify what transits.

What a gate *does* carry is **integrator-curated, never auto-populated**: the
`action_summary`, the optional `review_context` panel, and the optional
`reject_reasons` code set (`@guard(summary=…, context=…, reject_reasons=…)`) — all
strings-only and size-capped at the `ApprovalRequestWire` boundary, all authored
by the developer, so no tool arg reaches the inbox unless it was deliberately put
there. On the way back, the reviewer's decision returns only minimal metadata:
`human_decision`, `decided_by` (an opaque `usr_…` id), and — when the reviewer
rejects — the chosen `reason_code`, surfaced on `ApprovalRejected.reason_code`
(see [`api.md`](api.md#reviewer-context-and-reject-reasons-the-gate-path)). The
wire fields are versioned additively in
[`contracts/openapi.yaml`](../contracts/openapi.yaml) (`review_context` v1.1.0,
`reject_reasons` / `reason_code` v1.2.0).

## The ADRs (SPEC §4 — locked)

The seven Architecture Decision Records are locked in the spec. In brief:

- **ADR-1 — Exactly-once by a commit ledger, not by hope.** A `commit_records`
  row with `UNIQUE(idempotency_key)` is the source of truth for whether a side
  effect happened; the claim is `INSERT ... ON CONFLICT DO NOTHING`. Every
  guarded action needs a deterministic idempotency key.
- **ADR-2 — Idempotent end-to-end OR verifiable, else at-most-once.** You declare
  per action, via [`Effect`](api.md#effect), a downstream key or a verify probe.
  With neither, Airlock degrades to at-most-once, never blind-retries, and says
  so loudly. *This honesty is a feature.*
- **ADR-3 — No LLM in the decision path.** Policy evaluation is deterministic,
  declarative, local. (Risk *scoring* may use models later, but only to assist a
  human, never to gate inline.)
- **ADR-4 — Durable pause is a persisted state machine, not a webhook.** Gated
  runs serialize to `paused_runs` (`proposed → approved|rejected →
  committed|aborted`) and survive crash / deploy / restart. Resume is idempotent
  — a double-delivered approval cannot double-commit.
- **ADR-5 — Audit is append-only and hash-chained.** Each row stores
  `row_hash = SHA256(prev_hash ‖ canonical(envelope))`; tampering, truncation,
  or reordering is detectable with [`verify_chain`](api.md#verify_chain). Rows
  are never updated or deleted.
- **ADR-6 — Policy starts simple, stays swappable.** The v1 native `Policy` is
  declarative thresholds; the `PolicyBackend` protocol keeps call sites stable so
  a Rego/OPA backend slots in later.
- **ADR-7 — The open-core boundary is fixed.** The SDK (gate + commit + local
  audit) is OSS forever; the hosted tier is the approval UI, audit warehouse, and
  multi-team policy. A core-correctness feature never moves behind the paywall.

## The commit flow (SPEC §5, the correctness core)

The transaction boundaries are what make exactly-once real. `commit_once`:

1. **Claim** — `INSERT ... ON CONFLICT DO NOTHING`, committed in its own
   transaction *before* anything executes. A lost claim reads the existing row:
   terminal → return its outcome; in-flight → wait for the winner.
2. **Re-validate preconditions** (aborts a stale action).
3. **Mark executing** — a durable CAS `pending → executing` committed *before*
   the effect runs. This marker is what makes recovery honest: a row still
   `pending` provably never started its effect.
4. **Execute** the effect (passing the downstream idempotency key where the
   `Effect` supports it), under an execute timeout `< reconcile_after`.
5. **Post-verify** if a probe exists — `present` proceeds, `absent` finalizes
   `failed`, `unknown` leaves it for the reconciler.
6. **Finalize** — CAS to `committed` **plus** the hash-chained audit append in
   **one** transaction. Either both land or neither does.

Recovery is a library, not a daemon: a stale in-flight row is reclaimed by
bumping an ownership **epoch** (which fences the original owner) and then
**verified before any re-execution — never blind-retried**. The same
verify-first machine recovers a paused run whose approval landed but whose commit
crashed. See SPEC §5 and PLAN §4 for the full recovery table and the eight
failure scenarios the suite exercises (concurrency, crash-injection, and
Hypothesis property tests).

## Where the code lives

| Concern | Module |
|---|---|
| `@guard`, `init`, the runtime | `airlock._guard` |
| policy (Decision / Rule / Policy / ActionContext) | `airlock.policy` |
| the commit primitive | `airlock.commit` |
| idempotency key derivation | `airlock.idempotency`, `airlock._canonical` |
| ADR-2 effects + probes | `airlock.effects` |
| verify-first recovery + `python -m airlock reconcile` | `airlock.reconcile` |
| durable pause state machine | `airlock.pause` |
| hash-chain compute/verify + `audit verify` | `airlock.audit` |
| the `action_event.v1` model | `airlock.events` |
| stores (protocol, SQLite, Postgres) | `airlock.store` |
| transports (protocol, console, http) | `airlock.transport` |
| the single enum/type vocabulary | `airlock.types` |
