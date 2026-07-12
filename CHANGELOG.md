# Changelog

All notable changes to Airlock are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches
`1.0`. Until then, the public API (`@guard`, `Policy`, `Store`,
`ApprovalTransport`) is intended to be stable but is not yet covered by a
compatibility promise.

The distribution is published as **`airlock-sdk`**; the import name is
**`airlock`**.

## [Unreleased]

## [0.1.0] — 2026-07-12

The first coherent release: the entire local SDK works end to end, and the
correctness core is proven under concurrency, crash-injection, and property
testing. Summarized by build phase:

- **Phase 0 — scaffold.** `uv` + `hatchling`, Python 3.12+, MIT. Base runtime
  dependency is `pydantic` only; `postgres` (`sqlalchemy` + `psycopg`) and `http`
  (`httpx`) are optional extras, imported lazily so the core import stays light
  (enforced by a CI guard). CI runs ruff, mypy (strict), and pytest across the
  Python matrix with a Postgres service.
- **Phase 1 — the exactly-once commit core (ADR-1/ADR-2).** The `commit_records`
  ledger with `UNIQUE(idempotency_key)`; `commit_once` with explicit transaction
  boundaries (claim → mark-executing → execute → post-verify → finalize);
  deterministic idempotency-key derivation over a canonical arg_map
  (`airlock-canon-1`) with downstream key passthrough; the `Effect` probe
  interface and **loud at-most-once degradation** when a tool is neither
  idempotent nor verifiable; a verify-first reconciler (`python -m airlock
  reconcile`) with an ownership-epoch fence. Backed by an 8-process concurrency
  suite, a crash-injection harness, and a Hypothesis property machine.
- **Phase 2 — policy, gate, and audit (ADR-3/4/5/6).** The `@guard` decorator and
  the native, declarative `Policy` / `Rule` (auto/gate/deny), evaluated on a
  pure, I/O-free hot path; hash-chained, append-only `audit_events` with a
  genesis constant and a `verify_chain` verifier (`python -m airlock audit
  verify`); the durable `paused_runs` state machine with idempotent,
  ensure-committed resume (a double-delivered approval cannot double-commit); the
  file-backed `ConsoleApprovalTransport` stub; and the single, versioned
  `action_event.v1` event contract.
- **Phase 3 — hosted approval inbox (code complete).** The signed HTTP wire
  contract in `/contracts` (OpenAPI + HMAC signing spec + pinned fixtures);
  `HttpApprovalTransport`, an ASGI `webhook_app` receiver, and a reconciler
  backstop poll; the SDK gates an action, it appears in the hosted inbox, a human
  approves, and the SDK commits exactly once — proven by a cross-repo
  end-to-end test across two separate databases (the data/control-plane split
  holds).
- **Phase 4 — OSS launch readiness.** The zero-config `SqliteStore` quickstart
  (single-host, same guarantees as Postgres); the runnable `double_refund` demo
  (without Airlock the agent double-charges; with it, exactly once); and this
  README + API / event-schema / architecture docs, whose code blocks are executed
  in CI so they cannot drift from the shipped API.

This is the first release published to PyPI as `airlock-sdk`, via GitHub
trusted publishing (OIDC).

### Held for a follow-up release

- A `1.0` API-stability commitment.

[Unreleased]: https://github.com/SUMAR7/airlock-python/commits/main
