# `/contracts` changelog

The Airlock wire + event + serialization contracts (SDK ↔ hosted control
plane). Both repos vendor these and run fixture tests against them; **pinned
fixtures stay green forever** — a failing old fixture is the "never break it
silently" tripwire (PLAN.md 6). Anything breaking is a new *versioned*
artifact (`/api/v2`, `action_event.v2.json`, `airlock-canon-2`, a `v2=`
signature scheme), never an in-place edit of a shipped one.

Versioning rules by artifact:

- **Wire API** (`openapi.yaml`): major version in the path (`/api/v1/`). Within
  v1, additive-only: the server may add optional response fields (clients ignore
  unknown fields) and new optional request fields ship server-first. Any
  removal / rename / type or semantic change ⇒ `/api/v2`. Request bodies are
  strict (`additionalProperties: false`); responses are tolerant.
- **Signing** (`signing.md` + `examples/signing_vectors.json`): the scheme is
  versioned by the `v1=` signature prefix, independently of the API path. A new
  construction ships as `v2=…` alongside `v1=…`; the reference vectors are
  frozen.
- **Event** (`events/action_event.v1.json`): adding optional fields does not
  bump; any rename/type/semantic change ⇒ `action_event.v2.json`.
- **Canonical JSON** (`canonical-json.md`) and **idempotency**
  (`idempotency.md`): any rule change is a new domain (`airlock-canon-2`,
  `airlock/v2`) — never in place (it would fork every key and audit hash).

## v1 — initial (P3.1)

- Widen `CreateApprovalResponse.status` from `RequestedStatus` to `ApprovalStatus` (`requested|approved|rejected`): an idempotent replay (200) returns the run's current status, as the endpoint description already stated. Backward-compatible (response enum widening; clients parse tolerantly).


The frozen v1 contract set.

- **`openapi.yaml`** — OpenAPI 3.1, the deliberately three-call wire contract
  (PLAN.md 6.2): `POST /api/v1/approvals` (create, idempotent on `approval_ref`),
  `GET /api/v1/approvals/{approval_id}` (the reconciler backstop poll), and the
  `approval.decided` webhook (`POST {customer.webhook_url}`). Keyed end-to-end
  on the SDK-minted `approval_ref` — the only cross-boundary identifier
  (PLAN.md 6.1). The create request body is EXACTLY the frozen allowlist with
  `additionalProperties: false`; the never-transits list is documented
  normatively and enforced structurally (no field carries tool args,
  `idempotency_key`, `downstream_key`, results, `serialized_state`, or audit
  data). Shared Money/Reversibility/BlastRadius/actor-id vocabulary is
  single-sourced from `airlock.types` and kept consistent with
  `action_event.v1`.
- **`signing.md`** + **`examples/signing_vectors.json`** — the `airlock-v1`
  HMAC-SHA256 request-signing scheme (PLAN.md 6.2): canonical string
  `airlock-v1\n{unix_ts}\n{METHOD}\n{path_with_query}\n{sha256_hex(raw_body)}`,
  `Airlock-Key`/`Airlock-Timestamp`/`Airlock-Signature: v1=…` headers, ±300s
  replay window (no nonce store — every endpoint is idempotent), constant-time
  compare on the raw body before parsing, one recoverable secret per customer
  signing both directions. Three fully-worked cross-language reference vectors
  (POST-with-body, empty-body GET, webhook POST) that both SDKs pin to.
- **`examples/`** — pinned request/response fixtures for all three calls
  (`create_approval.request.json`, `create_approval.response.json`,
  `get_approval.response.json`, `approval_decided.webhook.json`) plus
  `signing_vectors.json`.
- Reference implementation: `airlock._signing` (Python). `airlock-cloud`
  reimplements the same spec in Ruby; both are pinned to the vectors.

Prior art shipped before this changelog existed: `events/action_event.v1.json`
(+ fixtures, P2.2), `canonical-json.md` (P2.2), `idempotency.md` (P1.2).
