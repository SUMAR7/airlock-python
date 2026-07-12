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

## v1.2.0 — rejection reason codes (P3.9)

- Add `reject_reasons` to `CreateApprovalRequest` (`openapi.yaml`): an OPTIONAL,
  integrator-authored set of structured rejection CODES the action OFFERS a
  human — a `code -> short human description` map (e.g. `{"needs_more_info":
  "Needs more information", "not_authorized": "Not authorized for this
  amount"}`). A human who REJECTS picks one; the chosen code flows back
  (see `reason_code` below). **Backward-compatible additive widening within v1**
  (not a `/api/v2`): the field may be absent, and every pre-1.2.0 create body
  stays valid forever (the frozen `create_approval.request.json` example and the
  `create_approval_post` / `create_approval_with_context_post` signing vectors
  are UNCHANGED — the SDK omits the field from the wire when it is not set, so
  those bytes are byte-identical; `reject_reasons` serializes LAST, after
  `review_context`, so a with-context-only body is also byte-identical).
- Add `reason_code` to the decision response (`GetApprovalResponse`) and the
  `approval.decided` webhook (`ApprovalDecidedWebhook`): the structured code the
  human chose from the offered set, NULLABLE (null on an approval, when the
  action offered no codes, or when the reviewer chose none). The existing
  free-text `reason` is unchanged and both travel together. On the webhook it is
  an OPTIONAL field (not in `required`) so the frozen `webhook_decided_post`
  signing vector — which predates it — stays valid forever; on the tolerant
  `GetApprovalResponse` it is a normal nullable field. The SDK records it
  verbatim onto `ApprovalRejected.reason_code`.
- **Server-deploys-first (PLAN.md 6.2 versioning rule).** `reject_reasons` is on
  the frozen egress allowlist and the request body is still
  `additionalProperties: false`, so a server that does not yet know the field
  would 400 it. `airlock-cloud` MUST re-pin this contract and accept (store +
  render the offered codes, add the reject-with-code dropdown, deliver
  `reason_code` on the decision + webhook) BEFORE any SDK is configured to send
  `reject_reasons`.
- **Boundary (compliance-critical, SPEC.md 3 / PLAN.md 6.1).** `reject_reasons`
  is STRINGS-ONLY — `additionalProperties.type: string`, both codes and
  descriptions strings; no nested objects, lists, or numbers can transit through
  it — and size-capped (≤ 20 codes, code ≤ 64 chars, description ≤ 200 chars).
  It is integrator-authored ONLY, never auto-populated from tool args. The SDK
  enforces the shape + caps structurally at the `ApprovalRequestWire` boundary
  (`from_pause_request` → `_validate_reject_reasons`), so a smuggled non-string
  or over-limit value raises at build time and never reaches the wire.
- New pinned example: `examples/create_approval.request.with_reject_reasons.json`
  (a create body carrying `reject_reasons`), validated against the schema. A new
  frozen signing vector `create_approval_with_reject_reasons_post` pins the exact
  with-reject_reasons wire bytes + signature (generated from the reference impl).

## v1.1.0 — reviewer context (P3.6)

- Add `review_context` to `CreateApprovalRequest` (`openapi.yaml`): an OPTIONAL,
  integrator-authored labeled-metadata map the human reviewer sees alongside
  `action_summary` (e.g. `{"customer": "acme@co", "order": "#1832"}`).
  **Backward-compatible additive widening within v1** (not a `/api/v2`): the
  field may be absent, and every pre-1.1.0 create body stays valid forever
  (the frozen `create_approval.request.json` example and the
  `create_approval_post` signing vector are UNCHANGED — the SDK omits the field
  from the wire when it is not set, so those bytes are byte-identical).
- **Server-deploys-first (PLAN.md 6.2 versioning rule).** `review_context` is on
  the frozen egress allowlist and the request body is still
  `additionalProperties: false`, so a server that does not yet know the field
  would 400 it. `airlock-cloud` MUST re-pin this contract and accept (store +
  render) `review_context` BEFORE any SDK is configured to send it.
- **Boundary (compliance-critical, SPEC.md 3 / PLAN.md 6.1).** `review_context`
  is STRINGS-ONLY — `additionalProperties.type: string`, both keys and values
  strings; no nested objects, lists, or numbers can transit through it — and
  size-capped (≤ 20 keys, key ≤ 64 chars, value ≤ 500 chars). It is
  integrator-authored ONLY, never auto-populated from tool args. The SDK
  enforces the shape + caps structurally at the `ApprovalRequestWire` boundary
  (`from_pause_request` → `_validate_review_context`), so a smuggled non-string
  or over-limit value raises at build time and never reaches the wire.
- New pinned example: `examples/create_approval.request.with_context.json` (a
  create body carrying `review_context`), validated against the schema. A new
  frozen signing vector `create_approval_with_context_post` pins the exact
  with-context wire bytes + signature (generated from the reference impl).

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
