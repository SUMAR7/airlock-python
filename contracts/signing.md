# Request signing — `airlock-v1` (frozen)

*Language-neutral contract. The Python implementation is `airlock._signing`;
`airlock-cloud` (Ruby) reimplements this same document, and **both are pinned
to the reference vectors** in [`examples/signing_vectors.json`](examples/signing_vectors.json)
(§7). Any change to these rules is a new signature version (`v2=…`), never an
in-place edit — silently changing the scheme would reject every in-flight
request between a mixed-version SDK and control plane.*

Every call in the [wire contract](openapi.yaml) is signed and verified this
way, in **both directions**: the two SDK→cloud calls (`POST /api/v1/approvals`,
`GET /api/v1/approvals/{approval_id}`) and the cloud→customer webhook
(`POST {customer.webhook_url}` carrying `approval.decided`). One secret per
customer signs both directions (§5).

## 1. What is signed

Three request headers travel with every call:

| Header | Value | In the signed string? |
|---|---|---|
| `Airlock-Key` | the key id `ak_live_…` identifying the customer secret | no |
| `Airlock-Timestamp` | unix **seconds** as an ASCII integer | **yes** |
| `Airlock-Signature` | `v1=<lowercase hex HMAC-SHA256(secret, canonical_string)>` | — (it *is* the signature) |

The signature scheme is versioned **independently** of the API path version by
the `v1=` prefix (§4): a future construction ships as `v2=…`, and the header MAY
carry several space/comma-separated schemes at once during a rollover.

## 2. The canonical string

The exact bytes fed to HMAC are five fields joined by a single **LF (`0x0A`)**,
with **no trailing newline**:

```
airlock-v1\n{unix_ts}\n{METHOD}\n{path_with_query}\n{sha256_hex(raw_body)}
```

Spelled out, byte for byte:

1. the literal ASCII `airlock-v1` (the domain/version prefix);
2. `{unix_ts}` — the **exact ASCII text** of the `Airlock-Timestamp` header
   (stringified integer; no normalization — the verifier rebuilds the string
   from the header text and only parses it to an int for the window check, so
   leading zeros or a `+` can never desync signer and verifier);
3. `{METHOD}` — the HTTP method in **uppercase ASCII** (`POST`, `GET`);
4. `{path_with_query}` — the request target **exactly as sent**: the path, plus
   `?` and the raw query string if one is present. No scheme, no host, no
   fragment. (The reference calls carry no query; if a query is present it is
   included verbatim — do not reorder or re-encode it.)
5. `{sha256_hex(raw_body)}` — **lowercase hex** SHA-256 of the **raw request
   body bytes**, exactly as transmitted. An empty body (the GET) uses the
   SHA-256 of the empty string:
   `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

**Signing and verification operate on the raw bytes, BEFORE any JSON parsing.**
The body is never canonicalized or reserialized for signing — the bytes a human
approved are the bytes that were signed, and an intermediary that reformats the
JSON invalidates the signature (intended). A verifier hashes the received bytes
and rejects a mismatch by *signature*, not by the parser, so a malformed or
oversized body never reaches JSON decoding.

## 3. The HMAC

```
signature = "v1=" + lowercase_hex( HMAC-SHA256( key = UTF8(secret), msg = UTF8(canonical_string) ) )
```

- **The HMAC key is the secret token's UTF-8 bytes, verbatim** — the full
  `sk_live_…` string is used directly as the key, with **no** base64/hex decode
  step. (The token embeds 32 bytes of entropy; the *signing key* is nonetheless
  the token bytes themselves. This is the least ambiguous choice across
  languages: Python `hmac.new(secret.encode(), …)` and Ruby
  `OpenSSL::HMAC.hexdigest("SHA256", secret, …)` both take the key as bytes with
  no decoding.)
- The message is the UTF-8 encoding of the canonical string from §2.
- The output is lowercase hex (64 chars), prefixed `v1=`.

## 4. Verification

The verifier (either side) accepts a request iff **all** hold:

1. `Airlock-Timestamp` is present and parses as an integer;
2. it is within the replay window: `|now − timestamp| ≤ 300` seconds;
3. `Airlock-Signature` carries a `v1=<hex>` token; and
4. that hex **equals** the HMAC recomputed per §2–§3, compared in **constant
   time** (`hmac.compare_digest` in Python, `secure_compare` in Ruby — never
   `==`, which leaks length/prefix timing).

Any missing or malformed header ⇒ reject (return `false`; never raise). The
canonical string is rebuilt from the timestamp header's **raw text** (not a
reparsed int) so both sides agree byte-for-byte.

### Replay window & why there is no nonce store

Reject if `|now − timestamp| > 300s` (clock skew or replay). There is
**deliberately no nonce/seen-id store**, because **every endpoint is idempotent
by construction**, so a replay *inside* the window is a harmless no-op:

- `POST /api/v1/approvals` is idempotent on the SDK-minted `approval_ref`
  (hosted `UNIQUE(customer_id, approval_ref)`) — a replay returns the existing
  record;
- `GET /api/v1/approvals/{approval_id}` is read-only;
- the `approval.decided` webhook is driven through `apply_decision` (ADR-4
  ensure-committed), which dedupes on `approval_ref` — a replayed webhook
  re-drives to the same terminal outcome and commits nothing twice.

This is why the boundary can stay a three-call contract with no extra replay
infrastructure.

## 5. Keys & provisioning (Phase 3 = one key per customer)

- A customer has **one** key pair, console-seeded: a key id `ak_live_…` (sent in
  `Airlock-Key`) and a 32-byte secret encoded into a token `sk_live_…` (the
  HMAC key, §3).
- The **same secret signs both directions** — SDK→cloud and cloud→customer — so
  the secret must be **recoverable, encrypted-at-rest, never hashed** (a hashed
  secret cannot sign the outbound webhook). In `airlock-cloud` it is stored with
  Rails Active Record encryption and shown to the operator once at creation.
- **Rotation is deferred** past Phase 3. The `v1=` scheme prefix and the
  multi-scheme header already leave room for it (overlap two secrets/versions
  during a roll) without a contract change.

## 6. Why these choices

- **Timestamp in the signed string + a tight window** stops a captured
  signature from being replayed indefinitely, without a nonce store.
- **Hashing the raw body (not a parsed/re-serialized form)** means the signature
  covers the exact bytes, so body tampering — even a whitespace-only reformat —
  is caught before parsing, and a huge body is rejected cheaply.
- **Method + path-with-query in the string** bind a signature to one endpoint
  and target, so a valid signature for a GET poll cannot be lifted onto a POST.
- **Constant-time compare** removes the timing side channel that `==` on the hex
  digest would open.

## 7. Reference vectors (the cross-language golden values)

The machine-readable form is [`examples/signing_vectors.json`](examples/signing_vectors.json);
**both SDKs' test suites reproduce every `canonical_string` and `signature`
byte-for-byte** (`tests/test_signing.py` here). All three use the fixed test
credentials:

```
key_id (Airlock-Key):  ak_live_7f3a9c2e8b1d4a6f
secret (HMAC key):     sk_live_airlock_reference_vector_secret_do_not_use
timestamp:             1783944000
```

`\n` below is a literal LF; the canonical string has no trailing newline.

### Vector 1 — `POST /api/v1/approvals` (JSON body)

```
method: POST
path:   /api/v1/approvals
raw_body (exact bytes):
{"approval_ref":"3f8b1c2a-9d4e-4f6a-8b1c-2a9d4e4f6a8b","run_id":"run_9d1f2e3a4b5c6d7e8f9a0b1c2d3e4f50","action_type":"refund.create","action_summary":"Refund invoice inv_42 (12.50 EUR) to customer cus_8xq","cost":{"amount":"12.5","currency":"EUR"},"reversibility":"irreversible","blast_radius_estimate":"low","requested_at":"2026-07-11T03:59:20.000000Z","sdk_version":"0.0.1"}

sha256_hex(raw_body): 217ab0d3a5f81bcae71235c3cf91f9281148948a125d76594f6a8f2eda8bf17b
canonical_string:     airlock-v1\n1783944000\nPOST\n/api/v1/approvals\n217ab0d3a5f81bcae71235c3cf91f9281148948a125d76594f6a8f2eda8bf17b
Airlock-Signature:    v1=4167dfe1da0e4bf4791d337b9a536cbcdd9550a9e65603cfbc849707dd57a167
```

### Vector 2 — `GET /api/v1/approvals/{approval_id}` (empty body)

```
method: GET
path:   /api/v1/approvals/apr_01J9ZKQABCDEF0123456789XYZ0
raw_body:             (empty)
sha256_hex(raw_body): e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
canonical_string:     airlock-v1\n1783944000\nGET\n/api/v1/approvals/apr_01J9ZKQABCDEF0123456789XYZ0\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Airlock-Signature:    v1=b56ad63353b29df061e5652d531fbd6fd0467af8fe6673852b0def5c5e81cc20
```

### Vector 3 — `POST {customer.webhook_url}` (`approval.decided`)

```
method: POST
path:   /airlock/webhooks
raw_body (exact bytes):
{"event":"approval.decided","delivery_id":"dl_01J9ZM7C3QKX8V2N4B6D8F0H1K","approval_id":"apr_01J9ZKQABCDEF0123456789XYZ0","approval_ref":"3f8b1c2a-9d4e-4f6a-8b1c-2a9d4e4f6a8b","run_id":"run_9d1f2e3a4b5c6d7e8f9a0b1c2d3e4f50","decision":"approved","decided_by":"usr_01J9ZK3PABQR7VN3WL9TB6DF1S","decided_by_display":"alice@acme.example","decided_at":"2026-07-11T04:02:40.000000Z","decision_latency_ms":200000,"reason":null}

sha256_hex(raw_body): 0cca3beb725342340274c1123bd00b9b5e3c319f714bd696caa51c4b8a8c1a7d
canonical_string:     airlock-v1\n1783944000\nPOST\n/airlock/webhooks\n0cca3beb725342340274c1123bd00b9b5e3c319f714bd696caa51c4b8a8c1a7d
Airlock-Signature:    v1=2db8522b3a5124a5d53f7c81cf76b8d268b056f82cf882ab5fb6f7b330d09f42
```
