# Canonical JSON — `airlock-canon-1` (frozen)

*Language-neutral contract. The single shared implementation is
`airlock._canonical` — key derivation (`airlock.idempotency`) and audit-chain
hashing (`airlock.audit`) both import it; **neither reimplements it**. A
future TypeScript SDK implements this same document. Any change to these
rules is a new canon version (`airlock-canon-2`), never an in-place edit —
silently changing canonicalization forks every idempotency key (re-executing
in-flight actions, ADR-1) and breaks verification of every existing audit
chain (ADR-5).*

This document formalizes the rules embedded in
[`idempotency.md` §3](idempotency.md), which predates it (P1.2) and remains
normative for key derivation; the two sections are byte-for-byte compatible
and must stay so — this file is the standalone contract of record from P2.2
on, and `idempotency.md` §3 keeps its embedded subset with a pointer here.

## 1. What consumes this contract

| Consumer | Input | Output |
|---|---|---|
| Idempotency keys ([idempotency.md](idempotency.md)) | the `arg_map` object | `SHA-256("airlock/v1" ‖ action_type ‖ canonical_bytes(arg_map))` |
| Audit chain (ADR-5, PLAN.md 5.2) | the row **envelope** `{seq, run_id, action_type, event_type, created_at, payload}` | `row_hash = SHA-256(prev_hash(32 bytes) ‖ canonical_bytes(envelope))` |

`canonical_bytes(value)` is the UTF-8 encoding of `canonical_json(value)` as
defined below. Equal bytes give equal hashes; nothing else does.

## 2. The serialization rule

`canonical_json(value)` is exactly the output of Python

```python
json.dumps(value, sort_keys=True, separators=(",", ":"),
           ensure_ascii=False, allow_nan=False)
```

over the restricted value domain of §3. Spelled out language-neutrally:

- **object keys sorted by Unicode code point** (see the normative divergence
  note in §4 — this is NOT UTF-16 order);
- separators exactly `,` and `:` — no whitespace anywhere;
- non-ASCII characters emitted **literally** (the bytes are their UTF-8
  encoding), never `\uXXXX`-escaped;
- string escaping as in RFC 8785 (JCS): `"` and `\` escaped, control
  characters below U+0020 escaped using the two-character short forms
  (`\b \t \n \f \r`) where they exist and `\u00XX` otherwise, everything
  else literal;
- no `NaN` / `Infinity` (unrepresentable — floats are rejected outright, §3).

On this domain the rule is RFC 8785-compatible **except for key ordering**
(§4).

## 3. The value domain (restricted, enforced at emit time)

Only these value types are permitted; anything else is **rejected** with an
error naming the offending path (`CanonicalizationError` in Python), *before*
anything is hashed or persisted:

| Type | Rule |
|---|---|
| `null` | as-is |
| `true` / `false` | as-is |
| integer | only if \|n\| < 2^53 (exactly representable in IEEE-754 doubles); larger magnitudes are **rejected** — carry them as strings. A JS/TS consumer would silently corrupt them otherwise, breaking cross-language parity of keys and hashes |
| string | any Unicode string containing **no surrogate code points** (U+D800–U+DFFF) — see below; applies to values AND object keys |
| array | of permitted values |
| object | string keys only (surrogate-free), permitted values |

**Floats are rejected at serialization time, everywhere.** Money is
`{"amount": "<decimal-string>", "currency": "<ISO-4217>"}` — never a JSON
float (PLAN.md 3.2): float formatting differs across languages and would fork
idempotency keys and audit hashes between SDKs.

**Surrogate rejection (normative).** Lone surrogate code points
(U+D800–U+DFFF) have no UTF-8 encoding, so `canonical_bytes` would be
undefined for them; JS strings hold lone surrogates freely, so a TS SDK would
otherwise silently produce *different* bytes. The canonical string domain is
therefore **surrogate-free Unicode**, and strings containing surrogates are
rejected — in values and in object keys. (Python: surrogateescape'd values,
e.g. undecodable filenames from OS APIs, must be re-encoded before
canonicalizing.) Cross-reference: [`idempotency.md` §3](idempotency.md),
which states the identical rule for the key-derivation path.

**Native datetime/Decimal/etc. objects are rejected** — render them first
(§5, §6).

## 4. Key ordering — code point vs UTF-16 (normative divergence from JCS)

**Object keys sort by Unicode code point, NOT by UTF-16 code units.** This
deviates from RFC 8785 (JCS), which sorts by UTF-16 code units, for keys
containing characters above U+FFFF: U+FF61 (`｡`) sorts *before* U+10000 by
code point but *after* it by UTF-16 units (U+10000 encodes as the surrogate
pair D800 DC00). **A JCS library cannot be used as-is for canonicalization —
only its string-escaping rules apply.** Pinned fixture (every SDK's test
suite must reproduce it):

```
input:     {"｡": 1, "𐀀": 2}        (keys U+FF61 and U+10000)
canonical: {"｡":1,"𐀀":2}           (the U+FF61 key sorts FIRST)
```

This is what Python's `sort_keys=True` (plain `str` ordering) does natively;
a TS SDK must sort by code point explicitly (e.g. compare
`Array.from(key)` code points), not by the default `<` string comparison
(which is UTF-16 code-unit order).

## 5. Timestamps

Timestamps inside canonical JSON are **strings** in RFC 3339 UTC form with
microsecond precision and a `Z` suffix:

```
YYYY-MM-DDTHH:MM:SS.ffffffZ        e.g. 2026-07-06T12:00:00.000123Z
```

Native datetime values are rejected — render them first, from a UTC instant.
This exact rendering is what the audit chain hashes as the envelope's
`created_at` (and what `action_event.v1` carries as `emitted_at`): the hashed
string and the stored `TIMESTAMPTZ` column are the same instant, and a
verifier re-renders the stored column and must obtain the identical string.

## 6. Money / decimal strings

Money is `{"amount": "<decimal-string>", "currency": "<ISO-4217>"}`.
Decimal-string normalization (Python: `airlock.decimal_string`):

- plain fixed-point notation, never scientific (`1E+2` → `"100"`);
- no trailing fractional zeros (`12.50` → `"12.5"`) — trailing-zero *scale*
  is presentation, and letting it leak would fork keys/hashes between
  `12.5` and `12.50`;
- zero is always `"0"` (never `-0` or `0.00`);
- a leading `-` only for negative values; no `+`, no thousands separators.

## 7. The audit envelope (ADR-5 consumer, frozen field encoding)

The audit chain hashes `SHA-256(prev_hash ‖ canonical_bytes(envelope))` where
the envelope is the object

```
{"action_type": <string|null>,
 "created_at":  <RFC 3339 UTC string, §5>,
 "event_type":  <string>,
 "payload":     <object, §3 domain>,
 "run_id":      <string|null>,
 "seq":         <integer>}
```

(shown here in its canonical key order). Covering every chain-meaningful
column — not just the payload — is what makes the *columns* tamper-evident,
not only the payload blob. The genesis row is a universal constant: `seq=0`,
`prev_hash = 0x00×32`, `event_type="genesis"`,
`payload={"canon":"airlock-canon-1","chain":"airlock-audit-v1"}`,
`created_at="1970-01-01T00:00:00.000000Z"`, `run_id=action_type=null`.
Verification and the append protocol are specified in PLAN.md 5.2 and
implemented in `airlock.audit` / `airlock.store`.

## 8. Reference vectors

Key-derivation vector: see [`idempotency.md` §1](idempotency.md) (the
`refund.create` vector). Ordering fixture: §4 above. The genesis `row_hash`
constant is computable from §7 alone and is pinned by the SDK test suite
(`airlock.audit.GENESIS_ROW_HASH`); an independent implementation must
reproduce it byte-for-byte.
