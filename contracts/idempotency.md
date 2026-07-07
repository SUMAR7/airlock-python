# Idempotency key derivation — `airlock/v1` (frozen)

*Language-neutral contract. The Python implementation is
`airlock.idempotency`; a future TypeScript SDK implements this same document.
Any change to these rules is a new domain version (`airlock/v2`), never an
in-place edit — silently changing key derivation re-executes every in-flight
action (PLAN.md sections 3.4 and 6; SPEC.md ADR-1/ADR-2).*

## 1. The formula

```
key = lowercase_hex( SHA-256( UTF8("airlock/v1") || UTF8(action_type) || canonical_bytes(arg_map) ) )
```

The SHA-256 input is the exact concatenation of three byte strings, in this
order, with **no separators and no length prefixes**:

1. the 10 ASCII bytes `airlock/v1` (the domain-separation prefix);
2. the UTF-8 encoding of `action_type` — a stable, non-empty identifier for
   the action (e.g. `refund.create`);
3. the UTF-8 encoding of the canonical JSON serialization of `arg_map` per
   `airlock-canon-1` (§3 below). Because `arg_map` is a JSON object, this
   segment always begins with the byte `0x7B` (`{`).

The key is the lowercase hexadecimal digest: 64 characters, `[0-9a-f]`.

### Reference vector

```
action_type = "refund.create"
arg_map     = {"amount": "12.50", "currency": "EUR", "invoice": "inv_42"}
canonical   = {"amount":"12.50","currency":"EUR","invoice":"inv_42"}
key         = SHA-256 of the UTF-8 bytes of:
              airlock/v1refund.create{"amount":"12.50","currency":"EUR","invoice":"inv_42"}
```

(The pinned test suite computes this vector independently of the library
code; both must agree forever.)

## 2. The `arg_map`

**The formula is specified over an explicit canonical `arg_map` — a JSON
object mapping argument names to values — NOT over any language's
argument-binding semantics.** Each SDK's job is to construct that object;
the hash sees only the object.

### 2.1 How the Python SDK constructs `arg_map`

`airlock.idempotency.build_arg_map(fn, args, kwargs, *, key_ignore, key_param)`
binds the call against `inspect.signature(fn)` and applies declared defaults,
then normalizes:

- every named parameter appears under its parameter name, **defaults
  included** — so `f(1)`, `f(x=1)`, and `f(1, y=<the default value>)` all
  produce the same map and therefore the same key;
- a variadic-positional parameter (`*args`) appears under its own name as a
  JSON **array** (empty array when nothing extra was passed);
- variadic-keyword entries (`**kwargs`) are merged into the **top level** of
  the map. A name bound *both* as a parameter and inside `**kwargs` **is**
  representable in Python — a positional-only parameter passed positionally
  plus a same-named `**kwargs` entry, e.g. `def f(account, /, **opts)` called
  as `f("a1", account="acme")` — but NOT in the flat `arg_map`, so such calls
  are **rejected loudly** (never silently overwritten: an overwrite would
  make two different calls derive the same key);
- names listed in `key_ignore` (volatile arguments) and the effect's
  `key_param` (the argument that *receives* the derived key downstream) are
  **removed** and never feed the derivation.

### 2.2 How a TypeScript SDK will construct `arg_map`

A single options-object: the caller's options object *is* the `arg_map`
(minus `keyIgnore`/`keyParam` names), no binding semantics involved.

### 2.3 Cross-language key parity

Equal bytes give equal keys; nothing else does. **Cross-language parity
therefore requires identical `arg_map` contents** — the same names mapped to
the same values in both SDKs. A Python function whose parameter names differ
from the TS options-object's property names produces different keys by
design. Integrators who need one action deduped across both SDKs must align
names and value shapes (Money as decimal strings, timestamps as RFC 3339 UTC
strings — §3).

## 3. Canonical JSON — `airlock-canon-1` (embedded)

*These rules are normative for this contract. The standalone contract of
record is [`canonical-json.md`](canonical-json.md) (landed in P2.2 with the
audit hash chain, which consumes the same rule); this embedded section is the
key-derivation subset and is byte-for-byte compatible with it — a divergence
between the two documents is a contract break. The single shared
implementation is `airlock._canonical`.*

Serialization (equivalent to Python
`json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`,
encoded UTF-8):

- object keys sorted by Unicode code point;
- separators exactly `,` and `:` — no whitespace anywhere;
- non-ASCII characters emitted literally (the bytes are their UTF-8
  encoding), never `\uXXXX`-escaped;
- string escaping as in RFC 8785 (JCS): `"` and `\` escaped, control
  characters below U+0020 escaped using the two-character short forms
  (`\b \t \n \f \r`) where they exist and `\u00XX` otherwise, everything
  else literal;
- no `NaN`/`Infinity` (unrepresentable — see the float rule).

> **Normative — key ordering is by Unicode code point, NOT by UTF-16 code
> units.** This deviates from RFC 8785 (JCS), which sorts object keys by
> UTF-16 code units, for keys containing characters above U+FFFF: U+FF61
> (`｡`) sorts *before* U+10000 by code point but *after* it by UTF-16 units
> (U+10000 encodes as the surrogate pair D800 DC00). **A JCS library cannot
> be used as-is for canonicalization — only its string-escaping rules
> apply.** Pinned fixture (both SDK test suites must reproduce it):
>
> ```
> input:     {"｡": 1, "𐀀": 2}        (keys U+FF61 and U+10000)
> canonical: {"｡":1,"𐀀":2}           (the U+FF61 key sorts FIRST)
> ```

Permitted value types — **only** these:

| Type | Rule |
|---|---|
| `null` | as-is |
| `true` / `false` | as-is |
| integer | only if \|n\| < 2^53 (exact in IEEE-754 doubles); larger magnitudes are **rejected** — carry them as strings |
| string | any Unicode string containing **no surrogate code points** (U+D800–U+DFFF): lone surrogates have no UTF-8 encoding (and JS strings hold them freely), so they are **rejected** — in values and in object keys |
| array | of permitted values |
| object | string keys only (surrogate-free), permitted values |

**Floats are rejected at serialization time, everywhere.** Money is
`{"amount": "<decimal-string>", "currency": "<ISO-4217>"}` — never a JSON
float (PLAN.md section 3.2): float formatting differs across languages and
would fork keys (and, from P2.2, audit hashes) between SDKs.

Decimal-string normalization for Money amounts (Python:
`airlock.decimal_string`): plain fixed-point notation (never scientific), no
trailing fractional zeros (`12.50` → `"12.5"`), zero is always `"0"`, a
leading `-` only for negative values, no `+` and no separators.

Timestamps inside an `arg_map` are **strings** in RFC 3339 UTC form with
microsecond precision and a `Z` suffix: `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
Native datetime values are rejected — render them first.

## 4. Integrator key overrides

An integrator-supplied key (the `key=` override on `@guard`) replaces the
derivation, but is **namespaced by the SDK before touching the ledger**:

```
ledger_key = "{action_type}:{user_key}"
```

Plain string concatenation with a colon — not hashed — so overrides can
never collide across action types, and are visually distinguishable from
derived keys (which are exactly 64 lowercase hex characters).

**`action_type` must not contain `:`.** The first colon in a namespaced
ledger key is the action_type/user_key delimiter; for the encoding to be
injective it must be unambiguous, so an `action_type` containing a colon is
**rejected** (otherwise `("payment:refund", "order-9")` and
`("payment", "refund:order-9")` would collide on one ledger key and the
second action would silently receive the first action's outcome).
`user_key` may contain colons freely: it is the final segment.

## 5. Collide-and-dedupe (the documented caveat)

Two *intentionally* identical actions — same action type, same canonical
`arg_map` — collide by default: the second call dedupes against the first's
ledger row and returns its outcome. **This is the correct default** under the
prime directive (never cause a side effect more than once): collide-and-dedupe
beats double-commit. If two genuinely distinct actions can carry identical
arguments, carry a natural unique id (order id, invoice id, request id) in
the args — or override the key (§4).

`key_ignore` is the inverse hazard: a *volatile* argument (timestamp, trace
id) left in the map forks the key on every retry and re-executes the effect.
Exclude volatile arguments via `key_ignore`; the Python SDK rejects
`key_ignore` names the function cannot accept, so typos fail loudly instead
of silently keying on the volatile value.

## 6. Downstream passthrough

The derived ledger key is also the downstream idempotency key (one key, two
layers of dedup — PLAN.md section 3.4): when an effect declares `key_param`,
the SDK passes `map_key(ledger_key)` (or the ledger key verbatim when no
`map_key` is configured) to the downstream call, and persists **exactly that
post-`map_key` value** in `commit_records.downstream_key`. The stored value
is byte-for-byte what was sent downstream; verification probes and the
reconciler depend on that equality.
