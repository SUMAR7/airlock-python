"""HMAC request signing — the ``airlock-v1`` scheme (PLAN.md 6.2, /contracts/signing.md).

This module is the ONE Python implementation of the signing spec. Every wire
call in either direction (SDK -> cloud on ``POST /api/v1/approvals`` and
``GET /api/v1/approvals/{id}``; cloud -> customer on the ``approval.decided``
webhook) is signed and verified through exactly these functions. The hosted
control plane (``airlock-cloud``, Ruby) reimplements the SAME document, and
BOTH sides are pinned to the reference vectors in
``/contracts/examples/signing_vectors.json`` — the cross-language golden values.
Any behavioural change here that is not mirrored in signing.md + the vectors is
a silent contract break (the same rule the canonical-JSON module lives under).

Design notes that make cross-language parity possible:

- **The signed string is built from RAW bytes, before any JSON parsing.** The
  body term is ``sha256_hex(raw_request_body_bytes)``; an empty body hashes the
  empty string. Neither side canonicalizes the JSON — signing is over the exact
  bytes on the wire, so a proxy that reserializes the body breaks the signature
  (intended: the bytes a human approved are the bytes that were signed).
- **The HMAC key is the secret token's UTF-8 bytes**, verbatim — the full
  ``sk_live_…`` string, not a base64/hex decode of it. This is the least
  ambiguous choice across languages (Ruby ``OpenSSL::HMAC.hexdigest`` and
  Python ``hmac.new`` both take the key as bytes with no decoding step).
- **The timestamp is embedded as the exact header string.** Verification
  rebuilds the canonical string from the header's raw timestamp text and only
  parses it to an int for the replay-window check, so no int normalization
  (leading zeros, ``+``) can desync the two sides.

Import-light: stdlib ``hmac`` / ``hashlib`` / ``time`` only. No httpx here
(P3.4 adds the transport that calls this); nothing in this module pulls a heavy
dependency, so the base-import guard stays green.
"""

from __future__ import annotations

import hashlib
import hmac
import time as _time
from collections.abc import Mapping

__all__ = [
    "CANONICAL_PREFIX",
    "HEADER_KEY",
    "HEADER_SIGNATURE",
    "HEADER_TIMESTAMP",
    "REPLAY_WINDOW_SECONDS",
    "SIGNATURE_VERSION",
    "build_canonical_string",
    "empty_body_sha256_hex",
    "parse_signature_header",
    "sha256_hex",
    "sign",
    "signature_header",
    "verify",
]

#: The domain-separation prefix and first line of every signed string. Bumping
#: this (a breaking change to the signed-string layout) is what makes the whole
#: scheme versionable independently of the API's ``/api/v1/`` path version.
CANONICAL_PREFIX = "airlock-v1"

#: The signature-scheme tag carried inside the ``Airlock-Signature`` header
#: (``v1=<hex>``). A future HMAC construction ships as ``v2=…`` ALONGSIDE
#: ``v1=…`` so a rolling deploy can verify either — the header can carry
#: multiple space/comma-separated schemes.
SIGNATURE_VERSION = "v1"

#: Reject a request whose timestamp is more than this many seconds from now, in
#: either direction (clock skew or replay). No nonce store is needed: every
#: endpoint is idempotent by construction (create is keyed on the SDK-minted
#: ``approval_ref``; GET is read-only; the webhook receiver dedupes through
#: ``apply_decision``), so a replay inside the window is a harmless no-op.
REPLAY_WINDOW_SECONDS = 300

HEADER_KEY = "Airlock-Key"
HEADER_TIMESTAMP = "Airlock-Timestamp"
HEADER_SIGNATURE = "Airlock-Signature"

_EMPTY_BODY_SHA256_HEX = hashlib.sha256(b"").hexdigest()


def sha256_hex(raw_body: bytes) -> str:
    """Lowercase hex SHA-256 of the RAW request-body bytes (empty ⇒ empty hash).

    This is the body term of the canonical string. It is computed on the exact
    bytes received/sent — never on a re-encoded or parsed form.
    """
    return hashlib.sha256(raw_body).hexdigest()


def empty_body_sha256_hex() -> str:
    """The SHA-256 hex of the empty string — the body term for GET (no body)."""
    return _EMPTY_BODY_SHA256_HEX


def build_canonical_string(
    *,
    timestamp: int | str,
    method: str,
    path_with_query: str,
    raw_body: bytes,
) -> str:
    """Assemble the exact string that is HMAC'd (/contracts/signing.md §2).

    The layout is five LF-separated (0x0A) fields::

        airlock-v1\\n{unix_ts}\\n{METHOD}\\n{path_with_query}\\n{sha256_hex(raw_body)}

    ``method`` is upper-cased (canonical spelling); ``timestamp`` is stringified
    verbatim (no normalization); ``path_with_query`` is the request target
    exactly as sent — path plus ``?query`` if present, no host, no fragment.
    """
    body_hash = sha256_hex(raw_body)
    return "\n".join(
        (
            CANONICAL_PREFIX,
            str(timestamp),
            method.upper(),
            path_with_query,
            body_hash,
        )
    )


def _hmac_hex(secret: str, canonical_string: str) -> str:
    """Lowercase-hex HMAC-SHA256 over the canonical string with the secret bytes."""
    return hmac.new(
        secret.encode("utf-8"),
        canonical_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def signature_header(mac_hex: str) -> str:
    """Wrap a raw hex MAC as the ``Airlock-Signature`` value (``v1=<hex>``)."""
    return f"{SIGNATURE_VERSION}={mac_hex}"


def sign(
    secret: str,
    *,
    timestamp: int | str,
    method: str,
    path_with_query: str,
    raw_body: bytes,
) -> str:
    """Produce the ``Airlock-Signature`` header value for a request.

    Returns ``v1=<lowercase hex HMAC-SHA256(secret, canonical_string)>``. The
    caller sets ``Airlock-Key`` (the ``ak_live_…`` key id) and
    ``Airlock-Timestamp`` (the SAME ``timestamp`` passed here) alongside it.
    """
    canonical_string = build_canonical_string(
        timestamp=timestamp,
        method=method,
        path_with_query=path_with_query,
        raw_body=raw_body,
    )
    return signature_header(_hmac_hex(secret, canonical_string))


def parse_signature_header(value: str) -> dict[str, str]:
    """Parse an ``Airlock-Signature`` header into ``{scheme: hex}``.

    Accepts one or more space/comma-separated ``<scheme>=<hex>`` tokens so the
    header can advertise multiple signature schemes during a rotation. Tokens
    without an ``=`` are ignored. Returns an empty mapping for empty/garbage
    input — the caller decides that a missing ``v1`` scheme means "unsigned".
    """
    schemes: dict[str, str] = {}
    for token in value.replace(",", " ").split():
        scheme, sep, mac = token.partition("=")
        if sep and scheme and mac:
            schemes.setdefault(scheme, mac)
    return schemes


def verify(
    secret: str,
    *,
    headers: Mapping[str, str],
    method: str,
    path_with_query: str,
    raw_body: bytes,
    now: float | None = None,
    max_skew_seconds: int = REPLAY_WINDOW_SECONDS,
) -> bool:
    """Verify a signed request, constant-time, on the RAW body before parsing.

    Returns ``True`` iff:

    1. an ``Airlock-Timestamp`` header is present and parses as an integer;
    2. it is within ``max_skew_seconds`` of ``now`` (default: the real clock) —
       the replay/skew window;
    3. an ``Airlock-Signature`` header carries a ``v1=<hex>`` token; and
    4. that hex equals HMAC-SHA256(secret, canonical_string) under a
       constant-time compare (``hmac.compare_digest``).

    The canonical string is rebuilt from the timestamp header's RAW text (not a
    reparsed int) so signer and verifier agree byte-for-byte. Verification
    happens on ``raw_body`` — the exact received bytes — before any JSON parse,
    so a malformed or oversized body is rejected by signature, not by the
    parser. Any missing/garbled header returns ``False`` (never raises).

    ``now`` is injectable (unix seconds) so replay-window tests are deterministic
    without touching the wall clock (PLAN.md 7 — no sleeping, no real time).
    """
    ts_raw = _get_header(headers, HEADER_TIMESTAMP)
    sig_raw = _get_header(headers, HEADER_SIGNATURE)
    if ts_raw is None or sig_raw is None:
        return False

    try:
        ts_int = int(ts_raw.strip())
    except (ValueError, TypeError):
        return False

    reference = _time.time() if now is None else now
    if abs(reference - ts_int) > max_skew_seconds:
        return False

    provided = parse_signature_header(sig_raw).get(SIGNATURE_VERSION)
    if provided is None:
        return False

    canonical_string = build_canonical_string(
        timestamp=ts_raw.strip(),
        method=method,
        path_with_query=path_with_query,
        raw_body=raw_body,
    )
    expected = _hmac_hex(secret, canonical_string)
    return hmac.compare_digest(expected, provided)


def _get_header(headers: Mapping[str, str], name: str) -> str | None:
    """Case-insensitive header lookup (HTTP header names are case-insensitive)."""
    value = headers.get(name)
    if value is not None:
        return value
    lowered = name.lower()
    for key, val in headers.items():
        if key.lower() == lowered:
            return val
    return None
