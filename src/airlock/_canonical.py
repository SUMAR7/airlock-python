"""Canonical JSON — the ``airlock-canon-1`` rule (PLAN.md section 5.2).

This module is the ONE implementation of canonicalization in the SDK. Key
derivation (``airlock.idempotency``, P1.2) uses it today, and **P2.2's
hash-chained audit envelope hashing imports THIS module** — the standalone
``/contracts/canonical-json.md`` contract formally lands there. Until then,
the rules are embedded in ``/contracts/idempotency.md``, which depends on
them. Never fork or "locally tweak" these rules: two canonicalizations is a
silent contract break (PLAN.md section 10, point 5).

The ``airlock-canon-1`` rule
============================

``canonical_json(value)`` is exactly::

    json.dumps(value, sort_keys=True, separators=(",", ":"),
               ensure_ascii=False, allow_nan=False)

encoded as UTF-8 (``canonical_bytes``), over a *restricted* value domain:

- **Permitted value types, only these:** ``null``, ``bool``,
  ``int`` with ``|n| < 2**53``, ``str``, ``list``, ``dict`` with ``str`` keys.
- **Floats are rejected at emit time** — see :func:`decimal_string` and the
  Money rule below. ``allow_nan=False`` is belt-and-braces; the type check
  fires first.
- **Ints beyond ``2**53 - 1`` in magnitude are rejected**: they are not
  exactly representable as IEEE-754 doubles, so a JS/TS consumer would
  silently corrupt them and break cross-language key parity.
- **Strings must be surrogate-free Unicode**: code points in U+D800-U+DFFF
  (lone surrogates) have no UTF-8 encoding and are rejected — in values AND
  in object keys.
- Object keys sort by **Unicode code point** (Python ``str`` ordering — what
  ``sort_keys=True`` does), **NOT by UTF-16 code units**. This deviates from
  RFC 8785 (JCS) for keys containing characters above U+FFFF: e.g. U+FF61
  sorts *before* U+10000 by code point but *after* it by UTF-16 units (U+10000
  encodes as the surrogate pair D800 DC00). An off-the-shelf JCS canonicalizer
  therefore CANNOT be used as-is — only its string-escaping rules apply.
  Non-ASCII characters are emitted literally (``ensure_ascii=False``), so the
  bytes are their UTF-8 encoding.

Money rule
----------

Money is ``{"amount": "<decimal-string>", "currency": "<ISO-4217>"}`` —
**never a JSON float, anywhere** (PLAN.md section 3.2). Floats cannot
represent decimal amounts exactly, and their formatting differs across
languages, which would fork idempotency keys and audit hashes between SDKs.
Use :func:`decimal_string` to render a :class:`decimal.Decimal` amount.

Timestamp convention
--------------------

Timestamps inside canonical JSON are **strings** in RFC 3339 UTC form with
microsecond precision and a ``Z`` suffix: ``YYYY-MM-DDTHH:MM:SS.ffffffZ``
(e.g. ``2026-07-03T09:30:00.000000Z``). ``datetime`` objects themselves are
rejected — render them before canonicalizing, from a UTC instant.
"""

from __future__ import annotations

import json
from datetime import date, datetime, time
from decimal import Decimal

from airlock.errors import CanonicalizationError

__all__ = [
    "CANON_VERSION",
    "MAX_CANONICAL_INT",
    "canonical_bytes",
    "canonical_json",
    "decimal_string",
]

#: Name of the canonicalization rule this module implements (frozen).
CANON_VERSION = "airlock-canon-1"

#: Largest integer magnitude permitted: 2**53 - 1, the largest integer such
#: that it and all smaller magnitudes are exactly representable as IEEE-754
#: doubles ("|n| < 2**53", PLAN.md section 5.2).
MAX_CANONICAL_INT = 2**53 - 1

_MONEY_HINT = (
    "floats are forbidden in canonical JSON (airlock-canon-1): money is "
    '{"amount": "<decimal-string>", "currency": "<ISO-4217>"} — never a JSON '
    "float, anywhere (PLAN.md section 3.2). Render Decimal amounts with "
    "airlock.decimal_string()."
)


def canonical_json(value: object) -> str:
    """Serialize ``value`` per ``airlock-canon-1`` (see module docstring).

    Raises:
        CanonicalizationError: for any value outside the permitted domain —
            floats (with a pointer at the Money rule), out-of-range ints,
            non-``str`` dict keys, ``Decimal``/``datetime``/tuples/sets/
            arbitrary objects. The message names the offending path.
    """
    _reject_forbidden(value, "$")
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(value: object) -> bytes:
    """UTF-8 encoding of :func:`canonical_json` — the hashing input form.

    Key derivation hashes these bytes today; P2.2's audit ``row_hash`` will
    hash them too (``SHA256(prev_hash || canonical_bytes(envelope))``).
    """
    return canonical_json(value).encode("utf-8")


def decimal_string(amount: Decimal) -> str:
    """Render a ``Decimal`` as the canonical decimal string for Money amounts.

    Normalization (deterministic — equal Decimals always render identically,
    **independent of the ambient decimal context**: the rendering is purely
    textual and never rounds, so no thread-local ``getcontext().prec`` setting
    can change the output or silently truncate an amount):

    - plain fixed-point notation, never scientific (``1E+2`` -> ``"100"``);
    - no trailing fractional zeros (``12.50`` -> ``"12.5"``); trailing-zero
      *scale* is presentation, and letting it leak would fork keys between
      ``Decimal("12.5")`` and ``Decimal("12.50")``;
    - zero is always ``"0"`` (never ``-0`` or ``0.00``);
    - a leading ``-`` for negative values; no ``+``, no thousands separators.

    Raises:
        CanonicalizationError: for non-finite values (NaN/Infinity) or
            non-``Decimal`` input. Floats are rejected on principle — if you
            have a float amount you have already lost precision; fix the
            producer.
    """
    if not isinstance(amount, Decimal):
        raise CanonicalizationError(
            f"decimal_string() takes a decimal.Decimal, got {type(amount).__name__}. " + _MONEY_HINT
        )
    if not amount.is_finite():
        raise CanonicalizationError(
            f"cannot canonicalize non-finite Decimal {amount!r} as a Money amount"
        )
    if amount == 0:
        return "0"
    # format(..., "f") is exact and context-free (Decimal.__format__ without a
    # precision never consults the thread-local context and never rounds) —
    # unlike Decimal.normalize(), which rounds to the AMBIENT context precision
    # and would render the same amount differently across processes/threads,
    # forking idempotency keys (the double-commit ADR-1 exists to prevent).
    rendered = format(amount, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _reject_surrogates(value: str, path: str) -> None:
    """Reject strings containing surrogate code points (U+D800-U+DFFF).

    Lone surrogates have no UTF-8 encoding, so ``canonical_bytes`` would be
    undefined for them (Python raises a raw ``UnicodeEncodeError`` outside the
    ``CanonicalizationError`` contract; JS strings hold lone surrogates
    freely, so a TS SDK would silently produce *different* bytes). The
    canonical string domain is therefore surrogate-free Unicode — see
    ``/contracts/idempotency.md`` §3.
    """
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise CanonicalizationError(
            f"string at {path} contains surrogate code point(s) "
            "(U+D800-U+DFFF), which have no UTF-8 encoding — canonical JSON "
            "strings must be surrogate-free Unicode (airlock-canon-1). "
            "Surrogateescape'd values (e.g. undecodable filenames from os "
            "APIs) must be re-encoded before keying."
        ) from None


def _reject_forbidden(value: object, path: str) -> None:
    """Depth-first validation of the airlock-canon-1 value domain."""
    if value is None or type(value) is bool:  # bool BEFORE int: bool subclasses int
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"float at {path}: {_MONEY_HINT}")
    if isinstance(value, int):
        if abs(value) > MAX_CANONICAL_INT:
            raise CanonicalizationError(
                f"int at {path} exceeds the safe-integer bound |n| < 2**53 "
                f"(got {value}): larger ints silently lose precision in "
                "IEEE-754 consumers and would break cross-language key parity. "
                "Carry it as a string."
            )
        return
    if isinstance(value, str):
        _reject_surrogates(value, path)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_forbidden(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if type(key) is not str:
                raise CanonicalizationError(
                    f"non-str dict key at {path}: {key!r} "
                    f"({type(key).__name__}) — canonical JSON object keys must "
                    "be plain str"
                )
            _reject_surrogates(key, f"{path} (object key {key!r})")
            _reject_forbidden(item, f"{path}.{key}")
        return
    if isinstance(value, Decimal):
        raise CanonicalizationError(
            f"Decimal at {path}: canonical JSON has no Decimal type — render "
            "Money amounts with airlock.decimal_string() and carry the string."
        )
    if isinstance(value, (datetime, date, time)):
        raise CanonicalizationError(
            f"{type(value).__name__} at {path}: canonical JSON has no datetime "
            "type — render timestamps as RFC 3339 UTC strings with microseconds "
            "('YYYY-MM-DDTHH:MM:SS.ffffffZ') before canonicalizing."
        )
    raise CanonicalizationError(
        f"{type(value).__name__} at {path} is not a permitted canonical JSON "
        "value (airlock-canon-1 permits only null/bool/int/str/list/dict)"
    )
