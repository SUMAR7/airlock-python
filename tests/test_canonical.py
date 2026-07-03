"""airlock-canon-1 semantics (PLAN.md section 5.2 / contracts/idempotency.md §3).

Pure unit tests — no database. The canonical form is a frozen contract: these
tests pin exact output strings and bytes, not just round-trip behavior.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Context, Decimal, localcontext

import pytest

from airlock._canonical import (
    CANON_VERSION,
    MAX_CANONICAL_INT,
    canonical_bytes,
    canonical_json,
    decimal_string,
)
from airlock.errors import CanonicalizationError


def test_canon_version_is_frozen() -> None:
    assert CANON_VERSION == "airlock-canon-1"


def test_sorted_keys_compact_separators() -> None:
    value = {"b": 1, "a": [True, None, "x"], "c": {"z": 0, "y": ""}}
    assert canonical_json(value) == '{"a":[true,null,"x"],"b":1,"c":{"y":"","z":0}}'


def test_key_order_never_affects_output() -> None:
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})


def test_non_ascii_is_emitted_literally_as_utf8() -> None:
    """ensure_ascii=False: the bytes are the UTF-8 encoding, never \\uXXXX."""
    value = {"café": "übergrößen", "emoji": "🚀", "cjk": "取引"}
    encoded = canonical_bytes(value)
    assert "\\u" not in canonical_json(value)
    assert "🚀".encode() in encoded
    assert encoded == canonical_json(value).encode("utf-8")


def test_control_characters_use_short_escapes() -> None:
    """RFC 8785-compatible string escaping (contract §3)."""
    assert canonical_json({"s": 'a"b\\c\nd\te'}) == '{"s":"a\\"b\\\\c\\nd\\te"}'
    assert canonical_json({"s": "\x01"}) == '{"s":"\\u0001"}'


def test_float_rejected_pointing_at_money_rule() -> None:
    with pytest.raises(CanonicalizationError, match="decimal-string"):
        canonical_json({"amount": 12.5})


def test_nested_float_rejected_with_path() -> None:
    with pytest.raises(CanonicalizationError, match=r"\$\.order\.lines\[1\]"):
        canonical_json({"order": {"lines": [{"amount": "1"}, 0.1]}})


def test_int_at_bound_accepted_and_exact() -> None:
    assert canonical_json({"n": MAX_CANONICAL_INT}) == f'{{"n":{2**53 - 1}}}'
    assert canonical_json({"n": -MAX_CANONICAL_INT}) == f'{{"n":-{2**53 - 1}}}'


@pytest.mark.parametrize("n", [2**53, -(2**53), 2**64])
def test_int_beyond_bound_rejected(n: int) -> None:
    with pytest.raises(CanonicalizationError, match="2\\*\\*53"):
        canonical_json({"n": n})


def test_bool_is_not_an_int() -> None:
    """bool subclasses int in Python; canonical JSON keeps them distinct."""
    assert canonical_json({"flag": True}) == '{"flag":true}'
    assert canonical_json({"flag": 1}) == '{"flag":1}'
    assert canonical_json({"flag": True}) != canonical_json({"flag": 1})


def test_non_str_dict_key_rejected() -> None:
    with pytest.raises(CanonicalizationError, match="non-str dict key"):
        canonical_json({1: "a"})


def test_lone_surrogate_in_string_value_rejected() -> None:
    """Lone surrogates (U+D800-U+DFFF) have no UTF-8 encoding: the canonical
    string domain is surrogate-free Unicode (contract §3), and the rejection
    is the contract error naming the path — never a raw UnicodeEncodeError."""
    with pytest.raises(CanonicalizationError, match=r"surrogate.*U\+D800"):
        canonical_json({"path": "backup\ud800file"})
    with pytest.raises(CanonicalizationError, match=r"\$\.nested\.name"):
        canonical_json({"nested": {"name": "\udfff"}})


def test_lone_surrogate_in_object_key_rejected() -> None:
    with pytest.raises(CanonicalizationError, match="surrogate"):
        canonical_json({"\udc80": 1})


def test_surrogateescaped_os_value_rejected_as_contract_error() -> None:
    """The practical trigger: an undecodable filename surrogateescape'd by an
    os API used as an action arg must fail with the declared error surface,
    not escape canonical_bytes as UnicodeEncodeError."""
    filename = b"caf\xe9.txt".decode("utf-8", "surrogateescape")
    with pytest.raises(CanonicalizationError, match="surrogate"):
        canonical_bytes({"filename": filename})


def test_astral_key_ordering_is_code_point_not_utf16() -> None:
    """Contract §3 normative note: keys sort by Unicode CODE POINT, which
    diverges from RFC 8785 (JCS, UTF-16 code units) for non-BMP keys — U+FF61
    sorts before U+10000 by code point but after it by UTF-16 units. Pinned
    so a future TS SDK cannot satisfy the contract with an off-the-shelf JCS
    canonicalizer and silently fork keys (cross-language double-commit)."""
    assert canonical_json({"｡": 1, "\U00010000": 2}) == '{"｡":1,"\U00010000":2}'
    assert canonical_json({"\U0001d306": 1, "｡": 2}) == '{"｡":2,"\U0001d306":1}'


def test_empty_containers_pinned() -> None:
    assert canonical_json({"a": [], "b": {}}) == '{"a":[],"b":{}}'
    assert canonical_json({}) == "{}"


def test_decimal_rejected_pointing_at_helper() -> None:
    with pytest.raises(CanonicalizationError, match="decimal_string"):
        canonical_json({"amount": Decimal("12.5")})


def test_datetime_rejected_pointing_at_rfc3339() -> None:
    with pytest.raises(CanonicalizationError, match="RFC 3339"):
        canonical_json({"at": datetime(2026, 7, 3, tzinfo=UTC)})


def test_arbitrary_object_rejected() -> None:
    with pytest.raises(CanonicalizationError, match="not a permitted"):
        canonical_json({"x": object()})


def test_tuple_and_set_rejected() -> None:
    with pytest.raises(CanonicalizationError, match="tuple"):
        canonical_json({"x": (1, 2)})
    with pytest.raises(CanonicalizationError, match="set"):
        canonical_json({"x": {1, 2}})


def test_nan_and_infinity_have_no_path_in() -> None:
    """allow_nan=False is belt-and-braces: the float type check fires first."""
    for pathological in (float("nan"), float("inf")):
        with pytest.raises(CanonicalizationError, match="float"):
            canonical_json({"x": pathological})


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("12.50", "12.5"),  # trailing-zero scale is presentation, not identity
        ("12.5", "12.5"),
        ("1E+2", "100"),  # never scientific notation
        ("100", "100"),
        ("0.000001", "0.000001"),
        ("0", "0"),
        ("0.00", "0"),
        ("-0", "0"),  # zero is always "0"
        ("-0.00", "0"),
        ("-12.50", "-12.5"),
        ("1234567.89", "1234567.89"),
    ],
)
def test_decimal_string_normalization(raw: str, expected: str) -> None:
    assert decimal_string(Decimal(raw)) == expected


def test_equal_decimals_always_render_identically() -> None:
    assert decimal_string(Decimal("12.50")) == decimal_string(Decimal("12.5"))
    assert decimal_string(Decimal("1E+2")) == decimal_string(Decimal("100.00"))


def test_decimal_string_is_context_independent() -> None:
    """The rendering must never consult the thread-local decimal context: a
    library that lowers getcontext().prec (common in financial code) must not
    change the canonical string — a context-dependent rendering forks
    idempotency keys across processes, the exact double-commit ADR-1 exists
    to prevent."""
    amount = Decimal("1234567.891")
    with localcontext(Context(prec=5)):
        squeezed = decimal_string(amount)
    assert squeezed == decimal_string(amount) == "1234567.891"


def test_decimal_string_never_rounds_beyond_default_precision() -> None:
    """30 significant digits exceed even the DEFAULT context precision (28):
    the amount must render exactly, never silently round to '1E+28'-ish."""
    amount = Decimal("10000000000000000000000000000.5")
    assert decimal_string(amount) == "10000000000000000000000000000.5"
    with localcontext(Context(prec=5)):
        assert decimal_string(amount) == "10000000000000000000000000000.5"


@pytest.mark.parametrize("raw", ["NaN", "Infinity", "-Infinity"])
def test_decimal_string_rejects_non_finite(raw: str) -> None:
    with pytest.raises(CanonicalizationError, match="non-finite"):
        decimal_string(Decimal(raw))


def test_decimal_string_rejects_floats_on_principle() -> None:
    with pytest.raises(CanonicalizationError, match=r"decimal\.Decimal"):
        decimal_string(12.5)  # type: ignore[arg-type]
