"""Key derivation (PLAN.md section 3.4 / contracts/idempotency.md).

Pure unit tests plus one spawn-subprocess determinism check — no database.
The formula test computes the expected digest INDEPENDENTLY of the library
(straight from the contract's byte-level definition), so code and contract
can never drift apart silently.
"""

from __future__ import annotations

import hashlib
import multiprocessing
import os
import subprocess
import sys
from decimal import Decimal
from typing import TYPE_CHECKING, Any

import pytest

from airlock._canonical import decimal_string
from airlock.errors import CanonicalizationError
from airlock.idempotency import KEY_DOMAIN, build_arg_map, derive_key, namespace_user_key

if TYPE_CHECKING:
    from multiprocessing.queues import Queue

ACTION = "refund.create"
ARG_MAP = {"invoice": "inv_42", "amount": "12.50", "currency": "EUR"}

#: Payload for the cross-process determinism check: unicode, nesting, ints,
#: bools, null — everything whose hashing could conceivably vary per process.
DETERMINISM_ARG_MAP: dict[str, Any] = {
    "invoice": "inv_42",
    "note": "übergrößen-🚀-取引",
    "amount": "12.50",
    "count": 2**53 - 1,
    "nested": {"z": [1, "два", None], "a": {"deep": True}},
}


def _refund(invoice: str, amount: str, currency: str = "EUR") -> None: ...


# ---------------------------------------------------------------------------
# The formula, pinned independently of the implementation
# ---------------------------------------------------------------------------


def test_formula_matches_contract_byte_for_byte() -> None:
    """contracts/idempotency.md §1: SHA-256 over the exact concatenation
    UTF8("airlock/v1") || UTF8(action_type) || canonical_bytes(arg_map),
    no separators, no length prefixes, lowercase hex digest."""
    canonical = '{"amount":"12.50","currency":"EUR","invoice":"inv_42"}'
    expected = hashlib.sha256(
        b"airlock/v1" + ACTION.encode("utf-8") + canonical.encode("utf-8")
    ).hexdigest()
    assert derive_key(ACTION, ARG_MAP) == expected
    assert KEY_DOMAIN == b"airlock/v1"


def test_key_shape_is_64_lowercase_hex() -> None:
    key = derive_key(ACTION, ARG_MAP)
    assert len(key) == 64
    assert key == key.lower()
    assert all(c in "0123456789abcdef" for c in key)


def test_action_type_separates_domains() -> None:
    assert derive_key("refund.create", ARG_MAP) != derive_key("payout.create", ARG_MAP)


def test_empty_action_type_rejected() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        derive_key("", ARG_MAP)


# ---------------------------------------------------------------------------
# build_arg_map: binding equivalence
# ---------------------------------------------------------------------------


def test_positional_keyword_and_default_calls_derive_the_same_key() -> None:
    """f(1) and f(x=1) — and explicitly passing a default — all one key."""
    maps = [
        build_arg_map(_refund, ("inv_42", "12.50"), {}),
        build_arg_map(_refund, ("inv_42",), {"amount": "12.50"}),
        build_arg_map(_refund, (), {"invoice": "inv_42", "amount": "12.50"}),
        build_arg_map(_refund, (), {"amount": "12.50", "invoice": "inv_42"}),
        build_arg_map(_refund, ("inv_42", "12.50", "EUR"), {}),  # default, explicit
        build_arg_map(_refund, ("inv_42", "12.50"), {"currency": "EUR"}),
    ]
    assert all(m == ARG_MAP for m in maps)
    keys = {derive_key(ACTION, m) for m in maps}
    assert len(keys) == 1


def test_different_args_derive_different_keys() -> None:
    base = build_arg_map(_refund, ("inv_42", "12.50"), {})
    other = build_arg_map(_refund, ("inv_42", "12.51"), {})
    assert derive_key(ACTION, base) != derive_key(ACTION, other)


def test_binding_error_propagates() -> None:
    with pytest.raises(TypeError):
        build_arg_map(_refund, (), {"nope": 1})


# ---------------------------------------------------------------------------
# build_arg_map: key_ignore and key_param
# ---------------------------------------------------------------------------


def test_key_ignore_excludes_volatile_args() -> None:
    def fn(invoice: str, request_ts: str) -> None: ...

    first = build_arg_map(
        fn, ("inv_42", "2026-07-03T09:00:00.000000Z"), {}, key_ignore=("request_ts",)
    )
    second = build_arg_map(
        fn, ("inv_42", "2026-07-03T09:00:01.000000Z"), {}, key_ignore=("request_ts",)
    )
    assert first == second == {"invoice": "inv_42"}
    assert derive_key(ACTION, first) == derive_key(ACTION, second)


def test_key_ignore_typo_is_loud() -> None:
    """A typo'd key_ignore would silently key on the volatile value and fork
    the key per retry — the double-commit direction — so it must raise."""
    with pytest.raises(ValueError, match="request_tz"):
        build_arg_map(_refund, ("inv_42", "12.50"), {}, key_ignore=("request_tz",))


def test_key_param_is_excluded_from_the_map() -> None:
    def fn(invoice: str, amount: str, idempotency_key: str | None = None) -> None: ...

    without = build_arg_map(fn, ("inv_42", "12.50"), {}, key_param="idempotency_key")
    with_key = build_arg_map(
        fn, ("inv_42", "12.50"), {"idempotency_key": "k-123"}, key_param="idempotency_key"
    )
    assert without == with_key == {"invoice": "inv_42", "amount": "12.50"}


def test_key_ignore_reaches_into_var_keyword() -> None:
    def fn(invoice: str, **extra: object) -> None: ...

    arg_map = build_arg_map(
        fn, ("inv_42",), {"trace_id": "t-1", "amount": "12.50"}, key_ignore=("trace_id",)
    )
    assert arg_map == {"invoice": "inv_42", "amount": "12.50"}


# ---------------------------------------------------------------------------
# build_arg_map: variadics
# ---------------------------------------------------------------------------


def test_var_positional_becomes_a_list_under_its_name() -> None:
    def fn(first: str, *rest: str) -> None: ...

    assert build_arg_map(fn, ("a", "b", "c"), {}) == {"first": "a", "rest": ["b", "c"]}
    assert build_arg_map(fn, ("a",), {}) == {"first": "a", "rest": []}


def test_var_keyword_merges_into_the_top_level() -> None:
    """The TS options-object shape (contract §2.2): extras live at the top."""

    def fn(invoice: str, **extra: object) -> None: ...

    arg_map = build_arg_map(fn, ("inv_42",), {"amount": "12.50", "region": "eu"})
    assert arg_map == {"invoice": "inv_42", "amount": "12.50", "region": "eu"}


def test_var_keyword_collision_with_var_positional_name_is_loud() -> None:
    def fn(*items: str, **extra: object) -> None: ...

    with pytest.raises(ValueError, match="collides"):
        build_arg_map(fn, ("a", "b"), {"items": "sneaky"})


# ---------------------------------------------------------------------------
# derive_key: canonical-domain enforcement
# ---------------------------------------------------------------------------


def test_float_arg_rejected_at_derivation() -> None:
    with pytest.raises(CanonicalizationError, match="float"):
        derive_key(ACTION, {"amount": 12.5})


def test_out_of_bound_int_rejected_at_derivation() -> None:
    with pytest.raises(CanonicalizationError, match="2\\*\\*53"):
        derive_key(ACTION, {"count": 2**53})


def test_unicode_payloads_derive_stable_keys() -> None:
    def fn(note: str, city: str) -> None: ...

    positional = build_arg_map(fn, ("übergrößen-🚀", "北京"), {})
    keyword = build_arg_map(fn, (), {"city": "北京", "note": "übergrößen-🚀"})
    assert derive_key(ACTION, positional) == derive_key(ACTION, keyword)


def test_decimal_amounts_go_through_the_helper() -> None:
    """Money flow: Decimal -> decimal_string -> stable key; raw Decimal refuses."""
    with pytest.raises(CanonicalizationError, match="decimal_string"):
        derive_key(ACTION, {"amount": Decimal("12.50")})
    a = derive_key(ACTION, {"amount": decimal_string(Decimal("12.50"))})
    b = derive_key(ACTION, {"amount": decimal_string(Decimal("12.5"))})
    c = derive_key(ACTION, {"amount": decimal_string(Decimal("12.51"))})
    assert a == b  # equal Decimals render identically -> one key
    assert a != c


# ---------------------------------------------------------------------------
# Override namespacing
# ---------------------------------------------------------------------------


def test_namespace_user_key_format() -> None:
    assert namespace_user_key("refund.create", "order-77") == "refund.create:order-77"


def test_same_user_key_under_two_action_types_never_collides() -> None:
    ledger_a = namespace_user_key("refund.create", "order-77")
    ledger_b = namespace_user_key("payout.create", "order-77")
    assert ledger_a != ledger_b


def test_namespace_user_key_rejects_empty_parts() -> None:
    with pytest.raises(ValueError, match="action_type"):
        namespace_user_key("", "order-77")
    with pytest.raises(ValueError, match="user_key"):
        namespace_user_key("refund.create", "")


# ---------------------------------------------------------------------------
# Cross-process determinism
# ---------------------------------------------------------------------------


def _derive_in_child(results: Queue[str]) -> None:
    """Spawn target (module-level so the child can import it by name)."""
    results.put(derive_key(ACTION, DETERMINISM_ARG_MAP))


def test_key_is_identical_in_a_spawn_subprocess() -> None:
    """A spawn child (fresh interpreter, fresh random hash seed) derives the
    identical key — any accidental dependence on process state (hash
    randomization, dict order tricks) would fork keys across workers and
    double-execute effects."""
    ctx = multiprocessing.get_context("spawn")
    results: Queue[str] = ctx.Queue()
    process = ctx.Process(target=_derive_in_child, args=(results,), daemon=True)
    process.start()
    try:
        child_key = results.get(timeout=60.0)
    finally:
        process.join(timeout=60.0)
    assert child_key == derive_key(ACTION, DETERMINISM_ARG_MAP)


def test_key_is_independent_of_hash_seed() -> None:
    """Belt-and-braces on the same property: force two DIFFERENT hash seeds
    explicitly and require the identical key from each interpreter."""
    code = (
        f"import sys; sys.path[:0] = {sys.path!r}\n"
        "from tests.test_idempotency import ACTION, DETERMINISM_ARG_MAP\n"
        "from airlock.idempotency import derive_key\n"
        "sys.stdout.write(derive_key(ACTION, DETERMINISM_ARG_MAP))\n"
    )
    keys = set()
    for seed in ("0", "424242"):
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        keys.add(result.stdout)
    assert keys == {derive_key(ACTION, DETERMINISM_ARG_MAP)}
