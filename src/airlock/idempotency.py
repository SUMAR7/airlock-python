"""Idempotency-key derivation (PLAN.md section 3.4).

The language-neutral contract for everything in this module is frozen in
``/contracts/idempotency.md`` — code and contract define the byte-level
formula identically; a drift between them is a contract break, not a bug fix.

The formula::

    key = SHA-256( UTF8("airlock/v1") || UTF8(action_type)
                   || canonical_bytes(arg_map) ).hexdigest()

is specified over an **explicit canonical arg_map** — a JSON object mapping
argument names to values — NOT over Python binding semantics, so a future TS
SDK can achieve key parity (PLAN.md section 9). Python constructs the arg_map
with :func:`build_arg_map` (signature binding with defaults applied, so
``f(1)`` and ``f(x=1)`` derive the same key); TS will use a single
options-object. Cross-language parity requires identical arg_map contents.

The collide-and-dedupe caveat (documented, deliberate): two *intentionally*
identical actions — same action type, same canonical arg_map — collide by
default and the second is deduped against the first's ledger row. That is the
correct default under the prime directive (collide-and-dedupe beats
double-commit): carry a natural unique id (order id, invoice id, request id)
in the args, or override the key per call — overrides are namespaced with
:func:`namespace_user_key` so they can never collide across action types.
"""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Callable, Mapping

from airlock._canonical import canonical_bytes

__all__ = [
    "KEY_DOMAIN",
    "build_arg_map",
    "derive_key",
    "namespace_user_key",
]

#: Domain-separation prefix for derived keys (frozen; any change to the
#: derivation rule bumps this string, never mutates it in place).
KEY_DOMAIN = b"airlock/v1"


def derive_key(action_type: str, arg_map: Mapping[str, object]) -> str:
    """Derive the deterministic idempotency key for one action (ADR-1).

    The SHA-256 input is the exact concatenation of three byte strings, in
    this order, with **no separators and no length prefixes** (identical
    wording in ``/contracts/idempotency.md``):

    1. the 10 ASCII bytes ``airlock/v1`` (:data:`KEY_DOMAIN`),
    2. the UTF-8 encoding of ``action_type``,
    3. the UTF-8 canonical-JSON encoding of ``arg_map`` per ``airlock-canon-1``
       (:func:`airlock._canonical.canonical_bytes` — always starts with ``{``).

    The key is the lowercase hex digest (64 chars).

    Args:
        action_type: stable, non-empty action identifier (e.g.
            ``"refund.create"``).
        arg_map: the explicit canonical argument map — build it with
            :func:`build_arg_map`, or supply it directly (that is exactly what
            a non-Python SDK does).

    Raises:
        ValueError: empty ``action_type``.
        CanonicalizationError: ``arg_map`` contains values outside the
            ``airlock-canon-1`` domain (floats, over-bound ints, ...).
    """
    if not action_type:
        raise ValueError("action_type must be a non-empty string")
    hasher = hashlib.sha256()
    hasher.update(KEY_DOMAIN)
    hasher.update(action_type.encode("utf-8"))
    hasher.update(canonical_bytes(dict(arg_map)))
    return hasher.hexdigest()


def build_arg_map(
    fn: Callable[..., object],
    args: tuple[object, ...],
    kwargs: Mapping[str, object],
    *,
    key_ignore: tuple[str, ...] = (),
    key_param: str | None = None,
) -> dict[str, object]:
    """Build the canonical arg_map for a call to ``fn`` (PLAN.md section 3.4).

    Binds ``args``/``kwargs`` against ``inspect.signature(fn)`` and applies
    defaults, so *how* an argument was passed never forks the key: ``f(1)``,
    ``f(x=1)``, and ``f(1, y=<the default>)`` all produce the same map.

    Normalization into the (language-neutral) map:

    - every named parameter appears under its name, defaults included;
    - a ``*args`` parameter appears under its own name as a JSON **list**
      (empty list when nothing extra was passed);
    - ``**kwargs`` entries are merged into the **top level** of the map —
      that is the shape a TS options-object produces, and a valid Python call
      can never pass the same name both ways;
    - ``key_ignore`` names and ``key_param`` are removed — ``key_param`` is
      the kwarg that will *receive* the derived key (``Effect.key_param``),
      so it can never feed back into the derivation.

    Args:
        fn: the function whose call is being keyed.
        args: positional arguments of the call.
        kwargs: keyword arguments of the call.
        key_ignore: volatile argument names excluded from the key (e.g.
            ``("request_ts",)``). Each name must be a parameter of ``fn`` —
            unless ``fn`` accepts ``**kwargs``, in which case unknown names
            are allowed and removed from the extras when present. A typo here
            would silently leave a volatile value in the key, forking the key
            on every retry — the exact double-commit this library exists to
            prevent — so unknown names are an error.
        key_param: name of the downstream-key kwarg to exclude (see
            ``Effect.key_param``), or ``None``.

    Raises:
        ValueError: a ``key_ignore``/``key_param`` name that ``fn`` cannot
            accept, or a ``**kwargs`` entry that collides with another map
            entry.
        TypeError: ``args``/``kwargs`` do not bind to ``fn``'s signature.
    """
    signature = inspect.signature(fn)
    parameters = signature.parameters
    has_var_keyword = any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()
    )

    excluded = set(key_ignore)
    if key_param is not None:
        excluded.add(key_param)
    unknown = excluded - parameters.keys()
    if unknown and not has_var_keyword:
        raise ValueError(
            f"key_ignore/key_param name(s) {sorted(unknown)!r} are not parameters of "
            f"{getattr(fn, '__qualname__', fn)!r} and it accepts no **kwargs — a typo here "
            "would leave a volatile value in the key derivation"
        )

    bound = signature.bind(*args, **dict(kwargs))
    bound.apply_defaults()

    arg_map: dict[str, object] = {}
    for name, value in bound.arguments.items():
        if name in excluded:
            continue
        kind = parameters[name].kind
        if kind is inspect.Parameter.VAR_POSITIONAL:
            arg_map[name] = list(value)
        elif kind is inspect.Parameter.VAR_KEYWORD:
            for extra_name, extra_value in value.items():
                if extra_name in excluded:
                    continue
                if extra_name in arg_map:
                    raise ValueError(
                        f"**kwargs entry {extra_name!r} collides with the map entry for "
                        f"parameter {extra_name!r} — rename one; a silent overwrite would "
                        "make two different calls derive the same key"
                    )
                arg_map[extra_name] = extra_value
        else:
            arg_map[name] = value
    return arg_map


def namespace_user_key(action_type: str, user_key: str) -> str:
    """Namespace an integrator-supplied key override (PLAN.md section 3.3).

    The ledger key for an override is the plain string
    ``"{action_type}:{user_key}"`` — NOT hashed — so overrides can never
    collide across action types, and an operator reading the ledger can see
    at a glance which rows carry custom keys (derived keys are 64 lowercase
    hex chars; namespaced overrides contain the action type and a colon).

    Raises:
        ValueError: empty ``action_type`` or ``user_key``.
    """
    if not action_type:
        raise ValueError("action_type must be a non-empty string")
    if not user_key:
        raise ValueError("user_key must be a non-empty string")
    return f"{action_type}:{user_key}"
