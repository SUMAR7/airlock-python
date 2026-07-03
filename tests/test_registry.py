"""The action registry shared by commit_once (inline) and the reconciler.

The registry is the lookup from ``action_type`` to the ``effect`` / ``execute``
/ ``preconditions`` a reconciler needs to reconstruct a call from a bare ledger
row. Re-registering the same action_type with a DIFFERENT registration must
raise — a silent overwrite would make the reconciler recover with the wrong
recovery logic.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import JsonValue

from airlock.effects import Effect
from airlock.registry import Registration, Registry, register, registry


def _execute(downstream_key: str | None, **_: Any) -> JsonValue:
    return {"ok": True}


def test_register_and_get_roundtrips() -> None:
    reg = Registry()
    effect = Effect(verify=lambda **_: None)  # type: ignore[arg-type]
    preconditions = lambda **_: True  # noqa: E731
    reg.register("act.one", effect, _execute, preconditions)
    got = reg.get("act.one")
    assert got == Registration(effect=effect, execute=_execute, preconditions=preconditions)
    assert "act.one" in reg
    assert len(reg) == 1


def test_get_unregistered_returns_none() -> None:
    reg = Registry()
    assert reg.get("nope") is None
    assert "nope" not in reg


def test_reregister_identical_is_a_noop() -> None:
    """A module imported twice re-registers the identical registration — fine."""
    reg = Registry()
    effect = Effect(key_param="idempotency_key")
    reg.register("act.dup", effect, _execute)
    reg.register("act.dup", effect, _execute)  # no raise
    assert len(reg) == 1


def test_reregister_different_raises() -> None:
    """A DIFFERENT registration for the same action_type is refused loudly."""
    reg = Registry()
    reg.register("act.conflict", Effect(key_param="idempotency_key"), _execute)
    with pytest.raises(ValueError, match="already registered with a different"):
        reg.register("act.conflict", Effect(verify=lambda **_: None), _execute)  # type: ignore[arg-type]


def test_empty_action_type_rejected() -> None:
    reg = Registry()
    with pytest.raises(ValueError, match="non-empty"):
        reg.register("", Effect(), _execute)


def test_module_level_register_uses_the_default_registry() -> None:
    """``airlock.registry.register`` populates the process-wide default registry
    — the one @guard (P2.1) and the reconciler CLI use by default."""
    action_type = "act.default-registry-probe"
    assert registry.get(action_type) is None
    try:
        register(action_type, Effect(key_param="idempotency_key"), _execute)
        assert registry.get(action_type) is not None
    finally:
        # keep the process-wide registry clean for other tests
        registry._registrations.pop(action_type, None)
