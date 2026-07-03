"""Effect semantics (ADR-2): guarantee precedence, downstream key derivation.

Pure unit tests — no database.
"""

from __future__ import annotations

import dataclasses

import pytest

from airlock.effects import Effect
from airlock.types import Guarantee, Verification


def _probe(**_: object) -> tuple[Verification, None]:
    return Verification.PRESENT, None


def test_guarantee_none_when_neither() -> None:
    assert Effect().guarantee is Guarantee.NONE


def test_guarantee_verifiable_with_probe_only() -> None:
    assert Effect(verify=_probe).guarantee is Guarantee.VERIFIABLE


def test_guarantee_downstream_idempotent_with_key_param() -> None:
    assert Effect(key_param="idempotency_key").guarantee is Guarantee.DOWNSTREAM_IDEMPOTENT


def test_guarantee_precedence_key_param_over_verify() -> None:
    """Documented precedence: a deduping downstream is the stronger mechanism
    even when a probe is also provided (the probe still runs at post-verify)."""
    both = Effect(key_param="idempotency_key", verify=_probe)
    assert both.guarantee is Guarantee.DOWNSTREAM_IDEMPOTENT


def test_map_key_without_key_param_rejected() -> None:
    with pytest.raises(ValueError, match="map_key without key_param"):
        Effect(map_key=lambda k: k[:20])


def test_empty_key_param_rejected() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        Effect(key_param="")


def test_effect_is_frozen() -> None:
    effect = Effect(key_param="idempotency_key")
    with pytest.raises(dataclasses.FrozenInstanceError):
        effect.key_param = "other"  # type: ignore[misc]


def test_downstream_key_none_without_key_param() -> None:
    assert Effect().downstream_key_for("ledger-key") is None
    assert Effect(verify=_probe).downstream_key_for("ledger-key") is None


def test_downstream_key_is_ledger_key_without_map_key() -> None:
    assert Effect(key_param="k").downstream_key_for("ledger-key") == "ledger-key"


def test_downstream_key_goes_through_map_key() -> None:
    effect = Effect(key_param="k", map_key=lambda key: f"stripe-{key[:8]}")
    assert effect.downstream_key_for("abcdefgh12345") == "stripe-abcdefgh"


@pytest.mark.parametrize("bad", ["", None, 42])
def test_map_key_returning_garbage_is_loud(bad: object) -> None:
    """A silently-stored broken downstream key would strand the reconciler."""
    effect = Effect(key_param="k", map_key=lambda _: bad)  # type: ignore[arg-type,return-value]
    with pytest.raises(ValueError, match="non-empty str"):
        effect.downstream_key_for("ledger-key")
