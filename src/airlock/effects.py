"""``Effect`` — how exactly-once is achievable for one action type (ADR-2).

We can only guarantee exactly-once if the downstream effect either

(a) accepts an idempotency key we pass through (``key_param`` — e.g. Stripe's
    ``Idempotency-Key``), or
(b) exposes a verification probe (``verify`` — "did this refund happen?").

The integrator provides one per action type. An ``Effect`` with neither
degrades the action to **at-most-once** (``Guarantee.NONE``): ``commit_once``
warns loudly (``AtMostOnceWarning``), stamps the degradation on the ledger
row, and never blind-retries — the honesty is a feature (SPEC.md section 5,
scenario 7).

This module is import-light by design: stdlib + ``airlock.types`` only.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from airlock.types import Guarantee, Verification

__all__ = ["Effect"]


@dataclass(frozen=True)
class Effect:
    """Declares the ADR-2 exactly-once mechanism for an action type.

    Attributes:
        key_param: name of the kwarg through which the wrapped tool accepts a
            downstream idempotency key (e.g. ``"idempotency_key"`` for
            Stripe). When set, ``commit_once`` derives the downstream key
            from the ledger key (via :meth:`downstream_key_for`) and the tool
            call receives it — one key, two layers of dedup (PLAN.md
            section 3.4).
        map_key: optional transform applied to the ledger key to satisfy
            downstream length/charset limits. Whatever ``map_key`` returns is
            EXACTLY what is sent downstream AND what is persisted in
            ``commit_records.downstream_key`` — the post-verify probe and the
            P1.3 reconciler depend on the stored value being the sent value.
            Meaningless without ``key_param`` (there is no downstream key to
            transform), so that combination is rejected.
        verify: the verification probe — "did this effect happen?". Called
            with the action's canonical arg_map splatted as keyword arguments
            (``verify(**arg_map)``), both by ``commit_once``'s post-verify
            step and by the P1.3 reconciler after rehydrating
            ``commit_records.args_json`` — write it against the arg_map
            values (canonical JSON: Money amounts are decimal strings, ...),
            and accept ``**_`` for args it does not need. Returns a
            ``(Verification, evidence)`` tuple; ``evidence`` (JSON-safe,
            ideally) is recorded on the ledger row for the ``absent`` and
            ``unknown`` answers.

    The ``guarantee`` precedence is ``key_param`` over ``verify``: a
    downstream that dedupes on a passed-through key is the stronger mechanism
    (recovery can safely re-issue with the same key — downstream dedup *is*
    the verification), so it defines the guarantee even when a probe is also
    provided. A probe alongside ``key_param`` is still used for post-verify.
    """

    key_param: str | None = None
    map_key: Callable[[str], str] | None = None
    verify: Callable[..., tuple[Verification, Any | None]] | None = None

    def __post_init__(self) -> None:
        if self.key_param is not None and not self.key_param:
            raise ValueError("key_param must be a non-empty kwarg name, or None")
        if self.map_key is not None and self.key_param is None:
            raise ValueError(
                "map_key without key_param is meaningless: map_key transforms the "
                "downstream idempotency key, and key_param is what makes one exist"
            )

    @property
    def guarantee(self) -> Guarantee:
        """The ADR-2 guarantee class this effect operates under.

        ``downstream_idempotent`` if ``key_param`` is set, else ``verifiable``
        if ``verify`` is set, else ``none`` (at-most-once mode — warned
        loudly and stamped on the ledger row by ``commit_once``).
        """
        if self.key_param is not None:
            return Guarantee.DOWNSTREAM_IDEMPOTENT
        if self.verify is not None:
            return Guarantee.VERIFIABLE
        return Guarantee.NONE

    def downstream_key_for(self, ledger_key: str) -> str | None:
        """The downstream idempotency key for ``ledger_key``, or ``None``.

        ``map_key(ledger_key)`` when both ``key_param`` and ``map_key`` are
        set, ``ledger_key`` verbatim when only ``key_param`` is set, ``None``
        when the downstream accepts no key. The return value is what
        ``execute`` receives AND what ``commit_records.downstream_key``
        stores — exactly the bytes sent downstream.

        Raises:
            ValueError: ``map_key`` returned something other than a
                non-empty ``str`` — silently storing a broken downstream key
                would strand the reconciler.
        """
        if self.key_param is None:
            return None
        if self.map_key is None:
            return ledger_key
        mapped = self.map_key(ledger_key)
        if not isinstance(mapped, str) or not mapped:
            raise ValueError(
                f"map_key must return a non-empty str, got {mapped!r} — the stored "
                "downstream_key must be exactly what was sent downstream"
            )
        return mapped
