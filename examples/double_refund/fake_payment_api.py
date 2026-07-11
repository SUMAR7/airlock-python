"""A tiny in-memory stand-in for a Stripe-shaped payment provider.

There is NO real network here — this class exists so the double-refund demo can
run with zero infrastructure and still *count* how many times money actually
moved. It models the two things that matter for the story:

1. It **records every actual refund side effect** (``refund_count`` reports how
   many times a charge was really refunded), and
2. Given an ``idempotency_key`` it **dedupes** — a repeated key returns the
   prior refund instead of issuing a new one. This mirrors how a real payment
   API behaves (Stripe's ``Idempotency-Key`` header; SPEC.md ADR-2 clause a),
   and it is the same key Airlock passes downstream via ``Effect.key_param``.

Everything is plain stdlib so ``python demo.py`` works on a base install.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Refund:
    """One issued refund — the record of a real money-movement side effect."""

    id: str
    charge_id: str
    amount_cents: int


class FakePaymentAPI:
    """An in-memory Stripe-shaped refund API (no network, fully counted)."""

    def __init__(self) -> None:
        self._refunds: dict[str, list[Refund]] = {}  # charge_id -> issued refunds
        self._by_key: dict[str, Refund] = {}  # idempotency_key -> prior refund
        self.total_calls = 0  # every refund() invocation, deduped or not

    def refund(
        self, charge_id: str, amount_cents: int, *, idempotency_key: str | None = None
    ) -> Refund:
        """Refund a charge. With an ``idempotency_key``, a repeat is deduped."""
        self.total_calls += 1
        # A real idempotent API: a key it has already seen returns the SAME
        # refund and moves no additional money (SPEC.md scenario 7 / ADR-2).
        if idempotency_key is not None and idempotency_key in self._by_key:
            return self._by_key[idempotency_key]
        # Otherwise this is a NEW side effect: money moves, and we record it.
        refund = Refund(
            id=f"re_{self.total_calls:04d}", charge_id=charge_id, amount_cents=amount_cents
        )
        self._refunds.setdefault(charge_id, []).append(refund)
        if idempotency_key is not None:
            self._by_key[idempotency_key] = refund
        return refund

    def refund_count(self, charge_id: str) -> int:
        """How many times this charge was ACTUALLY refunded (side effects)."""
        return len(self._refunds.get(charge_id, []))
