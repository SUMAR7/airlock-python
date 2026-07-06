"""The native Policy/Rule decision layer (P2.1) — pure unit tests, no database.

Covers the decision matrix at the policy level: first-match-wins, default GATE
for unmatched actions, the declarative thresholds (glob / max_cost /
reversibility_in / max_blast_radius), Money cross-currency behavior, and the
ordered BlastRadius comparison. The @guard integration (AUTO calls commit_once,
DENY/GATE surface) lives in tests/test_guard.py; the no-I/O hot-path proof
lives in tests/test_hot_path.py.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from airlock.policy import ActionContext, Policy, PolicyBackend, Rule
from airlock.types import BlastRadius, Decision, Money, Reversibility


def USD(amount: str) -> Money:
    return Money(amount=amount, currency="USD")


def EUR(amount: str) -> Money:
    return Money(amount=amount, currency="EUR")


def ctx(
    action_type: str = "refund.create",
    *,
    reversibility: Reversibility = Reversibility.IRREVERSIBLE,
    cost: Money | None = None,
    blast_radius: BlastRadius | None = None,
) -> ActionContext:
    return ActionContext(
        action_type=action_type,
        reversibility=reversibility,
        cost=cost,
        blast_radius=blast_radius,
    )


# ---------------------------------------------------------------------------
# BlastRadius is an ORDERED enum (PLAN.md 3.2), not alphabetical.
# ---------------------------------------------------------------------------


def test_blast_radius_orders_low_medium_high() -> None:
    assert BlastRadius.LOW < BlastRadius.MEDIUM < BlastRadius.HIGH
    assert BlastRadius.HIGH > BlastRadius.MEDIUM > BlastRadius.LOW
    assert BlastRadius.MEDIUM <= BlastRadius.MEDIUM
    assert BlastRadius.MEDIUM >= BlastRadius.MEDIUM
    # NOT the str/alphabetical order (which would put 'high' < 'low' < 'medium').
    assert not (BlastRadius.HIGH < BlastRadius.LOW)


def test_blast_radius_rank_beats_alphabetical() -> None:
    """The ordering is by severity RANK, not the underlying str value — even
    where they disagree. Alphabetically 'high' < 'medium', but by rank
    medium(1) < high(2); enum-to-enum comparison must use the rank."""
    assert BlastRadius.MEDIUM < BlastRadius.HIGH  # rank: medium(1) < high(2)
    assert "high" < "medium"  # ... while the raw strings sort the other way
    # A max_blast_radius=HIGH ceiling therefore admits MEDIUM (rank-wise below).
    rule = Rule(match="*", decision=Decision.AUTO, max_blast_radius=BlastRadius.HIGH)
    assert rule.matches(ctx(blast_radius=BlastRadius.MEDIUM))


# ---------------------------------------------------------------------------
# Money — canonical amount, cross-currency, float rejection (PLAN.md 3.2).
# ---------------------------------------------------------------------------


def test_money_normalizes_amount_and_currency() -> None:
    # Decimal and int inputs are accepted at runtime and canonicalized to a
    # decimal string (the field type is str; these ignores exercise coercion).
    assert Money(amount=Decimal("12.50"), currency="eur") == Money(  # type: ignore[arg-type]
        amount="12.5", currency="EUR"
    )
    assert Money(amount="0.00", currency="USD").amount == "0"
    assert Money(amount=100, currency="usd").amount == "100"  # type: ignore[arg-type]


def test_money_rejects_float_amount() -> None:
    with pytest.raises(ValueError, match=r"float|decimal"):
        Money(amount=12.5, currency="USD")  # type: ignore[arg-type]


def test_money_rejects_bad_currency() -> None:
    for bad in ("US", "USDX", "12A", "€€€"):
        with pytest.raises(ValueError, match="ISO-4217"):
            Money(amount="1", currency=bad)


# ---------------------------------------------------------------------------
# Rule matching — each declarative condition, and their conjunction.
# ---------------------------------------------------------------------------


def test_glob_match_is_case_sensitive() -> None:
    rule = Rule(match="refund.*", decision=Decision.AUTO)
    assert rule.matches(ctx("refund.create"))
    assert not rule.matches(ctx("payout.create"))
    assert not rule.matches(ctx("Refund.create"))  # case-sensitive


def test_default_match_matches_everything() -> None:
    rule = Rule(decision=Decision.DENY)  # match defaults to "*"
    assert rule.matches(ctx("anything.at.all"))


def test_max_cost_same_currency_inclusive() -> None:
    rule = Rule(match="*", decision=Decision.AUTO, max_cost=USD("100"))
    assert rule.matches(ctx(cost=USD("99.99")))
    assert rule.matches(ctx(cost=USD("100")))  # inclusive
    assert not rule.matches(ctx(cost=USD("100.01")))


def test_max_cost_none_context_cost_never_within_budget() -> None:
    """A rule with a ceiling cannot prove the bound for a cost-less action —
    fail safe: it does not match."""
    rule = Rule(match="*", decision=Decision.AUTO, max_cost=USD("100"))
    assert not rule.matches(ctx(cost=None))


def test_max_cost_cross_currency_does_not_match() -> None:
    """Documented cross-currency behavior (PLAN.md 3.2): a cost in a DIFFERENT
    currency than max_cost does not satisfy the condition (no hot-path FX), so
    the rule does not match and evaluation falls through."""
    rule = Rule(match="*", decision=Decision.AUTO, max_cost=USD("100"))
    # 5 EUR is 'cheap' but the rule cannot compare across currencies.
    assert not rule.matches(ctx(cost=EUR("5")))


def test_reversibility_in_filters() -> None:
    rule = Rule(
        match="*",
        decision=Decision.AUTO,
        reversibility_in=frozenset({Reversibility.REVERSIBLE}),
    )
    assert rule.matches(ctx(reversibility=Reversibility.REVERSIBLE))
    assert not rule.matches(ctx(reversibility=Reversibility.IRREVERSIBLE))
    assert not rule.matches(ctx(reversibility=Reversibility.UNKNOWN))


def test_max_blast_radius_inclusive_and_ordered() -> None:
    rule = Rule(match="*", decision=Decision.AUTO, max_blast_radius=BlastRadius.MEDIUM)
    assert rule.matches(ctx(blast_radius=BlastRadius.LOW))
    assert rule.matches(ctx(blast_radius=BlastRadius.MEDIUM))  # inclusive
    assert not rule.matches(ctx(blast_radius=BlastRadius.HIGH))


def test_max_blast_radius_none_context_never_matches() -> None:
    """A missing blast radius never satisfies a set ceiling — fail safe."""
    rule = Rule(match="*", decision=Decision.AUTO, max_blast_radius=BlastRadius.HIGH)
    assert not rule.matches(ctx(blast_radius=None))


def test_conditions_are_conjunctive() -> None:
    """A rule with several conditions matches only when ALL hold."""
    rule = Rule(
        match="refund.*",
        decision=Decision.AUTO,
        max_cost=USD("100"),
        reversibility_in=frozenset({Reversibility.REVERSIBLE}),
        max_blast_radius=BlastRadius.MEDIUM,
    )
    good = ctx(
        "refund.create",
        cost=USD("50"),
        reversibility=Reversibility.REVERSIBLE,
        blast_radius=BlastRadius.LOW,
    )
    assert rule.matches(good)
    # Break one condition at a time; each break must drop the match.
    assert not rule.matches(good.__class__(**{**good.__dict__, "action_type": "payout.x"}))
    assert not rule.matches(good.__class__(**{**good.__dict__, "cost": USD("500")}))
    assert not rule.matches(
        good.__class__(**{**good.__dict__, "reversibility": Reversibility.IRREVERSIBLE})
    )
    assert not rule.matches(good.__class__(**{**good.__dict__, "blast_radius": BlastRadius.HIGH}))


# ---------------------------------------------------------------------------
# Policy — first-match-wins and the fail-safe default (PLAN.md 3.3).
# ---------------------------------------------------------------------------


def test_default_default_is_gate_for_unknown_actions() -> None:
    """An empty Policy gates EVERYTHING (fail safe) — the documented default."""
    policy = Policy()
    assert policy.default is Decision.GATE
    assert policy.evaluate(ctx("never.seen.before")) is Decision.GATE


def test_no_rule_matches_returns_default() -> None:
    policy = Policy(rules=[Rule(match="refund.*", decision=Decision.AUTO)], default=Decision.DENY)
    assert policy.evaluate(ctx("payout.create")) is Decision.DENY


def test_first_matching_rule_wins() -> None:
    """Order matters: the FIRST match supplies the decision, later rules that
    would also match are never reached."""
    policy = Policy(
        rules=[
            Rule(match="refund.small", decision=Decision.AUTO),
            Rule(match="refund.*", decision=Decision.GATE),  # would also match
            Rule(match="*", decision=Decision.DENY),
        ],
        default=Decision.GATE,
    )
    assert policy.evaluate(ctx("refund.small")) is Decision.AUTO
    assert policy.evaluate(ctx("refund.large")) is Decision.GATE
    assert policy.evaluate(ctx("payout.x")) is Decision.DENY


def test_realistic_money_movement_matrix() -> None:
    """A representative rule set exercised across the whole auto/gate/deny grid."""
    policy = Policy(
        rules=[
            # Small, reversible, low-blast refunds auto-commit.
            Rule(
                match="refund.*",
                decision=Decision.AUTO,
                max_cost=USD("100"),
                reversibility_in=frozenset({Reversibility.REVERSIBLE}),
                max_blast_radius=BlastRadius.LOW,
            ),
            # Bigger refunds gate for a human.
            Rule(match="refund.*", decision=Decision.GATE, max_cost=USD("10000")),
            # Payouts are always denied inline (out of policy).
            Rule(match="payout.*", decision=Decision.DENY),
        ],
        default=Decision.GATE,
    )
    auto = ctx(
        "refund.create",
        cost=USD("20"),
        reversibility=Reversibility.REVERSIBLE,
        blast_radius=BlastRadius.LOW,
    )
    assert policy.evaluate(auto) is Decision.AUTO
    # Reversible but too big → not the first rule; the second gates.
    big = ctx("refund.create", cost=USD("5000"), reversibility=Reversibility.REVERSIBLE)
    assert policy.evaluate(big) is Decision.GATE
    # Irreversible small refund → first rule's reversibility filter fails → gate.
    irr = ctx(
        "refund.create",
        cost=USD("20"),
        reversibility=Reversibility.IRREVERSIBLE,
        blast_radius=BlastRadius.LOW,
    )
    assert policy.evaluate(irr) is Decision.GATE
    assert policy.evaluate(ctx("payout.wire", cost=USD("1"))) is Decision.DENY
    # Cross-currency refund the rules can't bound → falls to default GATE.
    assert policy.evaluate(ctx("refund.create", cost=EUR("20"))) is Decision.GATE
    # Unknown action → default GATE.
    assert policy.evaluate(ctx("mystery.action")) is Decision.GATE


def test_policy_satisfies_the_backend_protocol() -> None:
    """Policy is a structural PolicyBackend (ADR-6 swap seam)."""
    assert isinstance(Policy(), PolicyBackend)


def test_action_context_is_frozen_and_serializable() -> None:
    """ActionContext carries no closures/callables — a frozen bag of resolved
    values, so a Rego backend / the event schema can consume the same input."""
    import dataclasses

    c = ctx("refund.create", cost=USD("10"), blast_radius=BlastRadius.LOW)
    with pytest.raises(dataclasses.FrozenInstanceError):
        c.action_type = "other"  # type: ignore[misc]
    # Every field is a plain serializable value (no callables captured).
    for f in dataclasses.fields(c):
        value = getattr(c, f.name)
        assert value is None or not callable(value), f.name
