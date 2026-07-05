"""The swappable policy layer (ADR-6) — the auto/gate/deny decision.

This is the one path that must be **boringly reliable** (SPEC.md 3, ADR-3):
policy evaluation is deterministic, declarative, in-process, and does **zero
I/O of any kind** — no socket, no DB, no LLM, no file. The hot-path rule is a
HARD constraint: ~95% of guarded calls decide here and never leave the
customer's process. A no-socket test pins it (``tests/test_hot_path.py``).

The layer has four pieces:

- :class:`ActionContext` — the SERIALIZABLE decision input (action_type, cost,
  reversibility, blast_radius). No captured closures, no callables: a frozen
  bag of already-resolved values, so a future Rego/OPA backend (PLAN.md 9) can
  consume the SAME inputs the native backend does. ``@guard`` builds it from
  decorator metadata + call args (resolving callable cost/blast_radius there,
  BEFORE this layer sees them).
- :class:`PolicyBackend` — the stable Protocol (one method, ``evaluate``) that
  keeps call sites decoupled from the backend, so Rego slots in later without
  touching ``@guard`` (ADR-6).
- :class:`Rule` — a DECLARATIVE threshold row (glob + decision + max_cost +
  reversibility set + max_blast_radius). No lambdas, so the shape translates to
  Rego later (PLAN.md 3.3).
- :class:`Policy` — the v1 native backend: first matching rule wins; the
  default default is ``GATE`` so an unmatched (unknown) action fails SAFE.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Protocol, runtime_checkable

from airlock.types import BlastRadius, Decision, Money, Reversibility

__all__ = [
    "ActionContext",
    "Policy",
    "PolicyBackend",
    "Rule",
]


@dataclass(frozen=True)
class ActionContext:
    """The serializable input to a policy decision (ADR-6, PLAN.md 3.3).

    A frozen bag of ALREADY-RESOLVED values — deliberately not a live view of
    the call. ``@guard`` resolves any callable ``cost``/``blast_radius``
    against the call args and freezes the results here BEFORE
    :meth:`PolicyBackend.evaluate` runs, so:

    - the decision layer never invokes integrator code (a callable on the hot
      path could do I/O and break the hard rule; resolving it in ``@guard``
      keeps ``evaluate`` pure), and
    - the exact same inputs serialize to JSON for a future Rego backend and for
      the P2.2 event/audit record — one shape, no forks (PLAN.md 9).

    Attributes:
        action_type: the stable action identifier (matched against
            :attr:`Rule.match`).
        cost: the action's monetary cost as :class:`~airlock.types.Money`, or
            ``None`` when the action has no cost / it is unknown. A ``None``
            cost is never "within budget" for a rule that sets ``max_cost``
            (that rule cannot prove the bound holds) — fail safe.
        reversibility: whether the effect can be undone
            (:class:`~airlock.types.Reversibility`).
        blast_radius: how wide the impact is
            (:class:`~airlock.types.BlastRadius`), or ``None`` when unknown. A
            ``None`` blast radius never satisfies a rule's ``max_blast_radius``
            — fail safe, same reasoning as cost.
    """

    action_type: str
    reversibility: Reversibility
    cost: Money | None = None
    blast_radius: BlastRadius | None = None


@runtime_checkable
class PolicyBackend(Protocol):
    """The stable policy interface (ADR-6) — the swap seam for Rego/OPA later.

    One method. Call sites (``@guard``) hold this Protocol, never a concrete
    backend, so a Rego/OPA implementation slots in without touching them
    (PLAN.md 9: "call sites hold the protocol").
    """

    def evaluate(self, ctx: ActionContext) -> Decision:
        """Return the auto/gate/deny :class:`~airlock.types.Decision` for ``ctx``.

        **MUST be deterministic, in-process, and I/O-free** (ADR-3 + the
        hot-path rule, SPEC.md 3): no network, no database, no LLM, no file, no
        clock-dependent branching. The same ``ctx`` must always yield the same
        decision. This is the ~95% path that never leaves the customer's
        process; a single socket here would violate the prime constraint.
        """
        ...


@dataclass(frozen=True)
class Rule:
    """One declarative policy rule (PLAN.md 3.3) — thresholds, never lambdas.

    A rule MATCHES an :class:`ActionContext` when ALL of its populated
    conditions hold; the first matching rule in a :class:`Policy` supplies the
    decision (first-match-wins). Every condition is a plain data threshold —
    there are no callables — so the whole rule set translates mechanically to
    Rego later (PLAN.md 9).

    A condition left at its default (``None`` / ``match="*"``) is unconstrained
    (always satisfied). All conditions are conjunctive: a rule that sets both
    ``max_cost`` and ``reversibility_in`` matches only a context that satisfies
    both.

    Attributes:
        match: a case-sensitive :func:`fnmatch.fnmatchcase` glob over
            ``action_type`` (``*`` any, ``?`` one char, ``[seq]`` a set).
            Default ``"*"`` matches every action.
        decision: the :class:`~airlock.types.Decision` this rule yields when it
            matches. Default ``GATE`` (a bare ``Rule(match="refund.*")`` gates,
            the safe direction).
        max_cost: the inclusive cost ceiling as :class:`~airlock.types.Money`.
            The condition holds when the context cost is present, is in the
            SAME currency, and is ``<= max_cost``. **Cross-currency behavior
            (documented, deliberate):** a context cost in a DIFFERENT currency
            does NOT satisfy this condition — there is no I/O-free exchange rate
            on the hot path, so the rule cannot prove the bound and does not
            match; evaluation falls through to the next rule / the default
            (fail safe). A ``None`` context cost likewise never satisfies a set
            ``max_cost``. ``None`` here means "no cost ceiling".
        reversibility_in: the set of acceptable
            :class:`~airlock.types.Reversibility` values; the condition holds
            when the context reversibility is IN the set. ``None`` means "any
            reversibility".
        max_blast_radius: the inclusive :class:`~airlock.types.BlastRadius`
            ceiling (the enum is ordered ``low < medium < high``); the
            condition holds when the context blast radius is present and
            ``<= max_blast_radius``. A ``None`` context blast radius never
            satisfies a set ceiling (fail safe). ``None`` here means "any blast
            radius".
    """

    match: str = "*"
    decision: Decision = Decision.GATE
    max_cost: Money | None = None
    reversibility_in: frozenset[Reversibility] | None = None
    max_blast_radius: BlastRadius | None = None

    def matches(self, ctx: ActionContext) -> bool:
        """Whether every populated condition of this rule holds for ``ctx``."""
        return (
            fnmatchcase(ctx.action_type, self.match)
            and self._cost_ok(ctx.cost)
            and self._reversibility_ok(ctx.reversibility)
            and self._blast_radius_ok(ctx.blast_radius)
        )

    def _reversibility_ok(self, reversibility: Reversibility) -> bool:
        return self.reversibility_in is None or reversibility in self.reversibility_in

    def _blast_radius_ok(self, blast_radius: BlastRadius | None) -> bool:
        if self.max_blast_radius is None:
            return True
        # A missing blast radius never satisfies a set ceiling (fail safe).
        return blast_radius is not None and blast_radius <= self.max_blast_radius

    def _cost_ok(self, cost: Money | None) -> bool:
        """The ``max_cost`` condition (see the class docstring for cross-currency)."""
        if self.max_cost is None:
            return True
        if cost is None:
            # No cost to compare: a rule with a ceiling cannot prove the bound
            # holds, so it does not match (fail safe).
            return False
        if cost.currency != self.max_cost.currency:
            # Cross-currency: undefined comparison, no hot-path FX. The rule
            # does not match; fall through to the next rule / default.
            return False
        return cost.as_decimal() <= self.max_cost.as_decimal()


@dataclass(frozen=True)
class Policy:
    """The v1 native policy backend (ADR-6): first matching rule wins.

    Rules are evaluated in order; the first whose :meth:`Rule.matches` is true
    supplies the decision. When no rule matches, :attr:`default` is returned —
    and its default is ``GATE``, so an unknown / unmatched action FAILS SAFE
    (pauses for a human rather than auto-committing, SPEC.md 3 / PLAN.md 3.3).

    Evaluation is pure: no I/O, no clock, no captured state beyond the frozen
    rule list — satisfying :class:`PolicyBackend` and the hot-path rule.

    Args:
        rules: the ordered rule set; first match wins. Empty (the default)
            means every action takes the ``default`` decision.
        default: the decision for a context no rule matches. Default ``GATE``
            (fail safe). Set it to ``DENY`` for a deny-by-default posture, or
            ``AUTO`` only when the rule set already gates/denies everything
            dangerous.
    """

    rules: Sequence[Rule] = field(default_factory=tuple)
    default: Decision = Decision.GATE

    def evaluate(self, ctx: ActionContext) -> Decision:
        """First-match-wins over :attr:`rules`, else :attr:`default` (pure)."""
        for rule in self.rules:
            if rule.matches(ctx):
                return rule.decision
        return self.default
