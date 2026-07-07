"""@guard end-to-end (P2.1): the decision → auto/deny/gate flow over the ledger.

DB-backed (the AUTO path drives the REAL commit_once against Postgres; effect
ground truth is the effects_log autocommit table). Covers:

- AUTO actually calls commit_once and commits EXACTLY ONCE (effects_log == 1),
  duplicate calls dedupe, the downstream key is injected via effect.key_param;
- DENY raises ActionDenied and does NOT execute, before any ledger claim;
- GATE does NOT execute the side effect and surfaces cleanly (GateNotSupported,
  a subclass of ActionPending) with no pause built (no paused_runs anywhere);
- callable cost / blast_radius resolved per-call from the args (before the pure
  policy sees them);
- the decision matrix (auto/gate/deny across action_type/cost/reversibility/
  blast_radius) exercised through the decorator;
- key override + key_ignore, preconditions (SPEC scenario 8 at the decorator);
- decoration is side-effect-free except the registry registration;
- calling @guard before init() is a loud error.

The pure policy matrix and the no-I/O hot-path proof live in test_policy.py and
test_hot_path.py respectively.
"""

from __future__ import annotations

import warnings
from decimal import Decimal
from typing import TYPE_CHECKING, Any

import pytest
from sqlalchemy import text

from airlock import guard, init
from airlock.effects import Effect
from airlock.errors import ActionDenied, ActionPending, AirlockError, GateNotSupported
from airlock.policy import Policy, Rule
from airlock.registry import registry as default_registry
from airlock.types import BlastRadius, Decision, LedgerState, Money, Reversibility

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore
    from tests.conftest import EffectsLog

pytestmark = pytest.mark.usefixtures("guard_isolation")


def USD(amount: str) -> Money:
    return Money(amount=amount, currency="USD")


def _auto_policy() -> Policy:
    return Policy(default=Decision.AUTO)


# ---------------------------------------------------------------------------
# AUTO — commit_once is really called, exactly once (effects_log ground truth).
# ---------------------------------------------------------------------------


def test_auto_commits_exactly_once_and_dedupes(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    """AUTO drives commit_once: one effect logged, the downstream key injected
    via key_param, and a duplicate call returns the first result WITHOUT a
    second effect (SPEC scenario 1 through the decorator)."""
    init(store=store, policy=_auto_policy())
    seen: list[str | None] = []

    @guard(
        "refund.create",
        cost=USD("10"),
        reversibility=Reversibility.REVERSIBLE,
        effect=Effect(key_param="idempotency_key"),
    )
    def do_refund(invoice: str, *, idempotency_key: str | None = None) -> dict[str, Any]:
        seen.append(idempotency_key)
        effects.log(idempotency_key or "none")
        return {"refunded": invoice, "dk": idempotency_key}

    first = do_refund("inv_1")
    assert first["refunded"] == "inv_1"
    downstream = seen[0]
    assert downstream is not None and len(downstream) == 64  # the derived ledger key
    assert effects.count(downstream) == 1

    # Duplicate call: ledger dedupes, no second effect, same result.
    second = do_refund("inv_1")
    assert second == first
    assert effects.count(downstream) == 1
    assert seen == [downstream]  # the tool ran exactly once


def test_auto_writes_a_committed_ledger_row(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    """The AUTO path leaves a durable committed commit_records row stamped with
    the guarantee derived from the Effect — proving it went through the ledger."""
    init(store=store, policy=_auto_policy())

    @guard("refund.durable", effect=Effect(key_param="idempotency_key"))
    def do_refund(invoice: str, *, idempotency_key: str | None = None) -> dict[str, str]:
        effects.log(invoice)
        return {"id": invoice}

    do_refund("inv_durable")
    with db.connect() as conn:
        row = conn.execute(
            text(
                "SELECT state, guarantee, action_type FROM commit_records "
                "WHERE action_type = 'refund.durable'"
            )
        ).one()
    assert row.state == LedgerState.COMMITTED.value
    assert row.guarantee == "downstream_idempotent"
    assert effects.count("inv_durable") == 1


def test_auto_callable_cost_and_blast_radius_resolved_from_args(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    """cost / blast_radius may be callables of the call args; @guard resolves
    them per call (before the pure policy). A rule keyed on the resolved cost
    then decides — small auto-commits, large gates."""
    policy = Policy(
        rules=[Rule(match="refund.dyn", decision=Decision.AUTO, max_cost=USD("100"))],
        default=Decision.GATE,
    )
    init(store=store, policy=policy)

    def cost_of(amount: str, **_: object) -> Money:
        # Exercise the Decimal-input path of Money (canonicalized on the way in).
        return Money(amount=Decimal(amount), currency="USD")  # type: ignore[arg-type]

    def blast_of(amount: str, **_: object) -> BlastRadius:
        return BlastRadius.HIGH if Decimal(amount) > 1000 else BlastRadius.LOW

    @guard(
        "refund.dyn",
        cost=cost_of,
        blast_radius=blast_of,
        effect=Effect(key_param="idempotency_key"),
    )
    def do_refund(amount: str, *, idempotency_key: str | None = None) -> dict[str, str]:
        effects.log(amount)
        return {"amount": amount}

    # $50 → under the $100 ceiling → AUTO.
    assert do_refund("50")["amount"] == "50"
    assert effects.count("50") == 1

    # $500 → over the ceiling → no rule matches → default GATE, no effect.
    with pytest.raises(GateNotSupported):
        do_refund("500")
    assert effects.count("500") == 0


def test_auto_failed_post_verify_surfaces_commit_failed(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    """An AUTO action whose post-verify probe PROVES the effect absent finalizes
    the ledger row 'failed'. @guard must surface that as CommitFailed rather than
    a silent None — the prime directive is 'always provable', so the caller must
    not mistake a non-landed effect for a successful commit."""
    from airlock.errors import CommitFailed
    from airlock.types import Verification

    init(store=store, policy=_auto_policy())

    @guard(
        "refund.probeabsent",
        reversibility=Reversibility.REVERSIBLE,
        effect=Effect(verify=lambda **_: (Verification.ABSENT, {"checked": True})),
    )
    def do_refund(invoice: str) -> str:
        effects.log(invoice)
        return invoice

    with pytest.raises(CommitFailed) as excinfo:
        do_refund("inv_absent")
    assert excinfo.value.action_type == "refund.probeabsent"
    assert excinfo.value.state == LedgerState.FAILED.value
    assert excinfo.value.error is not None  # the probe evidence is carried
    # The ledger row is durably 'failed' (executed, confirmed not to have landed).
    with db.connect() as conn:
        state = conn.execute(
            text("SELECT state FROM commit_records WHERE action_type = 'refund.probeabsent'")
        ).scalar_one()
    assert state == LedgerState.FAILED.value


# ---------------------------------------------------------------------------
# DENY — raises, does not execute, nothing durable.
# ---------------------------------------------------------------------------


def test_deny_raises_and_does_not_execute(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    init(store=store, policy=Policy(rules=[Rule(match="payout.*", decision=Decision.DENY)]))

    @guard("payout.wire", reversibility=Reversibility.IRREVERSIBLE)
    def do_payout(dest: str) -> dict[str, str]:
        effects.log(dest)  # must never run
        return {"sent": dest}

    with pytest.raises(ActionDenied) as excinfo:
        do_payout("acct_9")
    assert excinfo.value.action_type == "payout.wire"
    assert effects.count("acct_9") == 0
    # No ledger row was claimed for the denied action.
    with db.connect() as conn:
        count = conn.execute(
            text("SELECT count(*) FROM commit_records WHERE action_type = 'payout.wire'")
        ).scalar_one()
    assert count == 0


# ---------------------------------------------------------------------------
# GATE — does not execute, surfaces cleanly, no pause layer built (P2.1).
# ---------------------------------------------------------------------------


def test_gate_does_not_execute_and_surfaces_cleanly(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    """A GATE decision raises GateNotSupported (a subclass of ActionPending
    that names P2.3), runs no side effect, and creates no ledger row — the
    durable pause is explicitly NOT built in P2.1."""
    init(store=store, policy=Policy(default=Decision.GATE))

    @guard("gated.action", reversibility=Reversibility.IRREVERSIBLE)
    def gated(x: int) -> int:
        effects.log(str(x))  # must never run
        return x

    with pytest.raises(GateNotSupported) as excinfo:
        gated(7)
    # It IS an ActionPending (integrators can catch either).
    assert isinstance(excinfo.value, ActionPending)
    assert excinfo.value.action_type == "gated.action"
    assert excinfo.value.run_id is None  # no paused_runs row in P2.1
    assert "P2.3" in str(excinfo.value)
    assert effects.count("7") == 0
    with db.connect() as conn:
        count = conn.execute(
            text("SELECT count(*) FROM commit_records WHERE action_type = 'gated.action'")
        ).scalar_one()
    assert count == 0


# ---------------------------------------------------------------------------
# The decision matrix, exercised through the decorator.
# ---------------------------------------------------------------------------


def test_decision_matrix_through_the_decorator(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    """One rule set, three actions, three outcomes — auto commits, deny blocks,
    the default gates — all via @guard against the real ledger."""
    policy = Policy(
        rules=[
            Rule(
                match="refund.*",
                decision=Decision.AUTO,
                max_cost=USD("100"),
                reversibility_in=frozenset({Reversibility.REVERSIBLE}),
            ),
            Rule(match="payout.*", decision=Decision.DENY),
        ],
        default=Decision.GATE,
    )
    init(store=store, policy=policy)

    @guard(
        "refund.ok",
        cost=USD("20"),
        reversibility=Reversibility.REVERSIBLE,
        effect=Effect(key_param="idempotency_key"),
    )
    def refund(invoice: str, *, idempotency_key: str | None = None) -> str:
        effects.log(f"refund-{invoice}")
        return invoice

    @guard("payout.big", reversibility=Reversibility.IRREVERSIBLE)
    def payout(dest: str) -> str:
        effects.log(f"payout-{dest}")
        return dest

    @guard("mystery.op", reversibility=Reversibility.UNKNOWN)
    def mystery(v: int) -> int:
        effects.log(f"mystery-{v}")
        return v

    assert refund("inv_1") == "inv_1"  # AUTO
    assert effects.count("refund-inv_1") == 1

    with pytest.raises(ActionDenied):  # DENY
        payout("acct_1")
    assert effects.count("payout-acct_1") == 0

    with pytest.raises(GateNotSupported):  # default GATE
        mystery(3)
    assert effects.count("mystery-3") == 0


def test_irreversible_refund_gates_not_autos(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    """The reversibility filter bites: an otherwise-cheap refund that is
    irreversible does not match the AUTO rule → falls to default GATE."""
    policy = Policy(
        rules=[
            Rule(
                match="refund.*",
                decision=Decision.AUTO,
                max_cost=USD("100"),
                reversibility_in=frozenset({Reversibility.REVERSIBLE}),
            )
        ],
        default=Decision.GATE,
    )
    init(store=store, policy=policy)

    @guard("refund.irr", cost=USD("5"), reversibility=Reversibility.IRREVERSIBLE)
    def refund(invoice: str) -> str:
        effects.log(invoice)
        return invoice

    with pytest.raises(GateNotSupported):
        refund("inv_irr")
    assert effects.count("inv_irr") == 0


# ---------------------------------------------------------------------------
# Key override, key_ignore, preconditions.
# ---------------------------------------------------------------------------


def test_key_override_is_namespaced(store: PostgresStore, effects: EffectsLog, db: Engine) -> None:
    """key= overrides derivation; the ledger key is '{action_type}:{user_key}'
    (P1.2 namespacing), so an operator can see the custom key in the row."""
    init(store=store, policy=_auto_policy())

    @guard("refund.keyed", key=lambda order_id, **_: order_id, effect=Effect())
    def refund(order_id: str) -> str:
        effects.log(order_id)
        return order_id

    refund("order-42")
    with db.connect() as conn:
        keys = (
            conn.execute(
                text(
                    "SELECT idempotency_key FROM commit_records WHERE action_type = 'refund.keyed'"
                )
            )
            .scalars()
            .all()
        )
    assert keys == ["refund.keyed:order-42"]


def test_key_ignore_excludes_volatile_arg(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    """A volatile arg named in key_ignore must not fork the key: two calls that
    differ only in that arg dedupe to one effect."""
    init(store=store, policy=_auto_policy())

    @guard("refund.volatile", key_ignore=("request_ts",), effect=Effect())
    def refund(invoice: str, request_ts: str) -> str:
        effects.log(invoice)
        return invoice

    refund("inv_v", request_ts="2026-01-01T00:00:00Z")
    refund("inv_v", request_ts="2026-01-02T09:99:99Z")  # different ts, same key
    # One ledger row, one effect.
    with db.connect() as conn:
        count = conn.execute(
            text("SELECT count(*) FROM commit_records WHERE action_type = 'refund.volatile'")
        ).scalar_one()
    assert count == 1
    assert effects.count("inv_v") == 1


def test_preconditions_abort_surfaces_as_precondition_failed(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    """SPEC scenario 8 at the decorator: preconditions re-checked after the
    claim; when they fail the row is aborted, no effect runs, and @guard raises
    PreconditionFailed rather than returning a silent None."""
    from airlock.errors import PreconditionFailed

    init(store=store, policy=_auto_policy())

    @guard(
        "refund.precond",
        effect=Effect(),
        preconditions=lambda invoice, **_: invoice != "blocked",
    )
    def refund(invoice: str) -> str:
        effects.log(invoice)
        return invoice

    with pytest.raises(PreconditionFailed) as excinfo:
        refund("blocked")
    assert excinfo.value.action_type == "refund.precond"
    assert effects.count("blocked") == 0
    with db.connect() as conn:
        state = conn.execute(
            text("SELECT state FROM commit_records WHERE action_type = 'refund.precond'")
        ).scalar_one()
    assert state == LedgerState.ABORTED.value

    # A satisfied precondition commits normally.
    assert refund("allowed") == "allowed"
    assert effects.count("allowed") == 1


# ---------------------------------------------------------------------------
# Decoration is side-effect-free except the registry registration.
# ---------------------------------------------------------------------------


def test_decoration_only_side_effect_is_registration() -> None:
    """Applying @guard registers action_type -> (fn, effect, preconditions) in
    the shared registry (so resume/reconcile can find it) and does nothing
    else — no runtime, no store, no policy needed to DECORATE."""
    assert "reg.probe" not in default_registry

    effect = Effect(key_param="idempotency_key")
    precond = lambda **_: True  # noqa: E731

    @guard("reg.probe", effect=effect, preconditions=precond)
    def tool(x: int, *, idempotency_key: str | None = None) -> int:
        return x

    reg = default_registry.get("reg.probe")
    assert reg is not None
    assert reg.effect is effect
    assert reg.preconditions is not None  # adapted, not None
    # The wrapper is call-shaped like the original (functools.wraps).
    assert tool.__name__ == "tool"


def test_registered_execute_reconstructs_the_call() -> None:
    """The registry adapter (execute(downstream_key, **arg_map)) reconstructs
    the ORIGINAL call — the exact path a cross-process reconciler uses. The
    downstream key is injected via effect.key_param."""
    from airlock.idempotency import build_arg_map

    seen: list[tuple[Any, ...]] = []

    @guard("reg.recover", effect=Effect(key_param="idk"))
    def tool(a: int, b: int, *rest: int, flag: bool = True, idk: str | None = None) -> int:
        seen.append((a, b, rest, flag, idk))
        return a + b

    reg = default_registry.get("reg.recover")
    assert reg is not None
    arg_map = build_arg_map(tool, (1, 2, 9), {"flag": False}, key_param="idk")
    result = reg.execute("DK-123", **arg_map)
    assert result == 3
    assert seen == [(1, 2, (9,), False, "DK-123")]


# ---------------------------------------------------------------------------
# Guardrails: bad action_type, missing runtime.
# ---------------------------------------------------------------------------


def test_guard_before_init_is_a_loud_error(store: PostgresStore) -> None:
    """@guard resolves the runtime lazily at call time; calling before init()
    is a clear AirlockError, not an AttributeError on a None runtime."""

    # Note: guard_isolation cleared the runtime, so no init() has run here.
    @guard("noinit.action", effect=Effect())
    def tool(x: int) -> int:
        return x

    with pytest.raises(AirlockError, match=r"before airlock\.init"):
        tool(1)


def test_action_type_with_colon_rejected() -> None:
    with pytest.raises(ValueError, match="must not contain ':'"):

        @guard("bad:type")
        def tool() -> None: ...


def test_empty_action_type_rejected() -> None:
    with pytest.raises(ValueError, match="non-empty"):

        @guard("")
        def tool() -> None: ...


def test_at_most_once_auto_still_commits_with_warning(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    """An AUTO action with a bare Effect() (no key_param, no verify) runs
    at-most-once: commit_once warns loudly but still commits once — @guard does
    not suppress the ADR-2 degradation."""
    init(store=store, policy=_auto_policy())

    @guard("opaque.auto", effect=Effect(), reversibility=Reversibility.REVERSIBLE)
    def tool(x: str) -> str:
        effects.log(x)
        return x

    from airlock.errors import AtMostOnceWarning

    with pytest.warns(AtMostOnceWarning, match="AT-MOST-ONCE"):
        assert tool("v") == "v"
    assert effects.count("v") == 1


def test_no_paused_runs_table_is_created(store: PostgresStore, db: Engine) -> None:
    """Scope fence: P2.1 builds no durable pause. A GATE must not create a
    paused_runs table or any pause artifact — assert the table does not exist."""
    init(store=store, policy=Policy(default=Decision.GATE))

    @guard("scope.gate", reversibility=Reversibility.UNKNOWN)
    def tool() -> None: ...

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with pytest.raises(GateNotSupported):
            tool()

    with db.connect() as conn:
        exists = conn.execute(text("SELECT to_regclass('public.paused_runs')")).scalar_one()
    assert exists is None  # P2.3 builds paused_runs, not P2.1


# ---------------------------------------------------------------------------
# The event seam (P2.2): the ONE action_event.v1, mirrored to sinks.
# The full durable-emission matrix (audit rows, fields, chain integrity) lives
# in tests/test_guard_events.py; here we pin the sink-mirror behavior.
# ---------------------------------------------------------------------------


class _RecordingSink:
    """A test EventSink that records every ActionEvent it receives."""

    def __init__(self) -> None:
        from airlock.events import ActionEvent

        self.events: list[ActionEvent] = []

    def emit(self, event: Any) -> None:
        self.events.append(event)


def test_event_sink_mirrors_auto_and_deny_but_not_gate(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    """The one event contract (PLAN.md 6.3): AUTO mirrors its terminal
    action_event (outcome committed), DENY mirrors the denied event at decision
    time, and GATE emits NOTHING in P2.2 — its event belongs to the P2.3
    terminal state (see airlock.events)."""
    sink = _RecordingSink()
    policy = Policy(
        rules=[
            Rule(match="refund.*", decision=Decision.AUTO),
            Rule(match="payout.*", decision=Decision.DENY),
        ],
        default=Decision.GATE,
    )
    init(store=store, policy=policy, event_sinks=[sink])

    @guard(
        "refund.ev",
        cost=USD("10"),
        reversibility=Reversibility.REVERSIBLE,
        blast_radius=BlastRadius.LOW,
        effect=Effect(key_param="idempotency_key"),
    )
    def refund(invoice: str, *, idempotency_key: str | None = None) -> str:
        effects.log(invoice)
        return invoice

    @guard("payout.ev", reversibility=Reversibility.IRREVERSIBLE)
    def payout(dest: str) -> str:
        return dest

    @guard("gate.ev", reversibility=Reversibility.UNKNOWN)
    def gate(x: int) -> int:
        return x

    refund("inv_ev")
    with pytest.raises(ActionDenied):
        payout("acct")
    with pytest.raises(GateNotSupported):
        gate(1)

    from airlock.types import ActionOutcome

    seen = [(e.action_type, e.policy_decision, e.outcome) for e in sink.events]
    assert seen == [
        ("refund.ev", Decision.AUTO, ActionOutcome.COMMITTED),
        ("payout.ev", Decision.DENY, ActionOutcome.DENIED),
        # gate.ev: nothing — no terminal state exists for a gate until P2.3.
    ]
    # The AUTO event carries the resolved risk metadata + the schema-pinned shape.
    auto_event = sink.events[0]
    assert auto_event.schema_version == 1
    assert auto_event.cost == USD("10")
    assert auto_event.reversibility is Reversibility.REVERSIBLE
    assert auto_event.blast_radius_estimate is BlastRadius.LOW
    assert auto_event.guarantee.value == "downstream_idempotent"
    assert auto_event.post_verify.ran is False and auto_event.post_verify.result is None
    assert auto_event.run_id.startswith("run_")


def test_raising_event_sink_does_not_break_the_decision(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    """A best-effort sink that raises must NOT change control flow: the deny
    still raises ActionDenied, the auto still commits. The durable audit row is
    the record of truth (P2.2); a broken mirror sink cannot fail a decision."""

    class _BoomSink:
        def emit(self, event: Any) -> None:
            raise RuntimeError("sink is down")

    init(
        store=store,
        policy=Policy(
            rules=[Rule(match="refund.*", decision=Decision.AUTO)], default=Decision.DENY
        ),
        event_sinks=[_BoomSink()],
    )

    @guard("refund.robust", effect=Effect(key_param="idempotency_key"))
    def refund(invoice: str, *, idempotency_key: str | None = None) -> str:
        effects.log(invoice)
        return invoice

    @guard("deny.robust", reversibility=Reversibility.IRREVERSIBLE)
    def denied(x: int) -> int:
        return x

    # The raising sink surfaces as a warning, not a failure; the commit lands.
    with pytest.warns(UserWarning, match="EventSink"):
        assert refund("inv_robust") == "inv_robust"
    assert effects.count("inv_robust") == 1

    with pytest.warns(UserWarning, match="EventSink"), pytest.raises(ActionDenied):
        denied(1)
