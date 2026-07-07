"""THE HOT-PATH TEST (SPEC.md 3 / ADR-3 / PLAN.md 4.4) — the hard constraint.

The auto/deny DECISION must be pure, in-process, and do ZERO I/O of any kind:
no socket is created, and the decision layer is evaluable with only the core
dependency (pydantic) imported — sqlalchemy/httpx are NOT imported at decision
time. ~95% of guarded calls decide here and never leave the customer's process;
a single socket or a heavy-dep import on this path violates the prime rule.

This suite is the mechanical guard on that rule:

- ``policy.evaluate`` performs no network I/O (socket creation is booby-trapped
  to raise; evaluation must not trip it), for auto AND deny AND gate verdicts.
- ``@guard``'s DENY path raises ``ActionDenied`` without any socket AND without
  touching the store (the store is a sentinel that explodes on any access).
- the policy layer imports and evaluates in a subprocess that has NOT imported
  sqlalchemy or httpx — proving the decision is reachable with core deps only.

No database fixture is used here on purpose: the whole point is that the
decision needs none.
"""

from __future__ import annotations

import socket
import subprocess
import sys
from typing import Any

import pytest

from airlock import guard, init
from airlock.errors import ActionDenied
from airlock.policy import ActionContext, Policy, Rule
from airlock.types import Decision, Money, Reversibility


class _NoSocketAllowed:
    """A ``socket.socket`` replacement that fails if anything opens a socket."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise AssertionError(
            "the auto/deny decision path opened a socket — the hot-path rule "
            "(SPEC.md 3) forbids ANY network I/O on the policy decision"
        )


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Booby-trap socket creation: any socket() call under this fixture fails."""
    monkeypatch.setattr(socket, "socket", _NoSocketAllowed)


class _ExplodingStore:
    """A store sentinel: ANY attribute access is a hot-path violation.

    The GATE decision must be reached WITHOUT touching the store, so handing
    @guard this object and getting the decision anyway proves no data-plane
    I/O happened on the block path. (DENY is different as of P2.2: after the
    pure decision it performs exactly ONE local audit append — PLAN.md 4.4
    "DENY = decision + one local audit append" — see _DenyAuditOnlyStore.)
    """

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(
            f"the decision path touched the store ({name!r}) — this decision "
            "must not perform any store I/O (PLAN.md 4.4)"
        )


class _DenyAuditOnlyStore:
    """A store allowing exactly the deny path's sanctioned I/O: append_audit.

    Every OTHER store surface (claim/mark_executing/finalize/...) explodes —
    proving the deny path never claims a ledger row, never executes, and its
    only store touch is the one local audit append PLAN.md 4.4 sanctions.
    """

    def __init__(self) -> None:
        self.appended: list[Any] = []

    def append_audit(self, event: Any) -> Any:
        self.appended.append(event)
        return None  # @guard ignores the returned AuditRow

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(
            f"the deny path touched the store beyond append_audit ({name!r}) — "
            "DENY is the pure decision + ONE local audit append (PLAN.md 4.4), "
            "never a ledger claim or execute"
        )


def _matrix_policy() -> Policy:
    return Policy(
        rules=[
            Rule(
                match="refund.*",
                decision=Decision.AUTO,
                max_cost=Money(amount="100", currency="USD"),
                reversibility_in=frozenset({Reversibility.REVERSIBLE}),
            ),
            Rule(match="payout.*", decision=Decision.DENY),
        ],
        default=Decision.GATE,
    )


@pytest.mark.usefixtures("no_network")
def test_policy_evaluate_opens_no_socket() -> None:
    """Every verdict (auto/gate/deny) is computed with zero network I/O."""
    policy = _matrix_policy()
    auto = ActionContext(
        action_type="refund.create",
        reversibility=Reversibility.REVERSIBLE,
        cost=Money(amount="10", currency="USD"),
    )
    deny = ActionContext(action_type="payout.wire", reversibility=Reversibility.IRREVERSIBLE)
    gate = ActionContext(action_type="unknown.thing", reversibility=Reversibility.UNKNOWN)
    assert policy.evaluate(auto) is Decision.AUTO
    assert policy.evaluate(deny) is Decision.DENY
    assert policy.evaluate(gate) is Decision.GATE


@pytest.mark.usefixtures("no_network", "guard_isolation")
def test_guard_deny_path_no_socket_one_audit_append_only() -> None:
    """@guard's DENY raises ActionDenied with no socket and exactly ONE store
    touch — the local audit append (PLAN.md 4.4: "DENY = decision + one local
    audit append"). No ledger claim, no execute, nothing else."""
    store = _DenyAuditOnlyStore()
    init(store=store, policy=_matrix_policy())

    executed: list[str] = []

    @guard("payout.wire", reversibility=Reversibility.IRREVERSIBLE)
    def do_payout(dest: str) -> dict[str, str]:
        executed.append(dest)  # must never run
        return {"sent": dest}

    with pytest.raises(ActionDenied) as excinfo:
        do_payout("acct_1")
    assert excinfo.value.action_type == "payout.wire"
    assert executed == []  # no side effect
    # Exactly one append, and it is the denied action_event.
    assert len(store.appended) == 1
    appended = store.appended[0]
    assert appended.event_type == "action_event"
    assert appended.payload["outcome"] == "denied"
    assert appended.payload["policy_decision"] == "deny"
    assert appended.payload["action_type"] == "payout.wire"


@pytest.mark.usefixtures("no_network", "guard_isolation")
def test_guard_gate_path_no_socket_no_store() -> None:
    """@guard's GATE fail-safe surfaces without a socket and without touching the
    store: the side effect never runs, and the block is reached purely
    in-process (no paused_runs is built in P2.1, so no store write happens)."""
    from airlock.errors import ActionPending, GateNotSupported

    init(store=_ExplodingStore(), policy=Policy(default=Decision.GATE))

    executed: list[int] = []

    @guard("gated.op", reversibility=Reversibility.IRREVERSIBLE)
    def do_gated(x: int) -> int:
        executed.append(x)  # must never run
        return x

    with pytest.raises(GateNotSupported) as excinfo:
        do_gated(1)
    assert isinstance(excinfo.value, ActionPending)
    assert excinfo.value.run_id is None  # no paused_runs row (P2.1)
    assert executed == []  # no side effect


@pytest.mark.usefixtures("no_network", "guard_isolation")
def test_guard_deny_before_any_ledger_write() -> None:
    """Deny never touches the ledger surface — the only store call is the
    audit append; any claim/mark/finalize on the deny path would explode the
    _DenyAuditOnlyStore with its own AssertionError."""
    store = _DenyAuditOnlyStore()
    init(store=store, policy=Policy(default=Decision.DENY))

    @guard("anything.here", reversibility=Reversibility.UNKNOWN)
    def tool(x: int) -> int:
        raise AssertionError("must not execute under deny")

    with pytest.raises(ActionDenied):
        tool(1)
    assert len(store.appended) == 1  # the deny record — and nothing else


def test_decision_layer_evaluable_with_core_deps_only() -> None:
    """In a FRESH interpreter, importing + evaluating the policy layer must not
    pull sqlalchemy or httpx: the decision is reachable with core deps only
    (PLAN.md P2.1 DoD: 'evaluable with only the core deps imported')."""
    code = (
        "import sys\n"
        "from airlock.policy import ActionContext, Policy, Rule\n"
        "from airlock.types import Decision, Reversibility, Money, BlastRadius\n"
        "policy = Policy(rules=[Rule(match='refund.*', decision=Decision.AUTO,\n"
        "    max_cost=Money(amount='100', currency='USD'))], default=Decision.GATE)\n"
        "ctx = ActionContext(action_type='refund.create', reversibility=Reversibility.REVERSIBLE,\n"
        "    cost=Money(amount='10', currency='USD'))\n"
        "assert policy.evaluate(ctx) is Decision.AUTO\n"
        "gate_ctx = ActionContext(action_type='x', reversibility=Reversibility.UNKNOWN)\n"
        "assert policy.evaluate(gate_ctx) is Decision.GATE\n"
        "assert 'sqlalchemy' not in sys.modules, 'sqlalchemy imported at decision time'\n"
        "assert 'httpx' not in sys.modules, 'httpx imported at decision time'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, f"decision layer needed a heavy dep:\n{result.stderr}"


def test_guard_module_import_stays_light() -> None:
    """Importing airlock._guard (the decorator + runtime) must not import
    sqlalchemy/httpx: commit_once is imported LAZILY on the AUTO path only, so
    decorating + a deny/gate decision never pulls the extras."""
    code = (
        "import sys\n"
        "import airlock._guard\n"
        "import airlock.policy\n"
        "import airlock.events\n"
        "assert 'sqlalchemy' not in sys.modules, 'sqlalchemy leaked via airlock._guard'\n"
        "assert 'httpx' not in sys.modules, 'httpx leaked via airlock._guard'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, f"guard import pulled a heavy dep:\n{result.stderr}"
