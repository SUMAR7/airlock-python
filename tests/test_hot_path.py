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

    The DENY (and GATE) decision must be reached WITHOUT touching the store, so
    handing @guard this object and getting the decision anyway proves no
    data-plane I/O happened on the block path.
    """

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(
            f"the decision path touched the store ({name!r}) — a deny/gate decision "
            "must not perform any store I/O (PLAN.md 4.4)"
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
def test_guard_deny_path_no_socket_no_store() -> None:
    """@guard's DENY raises ActionDenied with no socket and no store access —
    the block happens purely in-process, before any ledger claim."""
    init(store=_ExplodingStore(), policy=_matrix_policy())

    executed: list[str] = []

    @guard("payout.wire", reversibility=Reversibility.IRREVERSIBLE)
    def do_payout(dest: str) -> dict[str, str]:
        executed.append(dest)  # must never run
        return {"sent": dest}

    with pytest.raises(ActionDenied) as excinfo:
        do_payout("acct_1")
    assert excinfo.value.action_type == "payout.wire"
    assert executed == []  # no side effect


@pytest.mark.usefixtures("no_network", "guard_isolation")
def test_guard_deny_before_any_ledger_write() -> None:
    """Deny raises before the store is even consulted — asserted by the
    exploding store staying untouched (any access would have raised its own
    AssertionError with a different message)."""
    init(store=_ExplodingStore(), policy=Policy(default=Decision.DENY))

    @guard("anything.here", reversibility=Reversibility.UNKNOWN)
    def tool(x: int) -> int:
        raise AssertionError("must not execute under deny")

    with pytest.raises(ActionDenied):
        tool(1)


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
