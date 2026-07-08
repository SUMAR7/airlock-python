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
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest

from airlock import guard, init
from airlock.errors import ActionDenied, ActionPending
from airlock.policy import ActionContext, Policy, Rule
from airlock.transport.console import ConsoleApprovalTransport
from airlock.types import (
    Decision,
    Money,
    PauseClaim,
    PausedRun,
    PauseStatus,
    Reversibility,
)

if TYPE_CHECKING:
    from pydantic import JsonValue


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


class _PausePersistingStore:
    """Allows the gate path's data-plane pause write, explodes on the ledger.

    As of P2.3 a GATE is NOT a pure decision: it persists a ``paused_runs`` row
    (data-plane I/O to the customer's own store — allowed, like AUTO's ledger
    writes; a gated action is already waiting on a human, PLAN.md 4.4). What it
    must NOT do before approval is claim/execute the LEDGER — so ``save_paused``
    is recorded but every ledger surface (``claim``/``mark_executing``/
    ``finalize``) explodes. No socket is opened either: the pause is local and
    the console transport is a stub.
    """

    def __init__(self) -> None:
        self.saved: list[str] = []

    def save_paused(
        self,
        *,
        run_id: str,
        idempotency_key: str,
        approval_ref: str,
        action_type: str,
        serialized_state: Mapping[str, JsonValue],
        state_version: int = 1,
        audit: Any = None,
    ) -> PauseClaim:
        self.saved.append(approval_ref)
        return PauseClaim(
            created=True,
            run=PausedRun(
                id=1,
                run_id=run_id,
                idempotency_key=idempotency_key,
                approval_ref=approval_ref,
                action_type=action_type,
                serialized_state=dict(serialized_state),
                state_version=state_version,
                status=PauseStatus.PROPOSED,
                created_at=datetime.now(UTC),
            ),
        )

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(
            f"the gate path touched the ledger surface ({name!r}) — a gated action "
            "persists a pause but must NOT claim/execute the ledger before approval"
        )


@pytest.mark.usefixtures("no_network", "guard_isolation")
def test_guard_gate_path_no_socket_persists_pause_only() -> None:
    """@guard's GATE persists a durable pause and surfaces ActionPending WITHOUT
    opening a socket and WITHOUT claiming the ledger: the side effect never runs,
    the pause is the only store write, and the stub transport touches no network
    (gate_wait=False, so no inline wait)."""
    store = _PausePersistingStore()
    init(
        store=store,
        policy=Policy(default=Decision.GATE),
        transport=ConsoleApprovalTransport("unused.jsonl"),
        gate_wait=False,
    )

    executed: list[int] = []

    @guard("gated.op", reversibility=Reversibility.IRREVERSIBLE)
    def do_gated(x: int) -> int:
        executed.append(x)  # must never run until approved
        return x

    with pytest.raises(ActionPending) as excinfo:
        do_gated(1)
    assert excinfo.value.run_id is not None  # the durable pause exists (P2.3)
    assert len(store.saved) == 1  # exactly one pause write; the ledger untouched
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
