"""The durable action_event emission matrix (P2.2, PLAN.md 6.3 / SPEC section 7).

For every guarded call: DENY appends the denied event at decision time, AUTO
appends the terminal event INSIDE the finalize transaction (committed /
aborted / failed), GATE appends nothing until its P2.3 terminal state.
Duplicate calls append nothing (events are per terminal TRANSITION). The
EventSink mirror receives the SAME object that was durably appended, and can
neither raise into nor block the guarded call. After everything, the chain
verifies — action events inherit chain integrity.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from sqlalchemy import text

from airlock import guard, init
from airlock.audit import verify_chain
from airlock.effects import Effect
from airlock.errors import ActionDenied, CommitFailed, GateNotSupported, PreconditionFailed
from airlock.events import ActionEvent
from airlock.policy import Policy, Rule
from airlock.types import Decision, Money, Reversibility, Verification

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore
    from tests.conftest import EffectsLog

pytestmark = pytest.mark.usefixtures("guard_isolation")


def USD(amount: str) -> Money:
    return Money(amount=amount, currency="USD")


class _RecordingSink:
    def __init__(self) -> None:
        self.events: list[ActionEvent] = []

    def emit(self, event: ActionEvent) -> None:
        self.events.append(event)


def _action_event_rows(db: Engine, action_type: str) -> list[dict[str, Any]]:
    with db.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT * FROM audit_events WHERE event_type = 'action_event'"
                    " AND action_type = :at ORDER BY seq"
                ),
                {"at": action_type},
            )
            .mappings()
            .all()
        )
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# AUTO -> committed.
# ---------------------------------------------------------------------------


def test_auto_committed_appends_one_chained_event_with_correct_fields(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    sink = _RecordingSink()
    init(store=store, policy=Policy(default=Decision.AUTO), event_sinks=[sink])

    @guard(
        "refund.audit",
        cost=USD("25"),
        reversibility=Reversibility.REVERSIBLE,
        effect=Effect(key_param="idempotency_key"),
    )
    def refund(invoice: str, *, idempotency_key: str | None = None) -> dict[str, str]:
        effects.log(invoice)
        return {"refunded": invoice}

    refund("inv_1")

    rows = _action_event_rows(db, "refund.audit")
    assert len(rows) == 1
    payload = rows[0]["payload_json"]
    assert payload["schema_version"] == 1
    assert payload["policy_decision"] == "auto"
    assert payload["outcome"] == "committed"
    assert payload["cost"] == {"amount": "25", "currency": "USD"}
    assert payload["reversibility"] == "reversible"
    assert payload["blast_radius_estimate"] is None
    assert payload["guarantee"] == "downstream_idempotent"
    assert payload["human_decision"] is None
    assert payload["decision_latency_ms"] is None
    assert payload["decided_by"] is None
    assert payload["action_diff"] is None
    assert payload["post_verify"] == {"ran": False, "result": None}
    assert len(payload["idempotency_key"]) == 64  # the derived ledger key
    # The audit row's envelope columns mirror the event:
    assert rows[0]["run_id"] == payload["run_id"]
    assert rows[0]["action_type"] == "refund.audit"

    # The sink mirrored the SAME object (identical payload incl. event_id):
    assert len(sink.events) == 1
    assert sink.events[0].to_payload() == payload

    verify_chain(store)


def test_auto_with_probe_records_post_verify_present(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    init(store=store, policy=Policy(default=Decision.AUTO))

    @guard(
        "refund.probed",
        reversibility=Reversibility.REVERSIBLE,
        effect=Effect(verify=lambda **_: (Verification.PRESENT, {"seen": True})),
    )
    def refund(invoice: str) -> str:
        effects.log(invoice)
        return invoice

    refund("inv_p")
    rows = _action_event_rows(db, "refund.probed")
    assert len(rows) == 1
    payload = rows[0]["payload_json"]
    assert payload["outcome"] == "committed"
    assert payload["guarantee"] == "verifiable"
    assert payload["post_verify"] == {"ran": True, "result": "present"}
    verify_chain(store)


def test_duplicate_auto_call_appends_no_second_event(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    """Events are per terminal TRANSITION: the duplicate reads back the
    recorded outcome and appends nothing (and mirrors nothing)."""
    sink = _RecordingSink()
    init(store=store, policy=Policy(default=Decision.AUTO), event_sinks=[sink])

    @guard("refund.dup", effect=Effect(key_param="idempotency_key"))
    def refund(invoice: str, *, idempotency_key: str | None = None) -> str:
        effects.log(invoice)
        return invoice

    refund("inv_d")
    refund("inv_d")  # duplicate: dedupes against the ledger
    assert effects.count("inv_d") == 1
    assert len(_action_event_rows(db, "refund.dup")) == 1
    assert len(sink.events) == 1
    verify_chain(store)


# ---------------------------------------------------------------------------
# AUTO -> aborted / failed.
# ---------------------------------------------------------------------------


def test_precondition_abort_appends_aborted_event_atomically(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    init(store=store, policy=Policy(default=Decision.AUTO))

    @guard(
        "refund.abort",
        effect=Effect(key_param="idempotency_key"),
        preconditions=lambda invoice, **_: invoice != "blocked",
    )
    def refund(invoice: str, *, idempotency_key: str | None = None) -> str:
        effects.log(invoice)
        return invoice

    with pytest.raises(PreconditionFailed):
        refund("blocked")
    rows = _action_event_rows(db, "refund.abort")
    assert len(rows) == 1
    payload = rows[0]["payload_json"]
    assert payload["outcome"] == "aborted"
    assert payload["post_verify"] == {"ran": False, "result": None}
    assert effects.count("blocked") == 0
    verify_chain(store)


def test_post_verify_absent_appends_failed_event(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    init(store=store, policy=Policy(default=Decision.AUTO))

    @guard(
        "refund.absent",
        reversibility=Reversibility.REVERSIBLE,
        effect=Effect(verify=lambda **_: (Verification.ABSENT, {"checked": True})),
    )
    def refund(invoice: str) -> str:
        effects.log(invoice)
        return invoice

    with pytest.raises(CommitFailed):
        refund("inv_a")
    rows = _action_event_rows(db, "refund.absent")
    assert len(rows) == 1
    payload = rows[0]["payload_json"]
    assert payload["outcome"] == "failed"
    assert payload["post_verify"] == {"ran": True, "result": "absent"}
    verify_chain(store)


def test_verification_unknown_appends_no_event(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    """No terminal state -> no event (nothing to evidence yet; the row stays
    'executing' for the reconciler, whose own resolution will carry events)."""
    from airlock.errors import VerificationUnknown

    init(store=store, policy=Policy(default=Decision.AUTO))

    @guard(
        "refund.unknown",
        reversibility=Reversibility.REVERSIBLE,
        effect=Effect(verify=lambda **_: (Verification.UNKNOWN, None)),
    )
    def refund(invoice: str) -> str:
        effects.log(invoice)
        return invoice

    with pytest.raises(VerificationUnknown):
        refund("inv_u")
    assert _action_event_rows(db, "refund.unknown") == []
    verify_chain(store)


# ---------------------------------------------------------------------------
# DENY / GATE.
# ---------------------------------------------------------------------------


def test_deny_appends_denied_event_durably(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    sink = _RecordingSink()
    init(
        store=store,
        policy=Policy(rules=[Rule(match="payout.*", decision=Decision.DENY)]),
        event_sinks=[sink],
    )

    @guard("payout.audit", cost=USD("9000"), reversibility=Reversibility.IRREVERSIBLE)
    def payout(dest: str) -> str:
        effects.log(dest)
        return dest

    with pytest.raises(ActionDenied):
        payout("acct_1")
    rows = _action_event_rows(db, "payout.audit")
    assert len(rows) == 1
    payload = rows[0]["payload_json"]
    assert payload["policy_decision"] == "deny"
    assert payload["outcome"] == "denied"
    assert payload["cost"] == {"amount": "9000", "currency": "USD"}
    assert payload["post_verify"] == {"ran": False, "result": None}
    assert effects.count("acct_1") == 0
    # No ledger row was ever claimed for the denied call:
    with db.connect() as conn:
        claimed = conn.execute(
            text("SELECT count(*) FROM commit_records WHERE action_type = 'payout.audit'")
        ).scalar_one()
    assert claimed == 0
    # The sink mirrored the same object:
    assert len(sink.events) == 1
    assert sink.events[0].to_payload() == payload
    verify_chain(store)


def test_every_denied_call_gets_its_own_event(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    """Each denied call is its own decision-time block (unlike terminal
    transitions, which happen once per ledger row)."""
    init(store=store, policy=Policy(default=Decision.DENY))

    @guard("payout.every", reversibility=Reversibility.IRREVERSIBLE)
    def payout(dest: str) -> str:
        return dest

    for _ in range(3):
        with pytest.raises(ActionDenied):
            payout("acct_2")
    assert len(_action_event_rows(db, "payout.every")) == 3
    verify_chain(store)


def test_deny_with_broken_audit_store_still_denies_loudly(
    store: PostgresStore, db: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail-safe posture: if the durable append fails, the deny STILL raises
    ActionDenied (the block can only stand), and the failure is loud — a
    warning plus a note on the raised error. Never a silent record loss."""
    init(store=store, policy=Policy(default=Decision.DENY))

    def broken_append(event: object) -> object:
        raise RuntimeError("audit store down")

    monkeypatch.setattr(store, "append_audit", broken_append)

    @guard("payout.broken", reversibility=Reversibility.IRREVERSIBLE)
    def payout(dest: str) -> str:
        return dest

    with (
        pytest.warns(UserWarning, match="deny audit append"),
        pytest.raises(ActionDenied) as excinfo,
    ):
        payout("acct_3")
    assert any("audit append failed" in note for note in getattr(excinfo.value, "__notes__", []))


def test_gate_appends_nothing_in_p22(store: PostgresStore, db: Engine) -> None:
    """GATE has no terminal state until P2.3 — no audit row, no mirror
    (airlock.events: emitting a fabricated decision-time event would
    double-count the call once the pause layer lands)."""
    sink = _RecordingSink()
    init(store=store, policy=Policy(default=Decision.GATE), event_sinks=[sink])

    @guard("gated.audit", reversibility=Reversibility.UNKNOWN)
    def gated(x: int) -> int:
        return x

    with pytest.raises(GateNotSupported):
        gated(1)
    assert _action_event_rows(db, "gated.audit") == []
    assert sink.events == []
    verify_chain(store)


# ---------------------------------------------------------------------------
# The sink mirror never raises into or blocks the call.
# ---------------------------------------------------------------------------


def test_raising_sink_cannot_perturb_the_committed_outcome(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    class _Boom:
        def emit(self, event: ActionEvent) -> None:
            raise RuntimeError("mirror down")

    init(store=store, policy=Policy(default=Decision.AUTO), event_sinks=[_Boom()])

    @guard("refund.mirror", effect=Effect(key_param="idempotency_key"))
    def refund(invoice: str, *, idempotency_key: str | None = None) -> str:
        effects.log(invoice)
        return invoice

    with pytest.warns(UserWarning, match="EventSink"):
        assert refund("inv_m") == "inv_m"
    assert effects.count("inv_m") == 1
    # The durable record landed regardless of the broken mirror:
    assert len(_action_event_rows(db, "refund.mirror")) == 1
    verify_chain(store)


def test_mirror_fires_only_after_the_durable_transition(
    store: PostgresStore, effects: EffectsLog, db: Engine
) -> None:
    """Ordering: when the sink observes the event, the audit row and the
    terminal ledger state are ALREADY durable — the mirror can never run ahead
    of (or instead of) the record of truth."""
    observed: list[tuple[int, str]] = []

    class _Observer:
        def emit(self, event: ActionEvent) -> None:
            with db.connect() as conn:
                count = conn.execute(
                    text(
                        "SELECT count(*) FROM audit_events WHERE event_type = 'action_event'"
                        " AND action_type = 'refund.order'"
                    )
                ).scalar_one()
                state = conn.execute(
                    text("SELECT state FROM commit_records WHERE action_type = 'refund.order'")
                ).scalar_one()
            observed.append((count, str(state)))

    init(store=store, policy=Policy(default=Decision.AUTO), event_sinks=[_Observer()])

    @guard("refund.order", effect=Effect(key_param="idempotency_key"))
    def refund(invoice: str, *, idempotency_key: str | None = None) -> str:
        effects.log(invoice)
        return invoice

    refund("inv_o")
    assert observed == [(1, "committed")]
