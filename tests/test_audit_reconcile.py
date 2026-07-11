"""Reconciler evidence rides the chain (P2.2): recovered + escalation events.

PLAN.md 4.2 calls the reconciler's recovered/escalation records "audit
events" — as of P2.2 they are chained ``audit_events`` rows
(``event_type='reconcile'``): terminal recoveries carry their event INSIDE
the finalize transaction; escalations (no state change) are standalone
appends. FakeClock throughout (no sleeps); the chain verifies after every
scenario.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest
from sqlalchemy import text

from airlock.audit import verify_chain
from airlock.effects import Effect
from airlock.reconcile import OnAbsent, Outcome, reconcile
from airlock.registry import Registry
from airlock.types import Guarantee, LedgerState, Verification

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore
    from tests.conftest import FakeClock

pytestmark = pytest.mark.matrix

OLDER_THAN = timedelta(seconds=60)


def _reconcile_rows(db: Engine) -> list[dict[str, Any]]:
    with db.connect() as conn:
        rows = (
            conn.execute(
                text("SELECT * FROM audit_events WHERE event_type = 'reconcile' ORDER BY seq")
            )
            .mappings()
            .all()
        )
    import json as _json

    from airlock.store.sqlite import sqlite_text_to_dt

    out = []
    for row in rows:
        d = dict(row)
        if isinstance(d.get("payload_json"), str):
            d["payload_json"] = _json.loads(d["payload_json"])
        # SQLite stores created_at as TEXT; normalize to the tz-aware datetime
        # the tests compare against (Postgres TIMESTAMPTZ already yields one).
        if isinstance(d.get("created_at"), str):
            d["created_at"] = sqlite_text_to_dt(d["created_at"])
        out.append(d)
    return out


def _stage_executing(store: PostgresStore, key: str, action: str, guarantee: Guarantee) -> None:
    claim = store.claim(key, action, guarantee, {"invoice": key}, None)
    assert claim.won
    assert store.mark_executing(key, claim.record.attempts)


def test_recovered_present_probe_appends_chained_reconcile_event(
    clock_store: PostgresStore, db: Engine, fake_clock: FakeClock
) -> None:
    """Scenario 3 recovery (probe present -> committed): the terminal
    transition and its reconcile audit row land in ONE transaction."""
    action = "test.rec.present"
    _stage_executing(clock_store, "k-rec-1", action, Guarantee.VERIFIABLE)
    registry = Registry()
    registry.register(
        action,
        Effect(verify=lambda **_: (Verification.PRESENT, {"seen": True})),
        lambda dk, **_: {"never": "called"},
    )
    fake_clock.advance(120)
    report = reconcile(clock_store, older_than=OLDER_THAN, now_fn=fake_clock, registry=registry)
    assert report.count(Outcome.COMMITTED) == 1

    rows = _reconcile_rows(db)
    assert len(rows) == 1
    payload = rows[0]["payload_json"]
    assert payload["outcome"] == "committed"
    assert payload["from_state"] == "executing"
    assert payload["to_state"] == "committed"
    assert payload["key"] == "k-rec-1"
    assert payload["epoch"] == 2  # the bumped takeover epoch
    assert rows[0]["action_type"] == action
    # The hashed created_at is the FakeClock instant (SDK-supplied, PLAN 5.2):
    assert rows[0]["created_at"] == fake_clock()
    verify_chain(clock_store)


def test_escalation_appends_standalone_chained_event_and_leaves_row_executing(
    clock_store: PostgresStore, db: Engine, fake_clock: FakeClock
) -> None:
    """PLAN.md 4.2 "unknown -> leave, escalate via audit event": the
    escalation is a chained row even though no ledger state changed."""
    action = "test.rec.unknown"
    _stage_executing(clock_store, "k-rec-2", action, Guarantee.VERIFIABLE)
    registry = Registry()
    registry.register(
        action,
        Effect(verify=lambda **_: (Verification.UNKNOWN, {"why": "flaky downstream"})),
        lambda dk, **_: {"never": "called"},
    )
    fake_clock.advance(120)
    report = reconcile(clock_store, older_than=OLDER_THAN, now_fn=fake_clock, registry=registry)
    assert report.count(Outcome.ESCALATED) == 1

    rows = _reconcile_rows(db)
    assert len(rows) == 1
    payload = rows[0]["payload_json"]
    assert payload["outcome"] == "escalated"
    assert payload["to_state"] is None  # no transition happened
    assert "unknown" in payload["reason"]
    with db.connect() as conn:
        state = conn.execute(
            text("SELECT state FROM commit_records WHERE idempotency_key = 'k-rec-2'")
        ).scalar_one()
    assert state == LedgerState.EXECUTING.value
    verify_chain(clock_store)


def test_none_guarantee_unknown_finalize_carries_chained_event(
    clock_store: PostgresStore, db: Engine, fake_clock: FakeClock
) -> None:
    """Scenario 7: executing+none -> finalize('unknown') + loud audit — the
    loud audit is a chained row in the finalize transaction."""
    action = "test.rec.none"
    _stage_executing(clock_store, "k-rec-3", action, Guarantee.NONE)
    registry = Registry()
    registry.register(action, Effect(), lambda dk, **_: {"never": "called"})
    fake_clock.advance(120)
    report = reconcile(clock_store, older_than=OLDER_THAN, now_fn=fake_clock, registry=registry)
    assert report.count(Outcome.UNKNOWN) == 1

    rows = _reconcile_rows(db)
    assert len(rows) == 1
    payload = rows[0]["payload_json"]
    assert payload["outcome"] == "unknown"
    assert payload["to_state"] == "unknown"
    assert payload["guarantee"] == "none"
    verify_chain(clock_store)


def test_pending_retry_commit_appends_retried_committed_event(
    clock_store: PostgresStore, db: Engine, fake_clock: FakeClock
) -> None:
    """Scenario 4 shape: a stale pending row retried to completion carries a
    retried_committed reconcile event inside its finalize transaction."""
    action = "test.rec.retry"
    claim = clock_store.claim("k-rec-4", action, Guarantee.DOWNSTREAM_IDEMPOTENT, {"n": 1}, "dk-4")
    assert claim.won  # left PENDING: provably effect-free
    registry = Registry()
    registry.register(
        action,
        Effect(key_param="idempotency_key"),
        lambda dk, **_: {"refund_id": f"re_{dk}"},
    )
    fake_clock.advance(120)
    report = reconcile(
        clock_store,
        older_than=OLDER_THAN,
        on_absent=OnAbsent.RETRY,
        now_fn=fake_clock,
        registry=registry,
    )
    assert report.count(Outcome.RETRIED_COMMITTED) == 1

    rows = _reconcile_rows(db)
    assert len(rows) == 1
    payload = rows[0]["payload_json"]
    assert payload["outcome"] == "retried_committed"
    assert payload["from_state"] == "pending"
    assert payload["to_state"] == "committed"
    verify_chain(clock_store)


def test_abort_recovery_appends_aborted_event(
    clock_store: PostgresStore, db: Engine, fake_clock: FakeClock
) -> None:
    action = "test.rec.abort"
    claim = clock_store.claim("k-rec-5", action, Guarantee.VERIFIABLE, {"n": 1}, None)
    assert claim.won
    registry = Registry()
    registry.register(
        action,
        Effect(verify=lambda **_: (Verification.ABSENT, None)),
        lambda dk, **_: {"never": "called"},
    )
    fake_clock.advance(120)
    report = reconcile(
        clock_store,
        older_than=OLDER_THAN,
        on_absent=OnAbsent.ABORT,
        now_fn=fake_clock,
        registry=registry,
    )
    assert report.count(Outcome.ABORTED) == 1
    rows = _reconcile_rows(db)
    assert len(rows) == 1
    assert rows[0]["payload_json"]["outcome"] == "aborted"
    verify_chain(clock_store)


def test_mixed_sweep_keeps_one_linear_verifiable_chain(
    clock_store: PostgresStore, db: Engine, fake_clock: FakeClock
) -> None:
    """A sweep over several stale rows appends several chained events — the
    chain stays linear, gapless, and fully verifiable."""
    registry = Registry()
    for n, guarantee in enumerate(
        (Guarantee.VERIFIABLE, Guarantee.NONE, Guarantee.VERIFIABLE), start=1
    ):
        action = f"test.rec.mix{n}"
        _stage_executing(clock_store, f"k-mix-{n}", action, guarantee)
        registry.register(
            action,
            Effect(verify=lambda **_: (Verification.PRESENT, None))
            if guarantee is Guarantee.VERIFIABLE
            else Effect(),
            lambda dk, **_: {"n": 1},
        )
    fake_clock.advance(120)
    reconcile(clock_store, older_than=OLDER_THAN, now_fn=fake_clock, registry=registry)

    rows = _reconcile_rows(db)
    assert len(rows) == 3
    assert [row["seq"] for row in rows] == [1, 2, 3]
    report = verify_chain(clock_store)
    assert report.head_seq == 3


@pytest.mark.usefixtures("db")
def test_reconcile_event_type_constant() -> None:
    from airlock.reconcile import RECONCILE_EVENT_TYPE

    assert RECONCILE_EVENT_TYPE == "reconcile"
