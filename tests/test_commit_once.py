"""commit_once semantics: scenario 1, transaction boundaries, fences, waiting.

Synchronization rules (SPEC.md section 9 / PLAN.md section 7): no time.sleep in
test bodies — commit_once's internal poll_interval is implementation, not test
timing; where these tests need "later", they drive the ledger directly.
"""

from __future__ import annotations

import pytest
from pydantic import JsonValue
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from airlock.commit import commit_once
from airlock.effects import Effect
from airlock.errors import CommitWaitTimeout
from airlock.store.postgres import PostgresStore, normalize_postgres_url
from airlock.types import Guarantee, LedgerState, Verification
from tests.conftest import EffectsLog, bump_epoch

ARGS = {"invoice": "inv_42", "amount": "12.50"}


def _probe_present(**_: object) -> tuple[Verification, None]:
    """A probe that always confirms the effect (guarantee: verifiable)."""
    return Verification.PRESENT, None


#: A verifiable effect whose probe always answers `present` — the P1.2 stand-in
#: for the P1.1 tests that stamped Guarantee.VERIFIABLE without a probe.
VERIFIABLE_EFFECT = Effect(verify=_probe_present)

#: Neither idempotent nor verifiable — at-most-once mode (warned once per
#: action_type per process; these tests reuse shared action types on purpose).
OPAQUE_EFFECT = Effect()


def _ledger_row_count(db: Engine) -> int:
    with db.connect() as conn:
        found = conn.execute(text("SELECT count(*) FROM commit_records")).scalar_one()
    return int(found)


def test_scenario_1_sequential_duplicate_returns_first_result(
    store: PostgresStore, db: Engine, effects: EffectsLog
) -> None:
    """SPEC.md section 5, row 1: retry sees the ledger conflict, returns the
    first result — one side effect, one ledger row."""
    key = "scenario-1"
    calls = 0

    def execute(downstream_key: str | None) -> JsonValue:
        nonlocal calls
        calls += 1
        effects.log(key)
        return {"refund_id": 1}

    first = commit_once(
        store,
        key=key,
        action_type="refund.create",
        execute=execute,
        effect=VERIFIABLE_EFFECT,
        args_json=ARGS,
    )
    second = commit_once(
        store,
        key=key,
        action_type="refund.create",
        execute=execute,
        effect=VERIFIABLE_EFFECT,
        args_json=ARGS,
    )

    assert first.state is LedgerState.COMMITTED
    assert first.result == {"refund_id": 1}
    assert first.guarantee is Guarantee.VERIFIABLE
    assert second.state is LedgerState.COMMITTED
    assert second.result == first.result
    assert second.guarantee is Guarantee.VERIFIABLE
    assert calls == 1
    assert effects.count(key) == 1
    assert _ledger_row_count(db) == 1


def test_downstream_key_defaults_to_ledger_key(store: PostgresStore, db: Engine) -> None:
    """PLAN 3.4: with key_param set and no map_key, the downstream key IS the
    ledger key — execute receives it and the row stores it."""
    outcome = commit_once(
        store,
        key="k-downstream",
        action_type="refund.create",
        execute=lambda downstream_key: {"got": downstream_key},
        effect=Effect(key_param="idempotency_key"),
        args_json=ARGS,
    )
    assert outcome.result == {"got": "k-downstream"}
    assert outcome.guarantee is Guarantee.DOWNSTREAM_IDEMPOTENT
    loaded = store.load("k-downstream")
    assert loaded is not None
    assert loaded.downstream_key == "k-downstream"
    assert loaded.guarantee is Guarantee.DOWNSTREAM_IDEMPOTENT


def test_execute_raise_leaves_durable_executing_row(
    store: PostgresStore, database_url: str, db: Engine
) -> None:
    """Transaction-boundary proof: the claim and the executing-mark each
    committed in their own transaction BEFORE execute ran — a fresh
    connection sees 'executing' while execute is still on the stack, and the
    error lands durably with the row still 'executing' (the reconciler's
    honest input: effect status unknown)."""
    key = "k-boom"
    fresh_engine = create_engine(normalize_postgres_url(database_url))
    seen_mid_execute: list[str] = []

    def execute(downstream_key: str | None) -> None:
        # A FRESH connection (not the store's pool) observes the row.
        with fresh_engine.connect() as conn:
            state = conn.execute(
                text("SELECT state FROM commit_records WHERE idempotency_key = :key"),
                {"key": key},
            ).scalar_one()
        seen_mid_execute.append(str(state))
        raise RuntimeError("downstream exploded")

    with pytest.raises(RuntimeError, match="downstream exploded"):
        commit_once(
            store,
            key=key,
            action_type="refund.create",
            execute=execute,
            effect=OPAQUE_EFFECT,
            args_json=ARGS,
        )

    # Mid-execute, the executing marker was already durable.
    assert seen_mid_execute == [LedgerState.EXECUTING.value]

    # After the raise: still 'executing' (no lying terminal state), error recorded.
    with fresh_engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT state, error_json, result_json, committed_at FROM commit_records"
                " WHERE idempotency_key = :key"
            ),
            {"key": key},
        ).one()
    fresh_engine.dispose()
    assert row.state == LedgerState.EXECUTING.value
    assert row.error_json == {"type": "RuntimeError", "message": "downstream exploded"}
    assert row.result_json is None
    assert row.committed_at is None


def test_execute_exception_survives_failed_evidence_write(database_url: str, db: Engine) -> None:
    """If the evidence write itself raises (ledger connection drops at exactly
    the moment the tool blew up), the TOOL's original exception must still
    propagate — an infrastructure error from Airlock would be the wrong signal
    for the caller — and the row stays 'executing' for the reconciler."""

    class EvidenceWriteBoom(PostgresStore):
        def record_error(self, key: str, epoch: int, error_json: JsonValue) -> bool:
            raise ConnectionError("ledger connection dropped during evidence write")

    key = "k-evidence-boom"
    store = EvidenceWriteBoom(database_url)

    def execute(downstream_key: str | None) -> None:
        raise RuntimeError("downstream exploded")

    try:
        with pytest.raises(RuntimeError, match="downstream exploded") as excinfo:
            commit_once(
                store,
                key=key,
                action_type="refund.create",
                execute=execute,
                effect=OPAQUE_EFFECT,
                args_json=ARGS,
            )
        # The secondary failure is attached as a note, not raised in its place.
        notes = getattr(excinfo.value, "__notes__", [])
        assert any("error_json" in note for note in notes), notes

        loaded = store.load(key)
        assert loaded is not None
        assert loaded.state is LedgerState.EXECUTING  # honest: status unknown
        assert loaded.error_json is None  # the evidence write never landed
    finally:
        store.close()


def test_precondition_violation_finalizes_aborted(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """PLAN.md 4.1 step 2: preconditions re-validated after the claim;
    violation aborts without executing."""
    key = "k-precond"

    def execute(downstream_key: str | None) -> None:
        effects.log(key)
        raise AssertionError("must not execute")

    outcome = commit_once(
        store,
        key=key,
        action_type="refund.create",
        execute=execute,
        preconditions=lambda: False,
        effect=OPAQUE_EFFECT,
        args_json=ARGS,
    )
    assert outcome.state is LedgerState.ABORTED
    assert effects.count(key) == 0
    loaded = store.load(key)
    assert loaded is not None
    assert loaded.state is LedgerState.ABORTED

    # A duplicate call returns the recorded abort — no second precondition run.
    duplicate = commit_once(
        store,
        key=key,
        action_type="refund.create",
        execute=execute,
        preconditions=lambda: True,
        effect=OPAQUE_EFFECT,
        args_json=ARGS,
    )
    assert duplicate.state is LedgerState.ABORTED
    assert effects.count(key) == 0


def test_loser_on_stale_inflight_row_times_out_naming_reconciler(
    store: PostgresStore, effects: EffectsLog
) -> None:
    """A loser stuck behind an in-flight row raises the wait-timeout error and
    NEVER re-executes; the message points at the P1.3 reconciler."""
    key = "k-stale"
    # An in-flight row whose owner will never finish (owner crashed, say).
    store.claim(key, "refund.create", Guarantee.NONE, ARGS, None)
    assert store.mark_executing(key, 1)

    def execute(downstream_key: str | None) -> None:
        effects.log(key)
        raise AssertionError("loser must never execute")

    with pytest.raises(CommitWaitTimeout, match="reconcile") as excinfo:
        commit_once(
            store,
            key=key,
            action_type="refund.create",
            execute=execute,
            effect=OPAQUE_EFFECT,
            args_json=ARGS,
            wait_timeout=0.3,
            poll_interval=0.02,
        )
    assert excinfo.value.key == key
    assert excinfo.value.last_state is LedgerState.EXECUTING
    assert effects.count(key) == 0
    loaded = store.load(key)
    assert loaded is not None
    assert loaded.state is LedgerState.EXECUTING  # untouched by the loser


def test_loser_with_wait_false_raises_immediately(store: PostgresStore) -> None:
    key = "k-nowait"
    store.claim(key, "refund.create", Guarantee.NONE, ARGS, None)

    with pytest.raises(CommitWaitTimeout, match="wait=False"):
        commit_once(
            store,
            key=key,
            action_type="refund.create",
            execute=lambda dk: pytest.fail("must not execute"),
            effect=OPAQUE_EFFECT,
            args_json=ARGS,
            wait=False,
        )


def test_loser_returns_terminal_outcome_even_with_wait_false(store: PostgresStore) -> None:
    key = "k-terminal-nowait"
    store.claim(key, "refund.create", Guarantee.NONE, ARGS, None)
    assert store.mark_executing(key, 1)
    assert store.finalize(key, 1, LedgerState.COMMITTED, {"refund_id": 9}, None)

    outcome = commit_once(
        store,
        key=key,
        action_type="refund.create",
        execute=lambda dk: pytest.fail("must not execute"),
        effect=OPAQUE_EFFECT,
        args_json=ARGS,
        wait=False,
    )
    assert outcome.state is LedgerState.COMMITTED
    assert outcome.result == {"refund_id": 9}


def test_epoch_fence_before_executing_mark_means_no_execute(
    store: PostgresStore, db: Engine, effects: EffectsLog
) -> None:
    """External takeover between claim and executing-mark: commit_once treats
    the fenced CAS as a lost claim — no execute, no override."""
    key = "k-fence-mark"

    def preconditions() -> bool:
        bump_epoch(db, key)  # takeover lands while we validate
        return True

    def execute(downstream_key: str | None) -> None:
        effects.log(key)
        raise AssertionError("fenced owner must not execute")

    with pytest.raises(CommitWaitTimeout):
        commit_once(
            store,
            key=key,
            action_type="refund.create",
            execute=execute,
            preconditions=preconditions,
            effect=OPAQUE_EFFECT,
            args_json=ARGS,
            wait=False,
        )
    assert effects.count(key) == 0
    loaded = store.load(key)
    assert loaded is not None
    assert loaded.state is LedgerState.PENDING  # fenced mark wrote nothing
    assert loaded.attempts == 2


def test_epoch_fence_at_finalize_means_no_override(
    store: PostgresStore, db: Engine, effects: EffectsLog
) -> None:
    """External takeover mid-execute: the fenced finalize must not override —
    the reconciler owns resolution (PLAN.md 4.1 step 6)."""
    key = "k-fence-finalize"

    def execute(downstream_key: str | None) -> JsonValue:
        effects.log(key)
        bump_epoch(db, key)  # takeover lands while the effect runs
        return {"executed": True}

    with pytest.raises(CommitWaitTimeout):
        commit_once(
            store,
            key=key,
            action_type="refund.create",
            execute=execute,
            effect=OPAQUE_EFFECT,
            args_json=ARGS,
            wait=False,
        )
    assert effects.count(key) == 1  # the effect did run, exactly once
    loaded = store.load(key)
    assert loaded is not None
    assert loaded.state is LedgerState.EXECUTING  # NOT committed by the fenced owner
    assert loaded.result_json is None
    assert loaded.committed_at is None
    assert loaded.attempts == 2


def test_precondition_fence_falls_back_to_waiting(store: PostgresStore, db: Engine) -> None:
    """Fenced abort-finalize: the takeover's resolution wins; the caller reads it."""
    key = "k-fence-abort"

    def preconditions() -> bool:
        bump_epoch(db, key)
        # The takeover resolves the row before we try to abort it.
        assert store.finalize(key, 2, LedgerState.ABORTED, None, None)
        return False

    outcome = commit_once(
        store,
        key=key,
        action_type="refund.create",
        execute=lambda dk: pytest.fail("must not execute"),
        preconditions=preconditions,
        effect=OPAQUE_EFFECT,
        args_json=ARGS,
        wait=False,
    )
    assert outcome.state is LedgerState.ABORTED


def test_rejects_nonpositive_timeouts(store: PostgresStore) -> None:
    for kwargs in ({"wait_timeout": 0.0}, {"poll_interval": -1.0}):
        with pytest.raises(ValueError, match="must be > 0"):
            commit_once(
                store,
                key="k-validate",
                action_type="a.b",
                execute=lambda dk: None,
                effect=OPAQUE_EFFECT,
                args_json={},
                **kwargs,  # type: ignore[arg-type]
            )
