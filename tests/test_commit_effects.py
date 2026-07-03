"""P1.2 commit_once integration: passthrough, post-verify, degradation.

- Passthrough (SPEC.md section 9 mandate): the derived ledger key reaches a
  ``FakeStripe`` double via ``key_param``, post-``map_key``, and the stored
  ``commit_records.downstream_key`` is EXACTLY the value sent downstream.
- Post-verify (PLAN.md 4.1 step 5): present commits; absent lands ``failed``
  with durable evidence; unknown leaves the row ``executing`` durably and
  raises the documented error.
- At-most-once degradation (SPEC.md section 5, scenario 7): loud warning
  once per action type, caller-visible guarantee, durable ledger stamp.

Durability assertions read through a FRESH engine (never the store's pool);
ground truth for side effects is the ``effects_log`` autocommit table.
"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import JsonValue
from sqlalchemy import create_engine, text

from airlock.commit import commit_once
from airlock.effects import Effect
from airlock.errors import AtMostOnceWarning, CommitWaitTimeout, VerificationUnknown
from airlock.idempotency import derive_key
from airlock.store.postgres import PostgresStore, normalize_postgres_url
from airlock.types import Guarantee, LedgerState, Verification
from tests.conftest import EffectsLog

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy.engine import Engine

ACTION = "refund.create"
ARGS = {"invoice": "inv_42", "amount": "12.50", "currency": "EUR"}


class FakeStripe:
    """Test double for a downstream that dedupes on idempotency keys.

    Records every received key (``requests``) and returns the FIRST response
    for a repeated key without re-executing — exactly the Stripe contract
    that makes ``Guarantee.DOWNSTREAM_IDEMPOTENT`` true.
    """

    def __init__(self, effects: EffectsLog) -> None:
        self._effects = effects
        self.requests: list[str] = []
        self._responses: dict[str, dict[str, Any]] = {}
        self._seq = 0

    def refund(self, *, idempotency_key: str, amount: str) -> dict[str, Any]:
        self.requests.append(idempotency_key)
        if idempotency_key in self._responses:
            return self._responses[idempotency_key]  # deduped: no new effect
        self._seq += 1
        self._effects.log(idempotency_key)  # the real-world side effect
        response = {"refund_id": f"re_{self._seq}", "amount": amount}
        self._responses[idempotency_key] = response
        return response


@pytest.fixture
def fresh_engine(database_url: str) -> Iterator[Engine]:
    """A fresh engine, NOT the store's pool — durability reads only."""
    engine = create_engine(normalize_postgres_url(database_url))
    yield engine
    engine.dispose()


def _row(fresh_engine: Engine, key: str) -> Any:
    with fresh_engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT state, guarantee, downstream_key, result_json, error_json,"
                " committed_at FROM commit_records WHERE idempotency_key = :key"
            ),
            {"key": key},
        ).one()


# ---------------------------------------------------------------------------
# Downstream passthrough (FakeStripe)
# ---------------------------------------------------------------------------


def test_passthrough_one_key_two_layers_of_dedup(
    store: PostgresStore, effects: EffectsLog, fresh_engine: Engine
) -> None:
    """SPEC section 9: the key FakeStripe receives == commit_records.downstream_key
    == map_key(derived ledger key); a second commit_once with the same ledger
    key never even reaches FakeStripe — the ledger dedupes first."""
    fake = FakeStripe(effects)
    ledger_key = derive_key(ACTION, ARGS)

    def map_key(key: str) -> str:
        return f"stripe-{key[:24]}"  # downstream length limit

    effect = Effect(key_param="idempotency_key", map_key=map_key)

    def execute(downstream_key: str | None) -> dict[str, Any]:
        assert downstream_key is not None
        return fake.refund(idempotency_key=downstream_key, amount=ARGS["amount"])

    first = commit_once(
        store,
        key=ledger_key,
        action_type=ACTION,
        execute=execute,
        effect=effect,
        args_json=ARGS,
    )

    expected_downstream = map_key(ledger_key)
    assert first.state is LedgerState.COMMITTED
    assert first.guarantee is Guarantee.DOWNSTREAM_IDEMPOTENT
    # The key received downstream, byte for byte:
    assert fake.requests == [expected_downstream]
    # ... is exactly what the ledger row stores (probe/reconciler contract):
    row = _row(fresh_engine, ledger_key)
    assert row.downstream_key == expected_downstream
    assert row.guarantee == Guarantee.DOWNSTREAM_IDEMPOTENT.value
    assert effects.count(expected_downstream) == 1

    # Second commit_once, same ledger key: deduped BEFORE FakeStripe.
    second = commit_once(
        store,
        key=ledger_key,
        action_type=ACTION,
        execute=execute,
        effect=effect,
        args_json=ARGS,
    )
    assert second.state is LedgerState.COMMITTED
    assert second.result == first.result
    assert fake.requests == [expected_downstream]  # unchanged: never called again
    assert effects.count(expected_downstream) == 1


def test_fake_stripe_double_dedupes_on_its_own(effects: EffectsLog) -> None:
    """The double itself honors the downstream-idempotency contract the P1.3
    reconciler will rely on: a re-issued key returns the first response."""
    fake = FakeStripe(effects)
    first = fake.refund(idempotency_key="dk-1", amount="12.50")
    again = fake.refund(idempotency_key="dk-1", amount="12.50")
    other = fake.refund(idempotency_key="dk-2", amount="12.50")
    assert again == first  # same response object, no second effect
    assert other != first
    assert fake.requests == ["dk-1", "dk-1", "dk-2"]
    assert effects.count("dk-1") == 1


def test_map_key_transform_is_applied_and_stored(
    store: PostgresStore, fresh_engine: Engine, effects: EffectsLog
) -> None:
    """A length-limiting map_key: execute receives the mapped key AND the row
    stores it — never the raw ledger key."""
    ledger_key = derive_key(ACTION, {"invoice": "inv_map", "amount": "1.00"})
    effect = Effect(key_param="idempotency_key", map_key=lambda k: k[:20])
    received: list[str | None] = []

    def execute(downstream_key: str | None) -> None:
        received.append(downstream_key)

    commit_once(
        store,
        key=ledger_key,
        action_type=ACTION,
        execute=execute,
        effect=effect,
        args_json={"invoice": "inv_map", "amount": "1.00"},
    )
    assert received == [ledger_key[:20]]
    assert len(ledger_key[:20]) == 20 < len(ledger_key)
    row = _row(fresh_engine, ledger_key)
    assert row.downstream_key == ledger_key[:20]


# ---------------------------------------------------------------------------
# Post-verify (PLAN.md 4.1 step 5)
# ---------------------------------------------------------------------------


def test_post_verify_present_commits(
    store: PostgresStore, effects: EffectsLog, fresh_engine: Engine
) -> None:
    key = "k-verify-present"
    probe_calls: list[dict[str, Any]] = []

    def verify(**arg_map: Any) -> tuple[Verification, dict[str, str]]:
        probe_calls.append(arg_map)
        return Verification.PRESENT, {"seen": "downstream"}

    def execute(downstream_key: str | None) -> JsonValue:
        effects.log(key)
        return {"refund_id": 7}

    outcome = commit_once(
        store,
        key=key,
        action_type=ACTION,
        execute=execute,
        effect=Effect(verify=verify),
        args_json=ARGS,
    )
    assert outcome.state is LedgerState.COMMITTED
    assert outcome.guarantee is Guarantee.VERIFIABLE
    assert outcome.result == {"refund_id": 7}
    # The probe ran AFTER execute, with the canonical arg_map splatted in —
    # the same call shape the P1.3 reconciler uses with rehydrated args_json.
    assert probe_calls == [dict(ARGS)]
    assert effects.count(key) == 1
    row = _row(fresh_engine, key)
    assert row.state == LedgerState.COMMITTED.value
    assert row.committed_at is not None


def test_post_verify_absent_lands_failed_with_durable_evidence(
    store: PostgresStore, effects: EffectsLog, fresh_engine: Engine
) -> None:
    """absent = executed and confirmed not to have taken effect -> 'failed',
    evidence recorded, durable from a fresh connection."""
    key = "k-verify-absent"

    def verify(**_: Any) -> tuple[Verification, dict[str, str]]:
        return Verification.ABSENT, {"searched": "refunds list", "found": "nothing"}

    def execute(downstream_key: str | None) -> JsonValue:
        effects.log(key)
        return {"claims_success": True}

    outcome = commit_once(
        store,
        key=key,
        action_type=ACTION,
        execute=execute,
        effect=Effect(verify=verify),
        args_json=ARGS,
    )
    assert outcome.state is LedgerState.FAILED
    assert outcome.guarantee is Guarantee.VERIFIABLE
    assert outcome.error == {
        "post_verify": "absent",
        "evidence": {"searched": "refunds list", "found": "nothing"},
    }
    assert effects.count(key) == 1  # the effect DID run; the probe disproved it
    row = _row(fresh_engine, key)
    assert row.state == LedgerState.FAILED.value
    assert row.error_json == {
        "post_verify": "absent",
        "evidence": {"searched": "refunds list", "found": "nothing"},
    }
    assert row.result_json is None
    assert row.committed_at is None

    # A duplicate call returns the recorded failure without re-executing.
    duplicate = commit_once(
        store,
        key=key,
        action_type=ACTION,
        execute=execute,
        effect=Effect(verify=verify),
        args_json=ARGS,
    )
    assert duplicate.state is LedgerState.FAILED
    assert effects.count(key) == 1


def test_post_verify_unknown_leaves_executing_and_raises(
    store: PostgresStore, effects: EffectsLog, fresh_engine: Engine
) -> None:
    """unknown = the honest non-answer: no terminal state would be truthful,
    so the row stays 'executing' (durably) for the P1.3 reconciler and the
    caller gets the documented error — consistent with stale-loser waits."""
    key = "k-verify-unknown"

    def verify(**_: Any) -> tuple[Verification, dict[str, str]]:
        return Verification.UNKNOWN, {"api": "timed out"}

    def execute(downstream_key: str | None) -> JsonValue:
        effects.log(key)
        return {"claims_success": True}

    with pytest.raises(VerificationUnknown, match="reconcile") as excinfo:
        commit_once(
            store,
            key=key,
            action_type=ACTION,
            execute=execute,
            effect=Effect(verify=verify),
            args_json=ARGS,
        )
    assert excinfo.value.key == key
    assert excinfo.value.evidence == {"api": "timed out"}
    assert effects.count(key) == 1

    row = _row(fresh_engine, key)
    assert row.state == LedgerState.EXECUTING.value  # no lying terminal state
    assert row.error_json == {"post_verify": "unknown", "evidence": {"api": "timed out"}}
    assert row.committed_at is None

    # The claim is still held: a retry is a loser against an in-flight row —
    # never a re-execute (resolution is the reconciler's job, P1.3).
    with pytest.raises(CommitWaitTimeout, match="reconcile"):
        commit_once(
            store,
            key=key,
            action_type=ACTION,
            execute=lambda dk: pytest.fail("must not re-execute"),
            effect=Effect(verify=verify),
            args_json=ARGS,
            wait=False,
        )
    assert effects.count(key) == 1


def test_probe_exception_is_unknown_not_a_verdict(
    store: PostgresStore, effects: EffectsLog, fresh_engine: Engine
) -> None:
    """A probe that blows up proves nothing: same honest path as 'unknown',
    with the probe error recorded as evidence and chained on the raise."""
    key = "k-verify-boom"

    def verify(**_: Any) -> tuple[Verification, None]:
        raise ConnectionError("stripe API unreachable")

    def execute(downstream_key: str | None) -> JsonValue:
        effects.log(key)
        return {"claims_success": True}

    with pytest.raises(VerificationUnknown) as excinfo:
        commit_once(
            store,
            key=key,
            action_type=ACTION,
            execute=execute,
            effect=Effect(verify=verify),
            args_json=ARGS,
        )
    assert excinfo.value.evidence is None
    assert isinstance(excinfo.value.__cause__, ConnectionError)
    assert effects.count(key) == 1

    row = _row(fresh_engine, key)
    assert row.state == LedgerState.EXECUTING.value
    assert row.error_json == {
        "post_verify": "unknown",
        "probe_error": {"type": "ConnectionError", "message": "stripe API unreachable"},
    }


# ---------------------------------------------------------------------------
# At-most-once degradation (scenario 7)
# ---------------------------------------------------------------------------


def test_degradation_warns_and_is_visible_and_durable(
    store: PostgresStore, effects: EffectsLog, fresh_engine: Engine
) -> None:
    """Neither idempotent nor verifiable -> AtMostOnceWarning fires, the
    caller sees guarantee 'none' on the outcome, and the ledger row carries
    it durably. The honesty is a feature — never hidden."""
    action_type = "opaque.degradation-visibility"  # unique: the warn-once registry is per process
    key = "k-degraded"

    def execute(downstream_key: str | None) -> JsonValue:
        assert downstream_key is None  # no key_param -> nothing to pass through
        effects.log(key)
        return {"sent": True}

    with pytest.warns(AtMostOnceWarning, match="AT-MOST-ONCE") as caught:
        outcome = commit_once(
            store,
            key=key,
            action_type=action_type,
            execute=execute,
            effect=Effect(),
            args_json=ARGS,
        )
    assert len(caught) == 1
    message = str(caught[0].message)
    assert action_type in message
    assert "scenario 7" in message

    # Caller-visible.
    assert outcome.state is LedgerState.COMMITTED
    assert outcome.guarantee is Guarantee.NONE
    assert effects.count(key) == 1

    # Durable: the ledger row itself says at-most-once, from a fresh connection.
    row = _row(fresh_engine, key)
    assert row.guarantee == Guarantee.NONE.value
    assert row.state == LedgerState.COMMITTED.value


def test_degradation_warns_once_per_action_type(store: PostgresStore) -> None:
    """The warning is loud but not spam: once per action type per process;
    a different action type warns again."""
    action_a = "opaque.warn-once-a"
    action_b = "opaque.warn-once-b"

    with pytest.warns(AtMostOnceWarning):
        commit_once(
            store,
            key="k-warn-1",
            action_type=action_a,
            execute=lambda dk: None,
            effect=Effect(),
            args_json={},
        )

    # Same action type, new key: no second warning.
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        commit_once(
            store,
            key="k-warn-2",
            action_type=action_a,
            execute=lambda dk: None,
            effect=Effect(),
            args_json={},
        )
    assert [w for w in caught if issubclass(w.category, AtMostOnceWarning)] == []

    # Different action type: warns again.
    with pytest.warns(AtMostOnceWarning, match=action_b):
        commit_once(
            store,
            key="k-warn-3",
            action_type=action_b,
            execute=lambda dk: None,
            effect=Effect(),
            args_json={},
        )


def test_duplicate_of_degraded_action_reports_none_guarantee(store: PostgresStore) -> None:
    """Scenario 1 meets scenario 7: the duplicate's outcome reads the 'none'
    guarantee back from the winner's ledger row."""
    key = "k-degraded-dup"
    action_type = "opaque.degradation-duplicate"
    for _ in range(2):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", AtMostOnceWarning)
            outcome = commit_once(
                store,
                key=key,
                action_type=action_type,
                execute=lambda dk: {"ok": True},
                effect=Effect(),
                args_json={},
            )
        assert outcome.state is LedgerState.COMMITTED
        assert outcome.guarantee is Guarantee.NONE
