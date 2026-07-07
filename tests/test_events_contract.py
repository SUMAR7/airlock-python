"""action_event.v1: model <-> JSON Schema <-> fixture round-trip (PLAN.md 6.3).

THE one event schema, pinned three ways in the same PR that ships it:

- every fixture in /contracts/events/examples validates against the JSON
  Schema AND round-trips through the pydantic model byte-identically;
- the JSON-schema enum lists are GENERATED-equal to the airlock.types enums
  (the single vocabulary source, PLAN.md 10.5) — the third surface of the
  enum-consistency check (types.py <-> DDL CHECKs <-> JSON schema; the DDL
  half lives in tests/test_schema.py);
- the model makes contract violations unrepresentable (reserved action_diff,
  post_verify.result without a probe, extra fields, malformed emitted_at).

v1 fixtures stay green forever — a failing old fixture is the "never break
it silently" tripwire (PLAN.md 6).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from airlock.events import ACTION_EVENT_TYPE, ActionEvent, PostVerify
from airlock.types import (
    TERMINAL_LEDGER_STATES,
    ActionOutcome,
    BlastRadius,
    Decision,
    Guarantee,
    HumanDecision,
    LedgerState,
    Money,
    Reversibility,
    Verification,
)

CONTRACTS = Path(__file__).parent.parent / "contracts" / "events"
SCHEMA_PATH = CONTRACTS / "action_event.v1.json"
FIXTURE_PATHS = sorted((CONTRACTS / "examples").glob("action_event.v1.*.json"))

SCHEMA: dict[str, Any] = json.loads(SCHEMA_PATH.read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


def _sample_event(**overrides: Any) -> ActionEvent:
    fields: dict[str, Any] = {
        "event_id": "e" * 32,
        "emitted_at": "2026-07-06T12:00:00.000000Z",
        "run_id": "run_x",
        "idempotency_key": "k" * 64,
        "action_type": "refund.create",
        "policy_decision": Decision.AUTO,
        "cost": Money(amount="12.5", currency="EUR"),
        "reversibility": Reversibility.REVERSIBLE,
        "blast_radius_estimate": BlastRadius.LOW,
        "guarantee": Guarantee.VERIFIABLE,
        "outcome": ActionOutcome.COMMITTED,
        "post_verify": PostVerify(ran=True, result=Verification.PRESENT),
    }
    fields.update(overrides)
    return ActionEvent(**fields)


# ---------------------------------------------------------------------------
# Fixture round-trip: fixture -> schema, fixture -> model -> dump == fixture.
# ---------------------------------------------------------------------------


def test_the_schema_itself_is_a_valid_draft_2020_12_schema() -> None:
    Draft202012Validator.check_schema(SCHEMA)


def test_there_are_pinned_fixtures() -> None:
    assert len(FIXTURE_PATHS) >= 3, "the v1 fixtures are the never-break-silently tripwire"


@pytest.mark.parametrize("path", FIXTURE_PATHS, ids=lambda p: p.stem)
def test_fixture_validates_against_the_schema(path: Path) -> None:
    VALIDATOR.validate(json.loads(path.read_text()))


@pytest.mark.parametrize("path", FIXTURE_PATHS, ids=lambda p: p.stem)
def test_fixture_round_trips_through_the_model(path: Path) -> None:
    """fixture -> ActionEvent -> model_dump(mode='json') == fixture, exactly."""
    fixture = json.loads(path.read_text())
    event = ActionEvent.model_validate(fixture)
    assert event.model_dump(mode="json") == fixture
    # And the model's payload form re-validates against the schema.
    VALIDATOR.validate(event.to_payload())


def test_model_built_event_validates_against_the_schema() -> None:
    VALIDATOR.validate(_sample_event().to_payload())
    VALIDATOR.validate(
        _sample_event(
            cost=None,
            blast_radius_estimate=None,
            guarantee=Guarantee.NONE,
            outcome=ActionOutcome.DENIED,
            policy_decision=Decision.DENY,
            post_verify=PostVerify(ran=False),
        ).to_payload()
    )


def test_to_audit_event_shape() -> None:
    event = _sample_event()
    audit = event.to_audit_event()
    assert audit.event_type == ACTION_EVENT_TYPE == "action_event"
    assert audit.run_id == event.run_id
    assert audit.action_type == event.action_type
    assert audit.payload == event.to_payload()
    assert audit.created_at == datetime(2026, 7, 6, 12, 0, 0, tzinfo=UTC)  # == emitted_at


# ---------------------------------------------------------------------------
# Enum consistency: JSON schema <-> types.py (the third surface).
# ---------------------------------------------------------------------------


def _schema_enum(field: str) -> list[str]:
    prop = SCHEMA["properties"][field]
    if "enum" in prop:
        return list(prop["enum"])
    # nullable enums are encoded as oneOf [enum, null]
    return list(prop["oneOf"][0]["enum"])


def test_schema_enums_match_types_py() -> None:
    """PLAN.md 10.5: one enum vocabulary. The schema lists must equal the
    types.py enums, values AND order (order = generated, not hand-kept)."""
    assert _schema_enum("policy_decision") == [d.value for d in Decision]
    assert _schema_enum("reversibility") == [r.value for r in Reversibility]
    assert _schema_enum("blast_radius_estimate") == [b.value for b in BlastRadius]
    assert _schema_enum("guarantee") == [g.value for g in Guarantee]
    assert _schema_enum("human_decision") == [h.value for h in HumanDecision]
    assert _schema_enum("outcome") == [o.value for o in ActionOutcome]
    post_verify = SCHEMA["$defs"]["post_verify"]["properties"]["result"]
    assert list(post_verify["oneOf"][0]["enum"]) == [v.value for v in Verification]


def test_action_outcome_is_terminal_ledger_states_plus_denied() -> None:
    """The outcome vocabulary is DERIVED from the ledger vocabulary: the four
    terminal states (same spellings) plus 'denied' — never a fork."""
    outcome_values = [o.value for o in ActionOutcome]
    assert outcome_values[:-1] == [s.value for s in LedgerState if s in TERMINAL_LEDGER_STATES]
    assert outcome_values[-1] == "denied"
    assert set(outcome_values[:-1]) == {s.value for s in TERMINAL_LEDGER_STATES}


def test_schema_version_is_const_one_and_fields_are_exactly_plan_6_3() -> None:
    assert SCHEMA["properties"]["schema_version"] == {
        "const": 1,
        "description": SCHEMA["properties"]["schema_version"]["description"],
    }
    expected_fields = {
        "schema_version",
        "event_id",
        "emitted_at",
        "run_id",
        "idempotency_key",
        "action_type",
        "policy_decision",
        "cost",
        "reversibility",
        "blast_radius_estimate",
        "guarantee",
        "human_decision",
        "decision_latency_ms",
        "decided_by",
        "action_diff",
        "outcome",
        "post_verify",
    }
    assert set(SCHEMA["properties"]) == expected_fields
    assert set(SCHEMA["required"]) == expected_fields
    assert SCHEMA["additionalProperties"] is False
    assert set(ActionEvent.model_fields) == expected_fields


# ---------------------------------------------------------------------------
# The model makes contract violations unrepresentable.
# ---------------------------------------------------------------------------


def test_action_diff_must_be_null() -> None:
    """Reserved field (SPEC section 7): any non-null value is rejected — the
    preference-learning shape is an action_event.v2 decision."""
    with pytest.raises(ValidationError):
        _sample_event(action_diff={"before": 1, "after": 2})


def test_post_verify_result_requires_ran() -> None:
    with pytest.raises(ValidationError, match="never ran"):
        PostVerify(ran=False, result=Verification.PRESENT)
    # And the schema encodes the same constraint:
    bad = _sample_event(post_verify=PostVerify(ran=True, result=Verification.PRESENT)).to_payload()
    bad["post_verify"] = {"ran": False, "result": "present"}
    assert not VALIDATOR.is_valid(bad)


def test_extra_fields_rejected_by_model_and_schema() -> None:
    payload = _sample_event().to_payload()
    payload["surprise"] = "field"
    with pytest.raises(ValidationError):
        ActionEvent.model_validate(payload)
    assert not VALIDATOR.is_valid(payload)


def test_emitted_at_shape_is_pinned() -> None:
    with pytest.raises(ValidationError, match="RFC 3339"):
        _sample_event(emitted_at="2026-07-06T12:00:00Z")  # no microseconds
    with pytest.raises(ValidationError, match="RFC 3339"):
        _sample_event(emitted_at="2026-07-06 12:00:00.000000Z")
    # A tz-aware datetime is accepted and rendered canonically:
    event = _sample_event(emitted_at=datetime(2026, 7, 6, 12, 0, 0, 42, tzinfo=UTC))
    assert event.emitted_at == "2026-07-06T12:00:00.000042Z"
    # Schema side: the pattern rejects the no-microseconds form too.
    payload = _sample_event().to_payload()
    payload["emitted_at"] = "2026-07-06T12:00:00Z"
    assert not VALIDATOR.is_valid(payload)


def test_money_is_never_a_float_in_the_schema() -> None:
    payload = _sample_event().to_payload()
    payload["cost"] = {"amount": 12.5, "currency": "EUR"}
    assert not VALIDATOR.is_valid(payload)
    payload["cost"] = {"amount": "12.50", "currency": "EUR"}  # trailing zero: not canonical
    assert not VALIDATOR.is_valid(payload)


def test_schema_version_other_than_one_rejected() -> None:
    payload = _sample_event().to_payload()
    payload["schema_version"] = 2
    assert not VALIDATOR.is_valid(payload)
    with pytest.raises(ValidationError):
        ActionEvent.model_validate(payload)
