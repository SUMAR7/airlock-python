"""P3.6 — reviewer context: @guard ``summary=`` + structured ``context=``.

Two levels (PLAN.md 6.1 / SPEC.md 3):

- ``summary=`` resolves (str or callable, exactly like ``cost``/``blast_radius``)
  onto the ``action_summary`` wire field; ``None`` keeps the ``action_type``
  default; over-length is rejected at the wire boundary.
- ``context=`` resolves onto the NEW allowlisted ``review_context`` wire field.
  Its whole safety property is the metadata-only boundary: STRINGS-ONLY, size-
  capped, integrator-authored. That boundary is enforced STRUCTURALLY in
  ``ApprovalRequestWire.from_pause_request`` (``_validate_review_context``), so a
  smuggled non-string / oversized value can NEVER reach the wire.

The boundary tests here are the important ones — they must stay red under any
mutation that weakens the strings-only / size-cap / not-auto-populated guarantee.

DB-free: the gate-path integration uses a stdlib ``SqliteStore`` on a tmp file
and a capturing stub transport (``gate_wait=False`` → the run durably pauses and
raises ``ActionPending``, and we inspect the captured ``PauseRequest`` /
``ApprovalRequestWire``). No Postgres, no network, no ``time.sleep``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from airlock import guard, init
from airlock.errors import ActionPending
from airlock.policy import Policy
from airlock.transport import PauseRequest, SendReceipt
from airlock.transport.http import (
    MAX_REJECT_REASON_CODE_CHARS,
    MAX_REJECT_REASON_DESC_CHARS,
    MAX_REJECT_REASONS,
    MAX_REVIEW_CONTEXT_KEY_CHARS,
    MAX_REVIEW_CONTEXT_KEYS,
    MAX_REVIEW_CONTEXT_VALUE_CHARS,
    WIRE_ALLOWLIST,
    ApprovalRequestWire,
)
from airlock.types import BlastRadius, Decision, Money, Reversibility

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

pytestmark = pytest.mark.usefixtures("guard_isolation")


# ---------------------------------------------------------------------------
# A capturing stub transport + a gate-path harness (SqliteStore, no DB).
# ---------------------------------------------------------------------------


class _CapturingTransport:
    """Records the PauseRequest ``send`` received; never resolves the decision."""

    def __init__(self) -> None:
        self.requests: list[PauseRequest] = []

    def send(self, request: PauseRequest) -> SendReceipt:
        self.requests.append(request)
        return SendReceipt(approval_ref=request.approval_ref)

    def wait(self, approval_ref: str, timeout: float) -> None:  # pragma: no cover
        return None


@pytest.fixture
def gate(tmp_path: Path) -> Iterator[_CapturingTransport]:
    """Wire an @guard runtime whose GATE path captures its PauseRequest."""
    from airlock.store.sqlite import SqliteStore

    store = SqliteStore(str(tmp_path / "airlock.db"))
    store.ensure_schema()
    transport = _CapturingTransport()
    init(store=store, policy=Policy(default=Decision.GATE), transport=transport, gate_wait=False)
    yield transport


def _gate_call(fn: Callable[..., object], *args: object, **kwargs: object) -> None:
    """Invoke a gated tool (which raises ActionPending under gate_wait=False)."""
    with pytest.raises(ActionPending):
        fn(*args, **kwargs)


# ===========================================================================
# Level 1 — summary=
# ===========================================================================


def test_summary_str_populates_action_summary(gate: _CapturingTransport) -> None:
    @guard("refund.create", summary="Refund invoice inv_42 to acme")
    def refund(invoice: str) -> str:  # pragma: no cover - gated, never executes
        return "ok"

    _gate_call(refund, "inv_42")
    assert gate.requests[-1].summary == "Refund invoice inv_42 to acme"


def test_summary_callable_populates_action_summary(gate: _CapturingTransport) -> None:
    @guard("refund.create", summary=lambda invoice: f"Refund {invoice}")
    def refund(invoice: str) -> str:  # pragma: no cover
        return "ok"

    _gate_call(refund, "inv_99")
    assert gate.requests[-1].summary == "Refund inv_99"


def test_summary_none_defaults_to_action_type(gate: _CapturingTransport) -> None:
    @guard("refund.create")
    def refund(invoice: str) -> str:  # pragma: no cover
        return "ok"

    _gate_call(refund, "inv_1")
    assert gate.requests[-1].summary == "refund.create"


def test_summary_over_length_raises_at_the_wire() -> None:
    """action_summary is capped at 500 chars at the wire boundary (loud)."""
    from pydantic import ValidationError

    over = "x" * 501
    with pytest.raises(ValidationError):
        ApprovalRequestWire.from_pause_request(_pause(summary=over), sdk_version="0.0.1")
    # Exactly 500 is fine.
    wire = ApprovalRequestWire.from_pause_request(_pause(summary="x" * 500), sdk_version="0.0.1")
    assert len(wire.action_summary) == 500


# ===========================================================================
# Level 2 — context= (happy path onto review_context)
# ===========================================================================


def test_context_dict_populates_review_context(gate: _CapturingTransport) -> None:
    ctx = {"customer": "acme@co", "order": "#1832"}

    @guard("refund.create", context=ctx)
    def refund(invoice: str) -> str:  # pragma: no cover
        return "ok"

    _gate_call(refund, "inv_42")
    request = gate.requests[-1]
    assert request.review_context == ctx
    wire = ApprovalRequestWire.from_pause_request(request, sdk_version="0.0.1")
    assert wire.review_context == ctx


def test_context_callable_populates_review_context(gate: _CapturingTransport) -> None:
    @guard("refund.create", context=lambda invoice: {"invoice": invoice, "reason": "defective"})
    def refund(invoice: str) -> str:  # pragma: no cover
        return "ok"

    _gate_call(refund, "inv_77")
    assert gate.requests[-1].review_context == {"invoice": "inv_77", "reason": "defective"}


def test_context_none_omits_review_context_on_the_wire(gate: _CapturingTransport) -> None:
    @guard("refund.create")
    def refund(invoice: str) -> str:  # pragma: no cover
        return "ok"

    _gate_call(refund, "inv_1")
    request = gate.requests[-1]
    assert request.review_context is None
    wire = ApprovalRequestWire.from_pause_request(request, sdk_version="0.0.1")
    assert wire.review_context is None
    # ...and the field is OMITTED entirely from the serialized wire body.
    assert b"review_context" not in wire.to_json_bytes()


def test_review_context_is_never_auto_populated_from_args(gate: _CapturingTransport) -> None:
    """The whole guarantee: raw args NEVER become review_context (PLAN.md 6.1)."""

    @guard("refund.create")
    def refund(invoice: str, card_number: str) -> str:  # pragma: no cover
        return "ok"

    _gate_call(refund, "inv_42", "4111111111111111")
    request = gate.requests[-1]
    assert request.review_context is None  # args did NOT leak into context
    wire = ApprovalRequestWire.from_pause_request(request, sdk_version="0.0.1")
    body = wire.to_json_bytes()
    assert b"4111111111111111" not in body  # the card number never transits
    assert b"card_number" not in body


# ===========================================================================
# THE BOUNDARY — from_pause_request REFUSES a bad review_context; NOTHING sent.
# ===========================================================================


def _pause(
    *,
    summary: str = "Refund invoice inv_42",
    review_context: object = None,
    reject_reasons: object = None,
) -> PauseRequest:
    return PauseRequest(
        approval_ref="3f8b1c2a-9d4e-4f6a-8b1c-2a9d4e4f6a8b",
        run_id="run_9d1f2e3a4b5c6d7e8f9a0b1c2d3e4f50",
        action_type="refund.create",
        summary=summary,
        requested_at=datetime(2026, 7, 11, 3, 59, 20, 0, tzinfo=UTC),
        cost=Money(amount="12.5", currency="EUR"),
        reversibility=Reversibility.IRREVERSIBLE,
        blast_radius_estimate=BlastRadius.LOW,
        review_context=review_context,  # type: ignore[arg-type]  # deliberately loose
        reject_reasons=reject_reasons,  # type: ignore[arg-type]  # deliberately loose
    )


@pytest.mark.parametrize(
    "bad_value",
    [
        1250,  # a smuggled number
        12.5,  # a smuggled float
        True,  # a bool (int subclass) — must NOT count as a string
        {"card": "4111"},  # a smuggled nested payload object
        ["a", "b"],  # a smuggled list
        None,  # a null value (not a string)
    ],
    ids=["int", "float", "bool", "nested_dict", "list", "null"],
)
def test_boundary_refuses_non_string_value(bad_value: object) -> None:
    with pytest.raises(ValueError, match="review_context"):
        ApprovalRequestWire.from_pause_request(
            _pause(review_context={"field": bad_value}), sdk_version="0.0.1"
        )


def test_boundary_refuses_non_string_key() -> None:
    with pytest.raises(ValueError, match="keys must be strings"):
        ApprovalRequestWire.from_pause_request(
            _pause(review_context={123: "value"}), sdk_version="0.0.1"
        )


def test_boundary_refuses_too_many_keys() -> None:
    too_many = {f"k{i}": "v" for i in range(MAX_REVIEW_CONTEXT_KEYS + 1)}
    with pytest.raises(ValueError, match="exceeding the cap"):
        ApprovalRequestWire.from_pause_request(_pause(review_context=too_many), sdk_version="0.0.1")
    # Exactly at the cap is allowed.
    at_cap = {f"k{i}": "v" for i in range(MAX_REVIEW_CONTEXT_KEYS)}
    wire = ApprovalRequestWire.from_pause_request(
        _pause(review_context=at_cap), sdk_version="0.0.1"
    )
    assert wire.review_context is not None and len(wire.review_context) == MAX_REVIEW_CONTEXT_KEYS


def test_boundary_refuses_over_length_key() -> None:
    with pytest.raises(ValueError, match="exceeding the cap"):
        ApprovalRequestWire.from_pause_request(
            _pause(review_context={"k" * (MAX_REVIEW_CONTEXT_KEY_CHARS + 1): "v"}),
            sdk_version="0.0.1",
        )


def test_boundary_refuses_over_length_value() -> None:
    with pytest.raises(ValueError, match="exceeding the cap"):
        ApprovalRequestWire.from_pause_request(
            _pause(review_context={"k": "v" * (MAX_REVIEW_CONTEXT_VALUE_CHARS + 1)}),
            sdk_version="0.0.1",
        )


def test_boundary_accepts_a_flat_string_map() -> None:
    wire = ApprovalRequestWire.from_pause_request(
        _pause(review_context={"customer": "acme@co", "order": "#1832"}),
        sdk_version="0.0.1",
    )
    assert wire.review_context == {"customer": "acme@co", "order": "#1832"}


# ===========================================================================
# The frozen allowlist now includes review_context and STILL forbids payloads.
# ===========================================================================


def test_wire_allowlist_includes_review_context_and_forbids_payloads() -> None:
    assert set(ApprovalRequestWire.model_fields) == set(WIRE_ALLOWLIST)
    assert "review_context" in WIRE_ALLOWLIST
    assert "reject_reasons" in WIRE_ALLOWLIST
    # The never-transits fields still have NO field on the wire model.
    for forbidden in ("idempotency_key", "downstream_key", "args", "payload", "result_json"):
        assert forbidden not in WIRE_ALLOWLIST


# ===========================================================================
# P3.9 — reject_reasons (OFFERED codes) onto the reject_reasons wire field.
# ===========================================================================


def test_reject_reasons_dict_populates_the_wire_field(gate: _CapturingTransport) -> None:
    reasons = {"needs_more_info": "Needs more information", "not_authorized": "Not authorized"}

    @guard("refund.create", reject_reasons=reasons)
    def refund(invoice: str) -> str:  # pragma: no cover
        return "ok"

    _gate_call(refund, "inv_42")
    request = gate.requests[-1]
    assert request.reject_reasons == reasons
    wire = ApprovalRequestWire.from_pause_request(request, sdk_version="0.0.1")
    assert wire.reject_reasons == reasons


def test_reject_reasons_callable_populates_the_wire_field(gate: _CapturingTransport) -> None:
    @guard(
        "refund.create",
        reject_reasons=lambda invoice: {"duplicate": f"{invoice} looks like a duplicate"},
    )
    def refund(invoice: str) -> str:  # pragma: no cover
        return "ok"

    _gate_call(refund, "inv_77")
    assert gate.requests[-1].reject_reasons == {"duplicate": "inv_77 looks like a duplicate"}


def test_reject_reasons_none_omits_the_field_on_the_wire(gate: _CapturingTransport) -> None:
    @guard("refund.create")
    def refund(invoice: str) -> str:  # pragma: no cover
        return "ok"

    _gate_call(refund, "inv_1")
    request = gate.requests[-1]
    assert request.reject_reasons is None
    wire = ApprovalRequestWire.from_pause_request(request, sdk_version="0.0.1")
    assert wire.reject_reasons is None
    # ...and the field is OMITTED entirely from the serialized wire body.
    assert b"reject_reasons" not in wire.to_json_bytes()


def test_reject_reasons_is_never_auto_populated_from_args(gate: _CapturingTransport) -> None:
    """Like review_context: raw args NEVER become reject_reasons (PLAN.md 6.1)."""

    @guard("refund.create")
    def refund(invoice: str, card_number: str) -> str:  # pragma: no cover
        return "ok"

    _gate_call(refund, "inv_42", "4111111111111111")
    request = gate.requests[-1]
    assert request.reject_reasons is None  # args did NOT leak into reject_reasons
    wire = ApprovalRequestWire.from_pause_request(request, sdk_version="0.0.1")
    body = wire.to_json_bytes()
    assert b"4111111111111111" not in body
    assert b"card_number" not in body


@pytest.mark.parametrize(
    "bad_value",
    [
        1250,  # a smuggled number
        12.5,  # a smuggled float
        True,  # a bool (int subclass) — must NOT count as a string
        {"card": "4111"},  # a smuggled nested payload object
        ["a", "b"],  # a smuggled list
        None,  # a null value (not a string)
    ],
    ids=["int", "float", "bool", "nested_dict", "list", "null"],
)
def test_reject_reasons_boundary_refuses_non_string_value(bad_value: object) -> None:
    with pytest.raises(ValueError, match="reject_reasons"):
        ApprovalRequestWire.from_pause_request(
            _pause(reject_reasons={"code": bad_value}), sdk_version="0.0.1"
        )


def test_reject_reasons_boundary_refuses_non_string_code() -> None:
    with pytest.raises(ValueError, match="codes must be strings"):
        ApprovalRequestWire.from_pause_request(
            _pause(reject_reasons={123: "value"}), sdk_version="0.0.1"
        )


def test_reject_reasons_boundary_refuses_too_many_codes() -> None:
    too_many = {f"c{i}": "v" for i in range(MAX_REJECT_REASONS + 1)}
    with pytest.raises(ValueError, match="exceeding the cap"):
        ApprovalRequestWire.from_pause_request(_pause(reject_reasons=too_many), sdk_version="0.0.1")
    # Exactly at the cap is allowed.
    at_cap = {f"c{i}": "v" for i in range(MAX_REJECT_REASONS)}
    wire = ApprovalRequestWire.from_pause_request(
        _pause(reject_reasons=at_cap), sdk_version="0.0.1"
    )
    assert wire.reject_reasons is not None and len(wire.reject_reasons) == MAX_REJECT_REASONS


def test_reject_reasons_boundary_refuses_over_length_code() -> None:
    with pytest.raises(ValueError, match="exceeding the cap"):
        ApprovalRequestWire.from_pause_request(
            _pause(reject_reasons={"c" * (MAX_REJECT_REASON_CODE_CHARS + 1): "v"}),
            sdk_version="0.0.1",
        )


def test_reject_reasons_boundary_refuses_over_length_description() -> None:
    with pytest.raises(ValueError, match="exceeding the cap"):
        ApprovalRequestWire.from_pause_request(
            _pause(reject_reasons={"c": "v" * (MAX_REJECT_REASON_DESC_CHARS + 1)}),
            sdk_version="0.0.1",
        )
    # Exactly at the cap is allowed (the description cap is 200, distinct from
    # review_context's 500 — a mutation that reuses 500 here reddens this).
    wire = ApprovalRequestWire.from_pause_request(
        _pause(reject_reasons={"c": "v" * MAX_REJECT_REASON_DESC_CHARS}), sdk_version="0.0.1"
    )
    assert wire.reject_reasons == {"c": "v" * MAX_REJECT_REASON_DESC_CHARS}


def test_reject_reasons_boundary_accepts_a_flat_string_map() -> None:
    wire = ApprovalRequestWire.from_pause_request(
        _pause(reject_reasons={"needs_more_info": "Needs more information"}),
        sdk_version="0.0.1",
    )
    assert wire.reject_reasons == {"needs_more_info": "Needs more information"}


def test_reject_reasons_and_review_context_coexist_on_the_wire(gate: _CapturingTransport) -> None:
    """Both optional metadata fields can be present together; order is context then
    reject_reasons (reject_reasons last), so byte-stability holds for each alone."""

    @guard(
        "refund.create",
        context={"customer": "acme@co"},
        reject_reasons={"not_authorized": "Not authorized"},
    )
    def refund(invoice: str) -> str:  # pragma: no cover
        return "ok"

    _gate_call(refund, "inv_42")
    request = gate.requests[-1]
    wire = ApprovalRequestWire.from_pause_request(request, sdk_version="0.0.1")
    body = wire.to_json_bytes()
    assert wire.review_context == {"customer": "acme@co"}
    assert wire.reject_reasons == {"not_authorized": "Not authorized"}
    # Field order: review_context precedes reject_reasons in the serialized bytes.
    assert body.index(b"review_context") < body.index(b"reject_reasons")


def test_wire_model_still_forbids_a_smuggled_extra_field() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ApprovalRequestWire(
            approval_ref="r",
            run_id="run",
            action_type="a",
            action_summary="s",
            cost=None,
            reversibility=Reversibility.IRREVERSIBLE,
            blast_radius_estimate=None,
            requested_at="2026-07-11T03:59:20.000000Z",
            sdk_version="0.0.1",
            idempotency_key="k" * 64,  # type: ignore[call-arg]  # must not exist
        )
