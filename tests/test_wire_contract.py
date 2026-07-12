"""/contracts/openapi.yaml — the wire contract, structurally pinned (PLAN.md 6).

The wire contract is compliance-critical: it defines EXACTLY what crosses the
customer boundary (PLAN.md 6.1). These tests are the boundary's structural
enforcement in this repo (airlock-cloud pins the same file, P3.2):

- the deliberately-three-call shape is present (PLAN.md 6.2);
- the create request body is EXACTLY the frozen egress allowlist (PLAN.md 6.1)
  and `additionalProperties: false`, and NO forbidden field name (tool args,
  idempotency_key, downstream_key, results, serialized_state, audit/hashes)
  appears anywhere in the request schemas — the never-transits list, enforced
  by shape not by hope;
- the shared Money / Reversibility / BlastRadius vocabulary is byte-consistent
  with action_event.v1 and airlock.types (single source, PLAN.md 10.5);
- every pinned example (and each signed request vector body) validates against
  its schema.

Changing the frozen allowlist below REQUIRES a contract version bump (a new
`/api/v2` shape) — it is not an additive change (PLAN.md 6.1 / CHANGELOG).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from airlock.types import BlastRadius, Reversibility

CONTRACTS = Path(__file__).parent.parent / "contracts"
OPENAPI_PATH = CONTRACTS / "openapi.yaml"
EXAMPLES = CONTRACTS / "examples"
ACTION_EVENT_SCHEMA: dict[str, Any] = json.loads(
    (CONTRACTS / "events" / "action_event.v1.json").read_text()
)

DOC: dict[str, Any] = yaml.safe_load(OPENAPI_PATH.read_text())


# --- THE FROZEN ALLOWLIST (mirrors PLAN.md 6.1) ----------------------------
# The exact set of keys the SDK may put on the wire in the create request.
# Changing this set is a boundary change: REMOVING/renaming a key needs a
# CONTRACT VERSION BUMP (/api/v2); ADDING an OPTIONAL key is a backward-
# compatible v1 widening (review_context, v1.1.0/P3.6). It is the compliance
# surface itself.
FROZEN_REQUEST_ALLOWLIST = frozenset(
    {
        "approval_ref",
        "run_id",
        "action_type",
        "action_summary",
        "cost",
        "reversibility",
        "blast_radius_estimate",
        "requested_at",
        "sdk_version",
        "review_context",
        "reject_reasons",
    }
)

# The REQUIRED subset (every allowlisted key except the OPTIONAL ones,
# review_context (v1.1.0) and reject_reasons (v1.2.0)). A pre-1.1.0 create body
# carries exactly these.
FROZEN_REQUEST_REQUIRED = FROZEN_REQUEST_ALLOWLIST - {"review_context", "reject_reasons"}

# Field names that must NEVER appear structurally in any request schema
# (PLAN.md 6.1 never-transits list). Checked against property/required KEYS
# only — descriptions legitimately NAME these to explain the exclusion.
FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "idempotency_key",
        "downstream_key",
        "result_json",
        "error_json",
        "serialized_state",
        "args",
        "arg_map",
        "payload",
        "payload_json",
        "stack_trace",
        "stacktrace",
        "traceback",
        "prev_hash",
        "row_hash",
        "audit",
    }
)


# ---------------------------------------------------------------------------
# Schema-resolution helpers: inline #/components/schemas/X as #/$defs/X so each
# component schema is a self-contained Draft 2020-12 schema we can validate with.
# ---------------------------------------------------------------------------

_SCHEMAS: dict[str, Any] = DOC["components"]["schemas"]
_DEFS: dict[str, Any] = json.loads(
    json.dumps(_SCHEMAS).replace("#/components/schemas/", "#/$defs/")
)


def _validator_for(schema_name: str) -> Draft202012Validator:
    schema = dict(_DEFS[schema_name])
    schema["$defs"] = _DEFS
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _all_property_names(node: Any) -> set[str]:
    """Every key declared under a `properties` object, recursively."""
    names: set[str] = set()
    if isinstance(node, dict):
        props = node.get("properties")
        if isinstance(props, dict):
            names.update(props.keys())
        for value in node.values():
            names |= _all_property_names(value)
    elif isinstance(node, list):
        for item in node:
            names |= _all_property_names(item)
    return names


# ---------------------------------------------------------------------------
# 1. The document parses and is the deliberately-three-call contract.
# ---------------------------------------------------------------------------


def test_openapi_parses_and_is_3_1() -> None:
    assert DOC["openapi"].startswith("3.1")
    assert DOC["info"]["version"] == "1.2.0"


def test_exactly_the_three_calls_are_present() -> None:
    # Call #1 (POST) and #2 (GET) are hosted paths under /api/v1/.
    paths = DOC["paths"]
    assert set(paths) == {"/api/v1/approvals", "/api/v1/approvals/{approval_id}"}
    assert set(paths["/api/v1/approvals"]) == {"post"}
    assert set(paths["/api/v1/approvals/{approval_id}"]) == {"get"}
    # Call #3 (the approval.decided push) is a webhook to the customer URL.
    assert "post" in DOC["webhooks"]["approvalDecided"]


def test_all_three_calls_require_the_signing_headers() -> None:
    """HMAC headers apply to every call, both directions (signing.md)."""
    header_sets = [
        DOC["paths"]["/api/v1/approvals"]["post"],
        DOC["paths"]["/api/v1/approvals/{approval_id}"]["get"],
        DOC["webhooks"]["approvalDecided"]["post"],
    ]
    for op in header_sets:
        refs = {p["$ref"].rsplit("/", 1)[-1] for p in op["parameters"] if "$ref" in p}
        assert {"AirlockKey", "AirlockTimestamp", "AirlockSignature"} <= refs
        assert op["security"] == [{"airlockSignature": []}]


# ---------------------------------------------------------------------------
# 2. The frozen allowlist + strict egress + never-transits enforcement.
# ---------------------------------------------------------------------------


def test_create_request_is_exactly_the_frozen_allowlist() -> None:
    req = _SCHEMAS["CreateApprovalRequest"]
    # Every allowlisted key is a declared property; ONLY review_context is
    # optional — everything else is still required (no accidental relaxation).
    assert set(req["properties"]) == set(FROZEN_REQUEST_ALLOWLIST)
    assert set(req["required"]) == set(FROZEN_REQUEST_REQUIRED)
    assert "review_context" not in req["required"]
    assert "reject_reasons" not in req["required"]


def test_review_context_is_strings_only_and_size_capped() -> None:
    """review_context is metadata-only: flat str->str, size-capped (PLAN.md 6.1)."""
    rc = _SCHEMAS["CreateApprovalRequest"]["properties"]["review_context"]
    assert rc["type"] == "object"
    # values are strings (never a nested object/list/number) and capped
    assert rc["additionalProperties"]["type"] == "string"
    assert rc["additionalProperties"]["maxLength"] == 500
    # at most 20 keys, each key <= 64 chars
    assert rc["maxProperties"] == 20
    assert rc["propertyNames"]["maxLength"] == 64


def test_reject_reasons_is_strings_only_and_size_capped() -> None:
    """reject_reasons is metadata-only: flat str->str, size-capped (P3.9)."""
    rr = _SCHEMAS["CreateApprovalRequest"]["properties"]["reject_reasons"]
    assert rr["type"] == "object"
    # values (the descriptions) are strings (never nested/list/number), capped 200
    assert rr["additionalProperties"]["type"] == "string"
    assert rr["additionalProperties"]["maxLength"] == 200
    # at most 20 codes, each code (key) <= 64 chars
    assert rr["maxProperties"] == 20
    assert rr["propertyNames"]["maxLength"] == 64


def test_create_request_schema_rejects_non_string_reject_reasons_value() -> None:
    """A smuggled non-string reject_reasons value fails the schema (strings-only)."""
    good = json.loads((EXAMPLES / "create_approval.request.with_reject_reasons.json").read_text())
    validator = _validator_for("CreateApprovalRequest")
    validator.validate(good)  # the honest all-strings body is valid
    # An int value (a smuggled number) is rejected.
    smuggled_num = copy.deepcopy(good)
    smuggled_num["reject_reasons"] = {"amount": 1250}
    assert not validator.is_valid(smuggled_num)
    # A nested object (a smuggled payload) is rejected.
    smuggled_obj = copy.deepcopy(good)
    smuggled_obj["reject_reasons"] = {"payload": {"card": "4111"}}
    assert not validator.is_valid(smuggled_obj)
    # A list value is rejected.
    smuggled_list = copy.deepcopy(good)
    smuggled_list["reject_reasons"] = {"items": ["a", "b"]}
    assert not validator.is_valid(smuggled_list)


def test_reason_code_is_nullable_on_decision_response_and_webhook() -> None:
    """reason_code (v1.2.0) is a nullable field on both inbound decision shapes."""
    for name in ("GetApprovalResponse", "ApprovalDecidedWebhook"):
        rc = _SCHEMAS[name]["properties"]["reason_code"]
        types = {branch.get("type") for branch in rc["oneOf"]}
        assert types == {"string", "null"}
    # The GET response promises it (required, like `reason`); the webhook keeps
    # it OPTIONAL so the frozen webhook signing vector (which predates it) stays
    # valid forever.
    assert "reason_code" in _SCHEMAS["GetApprovalResponse"]["required"]
    assert "reason_code" not in _SCHEMAS["ApprovalDecidedWebhook"]["required"]


def test_create_request_schema_rejects_non_string_review_context_value() -> None:
    """A smuggled non-string review_context value fails the schema (strings-only)."""
    good = json.loads((EXAMPLES / "create_approval.request.with_context.json").read_text())
    validator = _validator_for("CreateApprovalRequest")
    validator.validate(good)  # the honest all-strings body is valid
    # An int value (a smuggled number) is rejected.
    smuggled_num = copy.deepcopy(good)
    smuggled_num["review_context"] = {"amount": 1250}
    assert not validator.is_valid(smuggled_num)
    # A nested object (a smuggled payload) is rejected.
    smuggled_obj = copy.deepcopy(good)
    smuggled_obj["review_context"] = {"payload": {"card": "4111"}}
    assert not validator.is_valid(smuggled_obj)
    # A list value is rejected.
    smuggled_list = copy.deepcopy(good)
    smuggled_list["review_context"] = {"items": ["a", "b"]}
    assert not validator.is_valid(smuggled_list)


def test_request_schemas_are_strict_egress() -> None:
    """additionalProperties:false on every SDK/cloud-authored request body."""
    for name in ("CreateApprovalRequest", "ApprovalDecidedWebhook"):
        assert _SCHEMAS[name]["additionalProperties"] is False


def test_no_forbidden_field_name_in_request_schemas() -> None:
    """The never-transits list, structurally (PLAN.md 6.1)."""
    for name in ("CreateApprovalRequest", "ApprovalDecidedWebhook"):
        declared = _all_property_names(_SCHEMAS[name])
        leaked = declared & FORBIDDEN_FIELD_NAMES
        assert not leaked, f"{name} exposes forbidden field(s) on the wire: {leaked}"


def test_action_summary_is_capped_and_summary_shaped() -> None:
    summary = _SCHEMAS["CreateApprovalRequest"]["properties"]["action_summary"]
    assert summary["maxLength"] == 500  # PLAN.md 6.1: <=500, integrator-authored


def test_approval_ref_is_the_only_cross_boundary_key() -> None:
    """approval_ref appears in the create body, both decision responses, and the
    webhook — and it is a UUID (PLAN.md 6.1)."""
    assert _SCHEMAS["ApprovalRef"]["format"] == "uuid"
    for name in (
        "CreateApprovalRequest",
        "CreateApprovalResponse",
        "GetApprovalResponse",
        "ApprovalDecidedWebhook",
    ):
        assert "approval_ref" in _SCHEMAS[name]["properties"]


# ---------------------------------------------------------------------------
# 3. Shared vocabulary is single-sourced (consistent with types.py + event).
# ---------------------------------------------------------------------------


def test_reversibility_enum_matches_types() -> None:
    assert _SCHEMAS["Reversibility"]["enum"] == [r.value for r in Reversibility]


def test_blast_radius_enum_matches_types_and_is_ordered() -> None:
    assert _SCHEMAS["BlastRadius"]["enum"] == [b.value for b in BlastRadius]
    assert _SCHEMAS["BlastRadius"]["enum"] == ["low", "medium", "high"]


def test_money_shape_matches_action_event_v1() -> None:
    """One Money shape everywhere: never a float; same decimal-string pattern."""
    wire = _SCHEMAS["Money"]
    event = ACTION_EVENT_SCHEMA["$defs"]["money"]
    assert wire["properties"]["amount"]["pattern"] == event["properties"]["amount"]["pattern"]
    assert wire["properties"]["currency"]["pattern"] == event["properties"]["currency"]["pattern"]
    assert wire["additionalProperties"] is False
    # amount is a string (never a JSON number/float), like the event contract.
    assert wire["properties"]["amount"]["type"] == "string"


def test_actor_id_is_opaque_never_email() -> None:
    """decided_by is a usr_ actor id; the email lives in decided_by_display
    (PLAN.md 10.6)."""
    assert _SCHEMAS["ActorId"]["pattern"] == "^usr_[0-9A-Za-z]+$"
    webhook = _SCHEMAS["ApprovalDecidedWebhook"]["properties"]
    assert webhook["decided_by"]["$ref"].endswith("/ActorId")
    assert "decided_by_display" in webhook


# ---------------------------------------------------------------------------
# 4. Pinned examples + signed vector bodies validate against their schemas.
# ---------------------------------------------------------------------------

EXAMPLE_TO_SCHEMA = {
    "create_approval.request.json": "CreateApprovalRequest",
    "create_approval.request.with_context.json": "CreateApprovalRequest",
    "create_approval.request.with_reject_reasons.json": "CreateApprovalRequest",
    "create_approval.response.json": "CreateApprovalResponse",
    "get_approval.response.json": "GetApprovalResponse",
    "approval_decided.webhook.json": "ApprovalDecidedWebhook",
}


@pytest.mark.parametrize(("filename", "schema_name"), EXAMPLE_TO_SCHEMA.items())
def test_pinned_example_validates(filename: str, schema_name: str) -> None:
    example = json.loads((EXAMPLES / filename).read_text())
    _validator_for(schema_name).validate(example)


def test_signed_vector_bodies_validate_against_request_schemas() -> None:
    """The exact bytes we sign for the create + webhook calls are themselves
    valid request bodies — the boundary and the signature agree."""
    vectors = json.loads((EXAMPLES / "signing_vectors.json").read_text())["vectors"]
    by_name = {v["name"]: v for v in vectors}
    create = json.loads(by_name["create_approval_post"]["raw_body"])
    _validator_for("CreateApprovalRequest").validate(create)
    webhook = json.loads(by_name["webhook_decided_post"]["raw_body"])
    _validator_for("ApprovalDecidedWebhook").validate(webhook)
    # The no-context create body carries EXACTLY the required keys (no
    # review_context) — byte-identical to the pre-1.1.0 body.
    assert set(create) == set(FROZEN_REQUEST_REQUIRED)

    # The with-context vector validates and carries ONLY allowlisted keys,
    # including review_context — nothing outside the frozen allowlist transits.
    create_ctx = json.loads(by_name["create_approval_with_context_post"]["raw_body"])
    _validator_for("CreateApprovalRequest").validate(create_ctx)
    assert set(create_ctx) <= set(FROZEN_REQUEST_ALLOWLIST)
    assert "review_context" in create_ctx
    assert all(isinstance(v, str) for v in create_ctx["review_context"].values())

    # The with-reject_reasons vector validates and carries ONLY allowlisted keys,
    # including reject_reasons (strings-only) — nothing outside the allowlist.
    create_rr = json.loads(by_name["create_approval_with_reject_reasons_post"]["raw_body"])
    _validator_for("CreateApprovalRequest").validate(create_rr)
    assert set(create_rr) <= set(FROZEN_REQUEST_ALLOWLIST)
    assert "reject_reasons" in create_rr
    assert all(isinstance(v, str) for v in create_rr["reject_reasons"].values())


def test_create_request_rejects_a_forbidden_field() -> None:
    """A body that smuggles idempotency_key is rejected (additionalProperties)."""
    good = json.loads((EXAMPLES / "create_approval.request.json").read_text())
    smuggled = copy.deepcopy(good)
    smuggled["idempotency_key"] = "k" * 64  # the payload digest — must never transit
    assert not _validator_for("CreateApprovalRequest").is_valid(smuggled)
    smuggled2 = copy.deepcopy(good)
    smuggled2["args"] = {"amount": "12.50"}  # raw tool args — must never transit
    assert not _validator_for("CreateApprovalRequest").is_valid(smuggled2)
