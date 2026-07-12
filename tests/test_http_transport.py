"""P3.4 deliverable 4 — the SDK<->control-plane join, against a FAKE control
plane (no live Rails, CI-safe).

A tiny in-process control plane (:class:`FakeControlPlane`) implements the three
signed calls per ``/contracts`` over an ``httpx.MockTransport`` (no real
network, no time.sleep). It verifies EVERY request with the golden-vector
scheme (``airlock._signing.verify``) so a test only passes if the SDK signed
correctly, and it rejects a bad signature exactly as the real server does.

What this pins (PLAN.md 6.1/6.2, SPEC scenarios 5/6):

- ``send`` produces a request that VERIFIES with the golden scheme and whose
  body is EXACTLY the frozen allowlist — a smuggled ``payload`` /
  ``idempotency_key`` is impossible by construction (``extra="forbid"``), and
  the emitted bytes reproduce the ``/contracts`` reference vector byte-for-byte;
- ``send`` is idempotent-safe (200 and 201 both accepted; the hosted
  ``approval_id`` is returned + persisted for the backstop);
- ``wait`` polls and maps the decision (latency recorded verbatim); times out to
  ``None`` without sleeping;
- the ``webhook_app`` receiver verifies a signed ``approval.decided`` body and
  resumes EXACTLY ONCE, a DOUBLE delivery is a safe no-op (one effect), and a
  tampered / replayed webhook is 401;
- the reconciler backstop poll recovers a decision when no webhook arrived.

No real network, no ``time.sleep`` (an injected clock drives every poll).
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from airlock import init
from airlock._signing import (
    HEADER_KEY,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    sign,
    verify,
)
from airlock.reconcile import backstop_poll_paused
from airlock.transport import PauseRequest, SendReceipt
from airlock.transport.http import (
    WIRE_ALLOWLIST,
    ApprovalRequestWire,
    ApprovalTransportError,
    HttpApprovalTransport,
    webhook_app,
)
from airlock.types import (
    BlastRadius,
    HumanDecision,
    Money,
    PauseStatus,
    Reversibility,
)
from tests import _pause_harness as harness
from tests._pause_harness import GATE_ACTION, effect_key

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore
    from tests.conftest import EffectsLog, FakeClock

# Fixed test credentials + timestamp so signing is deterministic (mirrors the
# golden vectors' fixed creds; NOT the reference secret — a distinct test key).
BASE_URL = "https://cp.test"
KEY_ID = "ak_live_testkey0001"
SECRET = "sk_live_p34_http_transport_test_secret_value"
TS = 1783944000
WEBHOOK_PATH = "/airlock/webhooks"


# ===========================================================================
# The fake control plane (httpx.MockTransport) — the three signed calls.
# ===========================================================================


class FakeControlPlane:
    """An in-process control plane over ``httpx.MockTransport`` (no network).

    Verifies every request with the real ``airlock-v1`` scheme (401 on failure),
    creates/replays approvals idempotently on ``approval_ref``, and serves the
    decision poll. ``decide`` flips an approval to approved/rejected so ``wait``
    / ``fetch_decision`` observe it.
    """

    def __init__(self, secret: str = SECRET, *, verify_now: float = TS) -> None:
        self._secret = secret
        self._verify_now = verify_now
        self.by_ref: dict[str, dict[str, Any]] = {}
        self.by_id: dict[str, dict[str, Any]] = {}
        self.requests: list[tuple[str, str, bytes]] = []
        self.create_calls = 0
        self._seq = 0

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self._handler), base_url=BASE_URL)

    def _handler(self, request: httpx.Request) -> httpx.Response:
        raw = request.content
        path = request.url.raw_path.decode("ascii")
        ok = verify(
            self._secret,
            headers={k: v for k, v in request.headers.items()},
            method=request.method,
            path_with_query=path,
            raw_body=raw,
            now=self._verify_now,
        )
        if not ok:
            return httpx.Response(401, json={"code": "invalid_signature", "message": "bad sig"})
        self.requests.append((request.method, path, raw))
        if request.method == "POST":
            return self._create(json.loads(raw))
        return self._get(path.rsplit("/", 1)[-1])

    def _create(self, body: dict[str, Any]) -> httpx.Response:
        self.create_calls += 1
        ref = body["approval_ref"]
        existing = self.by_ref.get(ref)
        if existing is not None:
            return httpx.Response(200, json=_create_resp(existing))  # idempotent replay
        self._seq += 1
        row: dict[str, Any] = {
            "approval_id": f"apr_test{self._seq:026d}",
            "approval_ref": ref,
            "run_id": body["run_id"],
            "status": "requested",
            "decided_by": None,
            "decided_by_display": None,
            "decided_at": None,
            "decision_latency_ms": None,
            "reason": None,
            "reason_code": None,
        }
        self.by_ref[ref] = row
        self.by_id[row["approval_id"]] = row
        return httpx.Response(201, json=_create_resp(row))

    def _get(self, approval_id: str) -> httpx.Response:
        row = self.by_id.get(approval_id)
        if row is None:
            return httpx.Response(404, json={"code": "not_found", "message": "no approval"})
        return httpx.Response(200, json=_get_resp(row))

    def decide(
        self,
        approval_ref: str,
        decision: str,
        *,
        decided_by: str = "usr_reviewer1",
        decided_by_display: str | None = "alice@acme.example",
        decision_latency_ms: int = 4200,
        reason: str | None = None,
        reason_code: str | None = None,
    ) -> dict[str, Any]:
        row = self.by_ref[approval_ref]
        row.update(
            status=decision,
            decided_by=decided_by,
            decided_by_display=decided_by_display,
            decided_at="2026-07-11T04:02:40.000000Z",
            decision_latency_ms=decision_latency_ms,
            reason=reason,
            reason_code=reason_code,
        )
        return row


def _create_resp(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "approval_id": row["approval_id"],
        "approval_ref": row["approval_ref"],
        "status": row["status"],
        "inbox_url": f"{BASE_URL}/approvals/{row['approval_id']}",
    }


def _get_resp(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "approval_id": row["approval_id"],
        "approval_ref": row["approval_ref"],
        "status": row["status"],
        "decided_by": row["decided_by"],
        "decided_by_display": row["decided_by_display"],
        "decided_at": row["decided_at"],
        "decision_latency_ms": row["decision_latency_ms"],
        "reason": row["reason"],
        "reason_code": row["reason_code"],
    }


class _StepClock:
    """A monotonic clock that advances only when the poll sleeps (no wall time)."""

    def __init__(self) -> None:
        self.t = 0.0

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += seconds


def _transport(cp: FakeControlPlane, clock: _StepClock | None = None) -> HttpApprovalTransport:
    clock = clock if clock is not None else _StepClock()
    return HttpApprovalTransport(
        base_url=BASE_URL,
        key_id=KEY_ID,
        secret=SECRET,
        sdk_version="0.0.1",
        poll_interval=1.0,
        client=cp.client(),
        time_fn=lambda: float(TS),
        sleep_fn=clock.sleep,
        monotonic_fn=clock.monotonic,
    )


def _pause_request(ref: str = "3f8b1c2a-9d4e-4f6a-8b1c-2a9d4e4f6a8b") -> PauseRequest:
    return PauseRequest(
        approval_ref=ref,
        run_id="run_9d1f2e3a4b5c6d7e8f9a0b1c2d3e4f50",
        action_type="refund.create",
        summary="Refund invoice inv_42 (12.50 EUR) to customer cus_8xq",
        requested_at=datetime(2026, 7, 11, 3, 59, 20, 0, tzinfo=UTC),
        cost=Money(amount="12.5", currency="EUR"),
        reversibility=Reversibility.IRREVERSIBLE,
        blast_radius_estimate=BlastRadius.LOW,
    )


# ===========================================================================
# 1. The boundary — the wire body is EXACTLY the frozen allowlist.
# ===========================================================================


def test_wire_model_fields_are_exactly_the_frozen_allowlist() -> None:
    assert set(ApprovalRequestWire.model_fields) == set(WIRE_ALLOWLIST)


def test_wire_reproduces_the_golden_vector_body_and_signature() -> None:
    """The emitted create bytes ARE the /contracts reference vector, and sign to
    the reference signature — the bytes signed are the bytes sent."""
    with open(_contracts_path("examples/signing_vectors.json"), encoding="utf-8") as handle:
        vectors = json.load(handle)["vectors"]
    vec = next(v for v in vectors if v["name"] == "create_approval_post")
    wire = ApprovalRequestWire.from_pause_request(_pause_request(), sdk_version="0.0.1")
    body = wire.to_json_bytes()
    assert body.decode("utf-8") == vec["raw_body"]
    ref_secret = "sk_live_airlock_reference_vector_secret_do_not_use"
    signature = sign(
        ref_secret,
        timestamp=vec["timestamp"],
        method="POST",
        path_with_query="/api/v1/approvals",
        raw_body=body,
    )
    assert signature == vec["signature"]


def test_wire_forbids_a_smuggled_field() -> None:
    """extra='forbid' makes a payload/idempotency_key structurally impossible."""
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


# ===========================================================================
# 2. send — signed, verifying, idempotent, approval_id captured.
# ===========================================================================


def test_send_produces_a_verifying_signed_request_with_allowlist_body() -> None:
    cp = FakeControlPlane()
    transport = _transport(cp)
    receipt = transport.send(_pause_request())
    assert receipt.approval_id is not None
    # The server verified the signature (else it 401'd and send would raise);
    # assert the captured body carries ONLY allowlisted keys, nothing more. The
    # optional review_context is absent here, so the body is the required subset.
    method, path, raw = cp.requests[-1]
    assert (method, path) == ("POST", "/api/v1/approvals")
    body = json.loads(raw)
    assert set(body) <= set(WIRE_ALLOWLIST)
    # The optional metadata fields are absent here, so the body is the required
    # subset (no review_context, no reject_reasons).
    assert set(body) == set(WIRE_ALLOWLIST) - {"review_context", "reject_reasons"}


def test_send_with_review_context_carries_it_on_the_wire() -> None:
    """A PauseRequest with review_context reaches the wire body (strings-only)."""
    cp = FakeControlPlane()
    transport = _transport(cp)
    request = PauseRequest(
        approval_ref="3f8b1c2a-9d4e-4f6a-8b1c-2a9d4e4f6a8b",
        run_id="run_9d1f2e3a4b5c6d7e8f9a0b1c2d3e4f50",
        action_type="refund.create",
        summary="Refund invoice inv_42 (12.50 EUR) to customer cus_8xq",
        requested_at=datetime(2026, 7, 11, 3, 59, 20, 0, tzinfo=UTC),
        cost=Money(amount="12.5", currency="EUR"),
        reversibility=Reversibility.IRREVERSIBLE,
        blast_radius_estimate=BlastRadius.LOW,
        review_context={
            "customer": "acme@co",
            "order": "#1832",
            "reason": "item defective, refund approved by support",
        },
    )
    transport.send(request)
    _method, _path, raw = cp.requests[-1]
    body = json.loads(raw)
    assert set(body) <= set(WIRE_ALLOWLIST)
    assert body["review_context"] == {
        "customer": "acme@co",
        "order": "#1832",
        "reason": "item defective, refund approved by support",
    }


def test_send_with_review_context_reproduces_the_golden_vector() -> None:
    """The with-context create bytes ARE the /contracts with-context vector."""
    with open(_contracts_path("examples/signing_vectors.json"), encoding="utf-8") as handle:
        vectors = json.load(handle)["vectors"]
    vec = next(v for v in vectors if v["name"] == "create_approval_with_context_post")
    wire = ApprovalRequestWire.from_pause_request(
        PauseRequest(
            approval_ref="3f8b1c2a-9d4e-4f6a-8b1c-2a9d4e4f6a8b",
            run_id="run_9d1f2e3a4b5c6d7e8f9a0b1c2d3e4f50",
            action_type="refund.create",
            summary="Refund invoice inv_42 (12.50 EUR) to customer cus_8xq",
            requested_at=datetime(2026, 7, 11, 3, 59, 20, 0, tzinfo=UTC),
            cost=Money(amount="12.5", currency="EUR"),
            reversibility=Reversibility.IRREVERSIBLE,
            blast_radius_estimate=BlastRadius.LOW,
            review_context={
                "customer": "acme@co",
                "order": "#1832",
                "reason": "item defective, refund approved by support",
            },
        ),
        sdk_version="0.0.1",
    )
    assert wire.to_json_bytes().decode("utf-8") == vec["raw_body"]


def test_send_with_reject_reasons_carries_it_on_the_wire() -> None:
    """A PauseRequest with reject_reasons reaches the wire body (strings-only)."""
    cp = FakeControlPlane()
    transport = _transport(cp)
    request = PauseRequest(
        approval_ref="3f8b1c2a-9d4e-4f6a-8b1c-2a9d4e4f6a8b",
        run_id="run_9d1f2e3a4b5c6d7e8f9a0b1c2d3e4f50",
        action_type="refund.create",
        summary="Refund invoice inv_42 (12.50 EUR) to customer cus_8xq",
        requested_at=datetime(2026, 7, 11, 3, 59, 20, 0, tzinfo=UTC),
        cost=Money(amount="12.5", currency="EUR"),
        reversibility=Reversibility.IRREVERSIBLE,
        blast_radius_estimate=BlastRadius.LOW,
        reject_reasons={
            "needs_more_info": "Needs more information",
            "not_authorized": "Not authorized for this amount",
            "duplicate": "Looks like a duplicate request",
        },
    )
    transport.send(request)
    _method, _path, raw = cp.requests[-1]
    body = json.loads(raw)
    assert set(body) <= set(WIRE_ALLOWLIST)
    assert body["reject_reasons"] == {
        "needs_more_info": "Needs more information",
        "not_authorized": "Not authorized for this amount",
        "duplicate": "Looks like a duplicate request",
    }


def test_send_with_reject_reasons_reproduces_the_golden_vector() -> None:
    """The with-reject_reasons create bytes ARE the /contracts vector (P3.9)."""
    with open(_contracts_path("examples/signing_vectors.json"), encoding="utf-8") as handle:
        vectors = json.load(handle)["vectors"]
    vec = next(v for v in vectors if v["name"] == "create_approval_with_reject_reasons_post")
    wire = ApprovalRequestWire.from_pause_request(
        PauseRequest(
            approval_ref="3f8b1c2a-9d4e-4f6a-8b1c-2a9d4e4f6a8b",
            run_id="run_9d1f2e3a4b5c6d7e8f9a0b1c2d3e4f50",
            action_type="refund.create",
            summary="Refund invoice inv_42 (12.50 EUR) to customer cus_8xq",
            requested_at=datetime(2026, 7, 11, 3, 59, 20, 0, tzinfo=UTC),
            cost=Money(amount="12.5", currency="EUR"),
            reversibility=Reversibility.IRREVERSIBLE,
            blast_radius_estimate=BlastRadius.LOW,
            reject_reasons={
                "needs_more_info": "Needs more information",
                "not_authorized": "Not authorized for this amount",
                "duplicate": "Looks like a duplicate request",
            },
        ),
        sdk_version="0.0.1",
    )
    body = wire.to_json_bytes()
    assert body.decode("utf-8") == vec["raw_body"]
    ref_secret = "sk_live_airlock_reference_vector_secret_do_not_use"
    signature = sign(
        ref_secret,
        timestamp=vec["timestamp"],
        method="POST",
        path_with_query="/api/v1/approvals",
        raw_body=body,
    )
    assert signature == vec["signature"]


def test_send_is_idempotent_200_and_201_both_accepted() -> None:
    cp = FakeControlPlane()
    transport = _transport(cp)
    r1 = transport.send(_pause_request())  # 201 create
    r2 = transport.send(_pause_request())  # 200 replay (same approval_ref)
    assert r1.approval_id == r2.approval_id
    assert cp.create_calls == 2  # both calls reached the server (redelivery-safe)
    assert len(cp.by_ref) == 1  # ...but only ONE approval exists


def test_send_raises_on_bad_status() -> None:
    cp = FakeControlPlane(secret="sk_live_a_different_secret_entirely")  # sig won't verify
    transport = _transport(cp)
    with pytest.raises(ApprovalTransportError) as exc:
        transport.send(_pause_request())
    assert exc.value.status_code == 401
    assert exc.value.code == "invalid_signature"


# ===========================================================================
# 3. wait / fetch_decision — poll and map the decision.
# ===========================================================================


def test_wait_polls_until_decided_and_maps_the_decision() -> None:
    cp = FakeControlPlane()
    clock = _StepClock()
    transport = _transport(cp, clock)
    ref = _pause_request().approval_ref
    transport.send(_pause_request())

    # Not decided yet: wait times out to None WITHOUT sleeping past the deadline.
    assert transport.wait(ref, timeout=0.0) is None

    cp.decide(ref, "approved", decided_by="usr_reviewer1", decision_latency_ms=4200)
    decision = transport.wait(ref, timeout=10.0)
    assert decision is not None
    assert decision.decision is HumanDecision.APPROVED
    assert decision.decided_by == "usr_reviewer1"
    assert decision.decided_by_display == "alice@acme.example"
    assert decision.decision_latency_ms == 4200  # recorded VERBATIM (control-plane)


def test_wait_times_out_to_none_while_undecided() -> None:
    cp = FakeControlPlane()
    clock = _StepClock()
    transport = _transport(cp, clock)
    transport.send(_pause_request())
    assert transport.wait(_pause_request().approval_ref, timeout=3.0) is None
    assert clock.t <= 4.0  # a few polls, bounded — never a wall-clock sleep


def test_fetch_decision_rejected_maps_and_undecided_is_none() -> None:
    cp = FakeControlPlane()
    transport = _transport(cp)
    receipt = transport.send(_pause_request())
    assert receipt.approval_id is not None
    assert transport.fetch_decision(receipt.approval_id) is None  # still requested
    cp.decide(_pause_request().approval_ref, "rejected", reason="too risky")
    decision = transport.fetch_decision(receipt.approval_id)
    assert decision is not None and decision.decision is HumanDecision.REJECTED
    assert decision.reason == "too risky"


def test_wait_parses_reason_code_out_of_the_decision_response() -> None:
    """A rejection carrying reason_code (P3.9) is parsed onto the ApprovalDecision."""
    cp = FakeControlPlane()
    clock = _StepClock()
    transport = _transport(cp, clock)
    ref = _pause_request().approval_ref
    transport.send(_pause_request())
    cp.decide(ref, "rejected", reason="please attach the invoice", reason_code="needs_more_info")
    decision = transport.wait(ref, timeout=10.0)
    assert decision is not None and decision.decision is HumanDecision.REJECTED
    assert decision.reason_code == "needs_more_info"  # the chosen structured code
    assert decision.reason == "please attach the invoice"  # and the free-text note
    # An approval with no code leaves reason_code None.
    cp2 = FakeControlPlane()
    t2 = _transport(cp2)
    receipt = t2.send(_pause_request())
    assert receipt.approval_id is not None
    cp2.decide(_pause_request().approval_ref, "approved")
    approved = t2.fetch_decision(receipt.approval_id)
    assert approved is not None and approved.reason_code is None


# ===========================================================================
# 4. The webhook receiver — verify-before-parse, resume once, dup no-op.
# ===========================================================================


def _signed_webhook(
    body: dict[str, Any], *, secret: str = SECRET, ts: int = TS, path: str = WEBHOOK_PATH
) -> tuple[bytes, dict[str, str]]:
    raw = json.dumps(body).encode("utf-8")
    signature = sign(secret, timestamp=ts, method="POST", path_with_query=path, raw_body=raw)
    headers = {
        HEADER_KEY: KEY_ID,
        HEADER_TIMESTAMP: str(ts),
        HEADER_SIGNATURE: signature,
        "content-type": "application/json",
    }
    return raw, headers


def _webhook_body(approval_ref: str, run_id: str, decision: str = "approved") -> dict[str, Any]:
    return {
        "event": "approval.decided",
        "delivery_id": "dl_test_0001",
        "approval_id": "apr_testwebhook",
        "approval_ref": approval_ref,
        "run_id": run_id,
        "decision": decision,
        "decided_by": "usr_reviewer1",
        "decided_by_display": "alice@acme.example",
        "decided_at": "2026-07-11T04:02:40.000000Z",
        "decision_latency_ms": 200000,
        "reason": None,
    }


def _call_asgi(
    app: Any, raw: bytes, headers: dict[str, str], *, method: str = "POST", path: str = WEBHOOK_PATH
) -> tuple[int, dict[str, Any]]:
    scope: dict[str, Any] = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()],
    }
    incoming = [{"type": "http.request", "body": raw, "more_body": False}]
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return incoming.pop(0)

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    payload = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, json.loads(payload)


def _gate_a_run(store: PostgresStore, database_url: str, invoice: str) -> tuple[str, str]:
    """Drive the real @guard GATE path (gate_wait=False) to durably pause a run.

    Returns (approval_ref, run_id). Uses the harness refund tool (registered in
    the process-wide registry by importing tests._pause_harness), so the
    receiver's apply_decision can rehydrate + resume it.
    """
    import os

    from airlock.errors import ActionPending
    from airlock.policy import Policy
    from airlock.transport import SendReceipt as _SR
    from airlock.types import Decision

    os.environ["AIRLOCK_TEST_DSN"] = database_url

    class _Stub:
        def send(self, request: PauseRequest) -> _SR:
            return SendReceipt(approval_ref=request.approval_ref)

        def wait(self, approval_ref: str, timeout: float) -> None:  # pragma: no cover
            return None

    init(store=store, policy=Policy(default=Decision.GATE), transport=_Stub(), gate_wait=False)
    try:
        harness.harness_refund(invoice)
    except ActionPending as pending:
        assert pending.approval_ref is not None and pending.run_id is not None
        return pending.approval_ref, pending.run_id
    raise AssertionError("gate must raise ActionPending under gate_wait=False")


def test_receiver_resumes_exactly_once_and_double_delivery_is_a_noop(
    store: PostgresStore, db: Engine, effects: EffectsLog, database_url: str
) -> None:
    invoice = "inv_recv_once"
    approval_ref, run_id = _gate_a_run(store, database_url, invoice)
    assert effects.count(effect_key(invoice)) == 0

    app = webhook_app(store, SECRET, verify_now=lambda: float(TS))
    raw, headers = _signed_webhook(_webhook_body(approval_ref, run_id))

    # First delivery: resumes and commits exactly once.
    status1, body1 = _call_asgi(app, raw, headers)
    assert status1 == 200 and body1["status"] == "committed"
    # Second (duplicate) delivery: a safe no-op — still 200, one effect only.
    status2, body2 = _call_asgi(app, raw, headers)
    assert status2 == 200 and body2["status"] == "committed"

    assert effects.count(effect_key(invoice)) == 1  # EXACTLY ONE effect
    run = store.load_paused_by_ref(approval_ref)
    assert run is not None and run.status is PauseStatus.COMMITTED


def test_receiver_rejects_a_tampered_body_401(
    store: PostgresStore, db: Engine, database_url: str
) -> None:
    approval_ref, run_id = _gate_a_run(store, database_url, "inv_tamper")
    app = webhook_app(store, SECRET, verify_now=lambda: float(TS))
    raw, headers = _signed_webhook(_webhook_body(approval_ref, run_id))
    tampered = raw.replace(b"approved", b"rejected")  # body no longer matches the signature
    status, body = _call_asgi(app, tampered, headers)
    assert status == 401 and body["code"] == "invalid_signature"
    # Nothing was applied: the run is still proposed.
    run = store.load_paused_by_ref(approval_ref)
    assert run is not None and run.status is PauseStatus.PROPOSED


def test_receiver_rejects_a_replayed_timestamp_401(
    store: PostgresStore, db: Engine, database_url: str
) -> None:
    approval_ref, run_id = _gate_a_run(store, database_url, "inv_replay")
    # Verifier's clock is far past the signed timestamp -> outside the ±300s window.
    app = webhook_app(store, SECRET, verify_now=lambda: float(TS + 10_000))
    raw, headers = _signed_webhook(_webhook_body(approval_ref, run_id), ts=TS)
    status, body = _call_asgi(app, raw, headers)
    assert status == 401 and body["code"] == "invalid_signature"


def test_receiver_unknown_ref_is_404(store: PostgresStore, db: Engine, database_url: str) -> None:
    app = webhook_app(store, SECRET, verify_now=lambda: float(TS))
    raw, headers = _signed_webhook(
        _webhook_body("11111111-2222-3333-4444-555555555555", "run_never_seen")
    )
    status, body = _call_asgi(app, raw, headers)
    assert status == 404 and body["code"] == "unknown_approval_ref"


def test_receiver_non_post_is_405(store: PostgresStore, db: Engine) -> None:
    app = webhook_app(store, SECRET, verify_now=lambda: float(TS))
    status, _body = _call_asgi(app, b"", {}, method="GET")
    assert status == 405


# ===========================================================================
# 5. The backstop poll — recover a decision when NO webhook arrived.
# ===========================================================================


def test_backstop_poll_recovers_a_decision_with_one_effect(
    clock_store: PostgresStore,
    db: Engine,
    effects: EffectsLog,
    database_url: str,
    fake_clock: FakeClock,
) -> None:
    """A proposed run with a persisted approval_id whose webhook never arrived is
    recovered by polling the control plane and driving apply_decision once."""
    invoice = "inv_backstop"
    approval_ref, run_id = _gate_a_run(clock_store, database_url, invoice)
    cp = FakeControlPlane()
    transport = _transport(cp)
    # The GATE path would persist the approval_id from send's receipt; here the
    # run was gated with a local stub, so seed the hosted approval + the id the
    # backstop polls on (exactly what the create response carries).
    receipt = transport.send(
        PauseRequest(
            approval_ref=approval_ref,
            run_id=run_id,
            action_type=GATE_ACTION,
            summary=GATE_ACTION,
            requested_at=fake_clock(),
        )
    )
    assert receipt.approval_id is not None
    assert clock_store.set_approval_id(run_id, receipt.approval_id)

    # No webhook ever arrives; the decision lands only on the control plane.
    cp.decide(approval_ref, "approved", decided_by="usr_backstop")

    # Too fresh: the backstop scan skips it (created_at not past the threshold).
    report0 = backstop_poll_paused(clock_store, transport, older_than=timedelta(minutes=5))
    assert report0.total == 0

    fake_clock.advance(600)  # now the proposed run is stale enough to poll
    report = backstop_poll_paused(clock_store, transport, older_than=timedelta(minutes=5))
    assert report.count("committed") == 1
    assert effects.count(effect_key(invoice)) == 1
    run = clock_store.load_paused_by_ref(approval_ref)
    assert run is not None and run.status is PauseStatus.COMMITTED


def test_backstop_poll_leaves_undecided_runs_proposed(
    clock_store: PostgresStore,
    db: Engine,
    effects: EffectsLog,
    database_url: str,
    fake_clock: FakeClock,
) -> None:
    invoice = "inv_backstop_undecided"
    approval_ref, run_id = _gate_a_run(clock_store, database_url, invoice)
    cp = FakeControlPlane()
    transport = _transport(cp)
    receipt = transport.send(
        PauseRequest(
            approval_ref=approval_ref,
            run_id=run_id,
            action_type=GATE_ACTION,
            summary=GATE_ACTION,
            requested_at=fake_clock(),
        )
    )
    assert receipt.approval_id is not None
    clock_store.set_approval_id(run_id, receipt.approval_id)

    fake_clock.advance(600)
    report = backstop_poll_paused(clock_store, transport, older_than=timedelta(minutes=5))
    assert report.count("undecided") == 1  # control plane still 'requested'
    assert effects.count(effect_key(invoice)) == 0
    run = clock_store.load_paused_by_ref(approval_ref)
    assert run is not None and run.status is PauseStatus.PROPOSED


def _contracts_path(rel: str) -> str:
    import os

    here = os.path.dirname(__file__)
    return os.path.join(here, "..", "contracts", rel)
