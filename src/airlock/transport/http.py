"""``HttpApprovalTransport`` + ``webhook_app`` — the signed-HTTP join (P3.4).

This is where the SDK (in the customer's process) finally talks to the hosted
control plane (``airlock-cloud``) over the real signed wire contract
(``/contracts/openapi.yaml`` + ``signing.md``). It is deliberately the whole of
the three-call contract and nothing more (PLAN.md 6.2):

- :class:`HttpApprovalTransport` makes the two SDK -> cloud calls. ``send``
  POSTs ``/api/v1/approvals`` (call #1, idempotent on the SDK-minted
  ``approval_ref``); the poll (``wait`` / :meth:`~HttpApprovalTransport.
  fetch_decision`) GETs ``/api/v1/approvals/{approval_id}`` (call #2 — the
  reconciler backstop). Both are HMAC-signed via :mod:`airlock._signing`.
- :func:`webhook_app` is a tiny, dependency-light ASGI receiver for call #3
  (the ``approval.decided`` push, cloud -> customer): it verifies the HMAC on
  the RAW body BEFORE parsing, then drives the decision through
  :func:`airlock.pause.apply_decision` (ADR-4 ensure-committed) so a redelivery
  is a safe no-op (SPEC scenario 5). The fast path (push) and the backstop
  (poll) both funnel into the SAME ``apply_decision``, so nothing double-commits
  regardless of which arrives first or how many times.

Boundary (PLAN.md 6.1, compliance-critical). ``send`` builds the wire body ONLY
via :class:`ApprovalRequestWire` — a frozen, ``extra="forbid"`` model whose
field set IS the allowlist (asserted in CI). A local :class:`~airlock.transport.
PauseRequest` structurally cannot carry tool args / ``idempotency_key`` /
results, and the wire model has no field for them either, so a smuggled payload
is impossible by construction — not merely discouraged.

Import-light (PLAN.md 3.1). ``httpx`` lives in the ``http`` extra and is
imported LAZILY, inside the transport methods that make network calls — so
``import airlock`` (and even ``import airlock.transport.http`` for the receiver)
never pulls httpx onto the base-import path. The webhook receiver is httpx-free
entirely: a customer who only receives pushes needs no ``http`` extra.

The transport is touched ONLY on the GATE path, where a human is already the
latency floor (SPEC.md 3): the auto/deny hot path never imports or calls it.
"""

from __future__ import annotations

import time as _time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict

from airlock import __version__
from airlock._signing import (
    HEADER_KEY,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    sign,
    verify,
)
from airlock.audit import rfc3339_utc
from airlock.errors import AirlockError, UnknownApprovalRef
from airlock.transport import PauseRequest, SendReceipt
from airlock.types import ApprovalDecision, BlastRadius, HumanDecision, Money, Reversibility

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, MutableMapping, Sequence

    import httpx

    from airlock.events import EventSink
    from airlock.registry import Registry
    from airlock.store import Store

__all__ = [
    "WIRE_ALLOWLIST",
    "ApprovalRequestWire",
    "ApprovalTransportError",
    "HttpApprovalTransport",
    "WebhookReceiver",
    "webhook_app",
]

#: The FROZEN egress allowlist (PLAN.md 6.1 / openapi.yaml CreateApprovalRequest).
#: ``ApprovalRequestWire.model_fields`` is asserted EQUAL to this in CI — the
#: structural half of the boundary: there is no field here for tool args,
#: ``idempotency_key``, ``downstream_key``, results, ``serialized_state``, or
#: audit rows, so none can transit. Changing it is a contract-version bump.
WIRE_ALLOWLIST = frozenset(
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
    }
)

#: The ``approval.decided`` webhook body's ``event`` discriminator (openapi.yaml).
_WEBHOOK_EVENT = "approval.decided"


class ApprovalTransportError(AirlockError):
    """A control-plane HTTP call returned an unexpected status or shape.

    Raised by :class:`HttpApprovalTransport` when a signed call gets a status
    outside the contract's success set (a create that is neither 200 nor 201, a
    poll that is neither 200 nor a decided/undecided 200, an unexpected 4xx/5xx).
    Carries the ``status_code`` and any error ``code``/``message`` the control
    plane returned so a caller can distinguish an auth failure (401) from a bad
    request (400) without re-parsing the body.

    Attributes:
        status_code: the HTTP status the control plane returned.
        code: the machine error token from the body (e.g. ``invalid_signature``),
            or ``None`` when the body carried none.
    """

    def __init__(self, message: str, *, status_code: int, code: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code


class ApprovalRequestWire(BaseModel):
    """The ``POST /api/v1/approvals`` body — EXACTLY the frozen allowlist.

    ``extra="forbid"`` + the field set being :data:`WIRE_ALLOWLIST` is the
    structural boundary (PLAN.md 6.1): raw payloads have no code path here, and
    a stray key raises at construction rather than silently transiting. Built
    ONLY via :meth:`from_pause_request`, which maps every field explicitly from
    a boundary-safe :class:`~airlock.transport.PauseRequest`. ``frozen`` so a
    request cannot be mutated after it is signed.

    Serialization is pydantic's compact ``model_dump_json`` in field-definition
    order, which reproduces the ``/contracts`` reference-vector bytes for the
    create call byte-for-byte (the signing golden values) — the bytes that are
    signed are the bytes that are sent (signing.md §2).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    approval_ref: str
    run_id: str
    action_type: str
    action_summary: str
    cost: Money | None
    reversibility: Reversibility
    blast_radius_estimate: BlastRadius | None
    requested_at: str
    sdk_version: str

    @classmethod
    def from_pause_request(cls, request: PauseRequest, *, sdk_version: str) -> ApprovalRequestWire:
        """Map a local :class:`~airlock.transport.PauseRequest` onto the wire body.

        Every field is mapped explicitly (never a splat). ``summary`` becomes
        ``action_summary``; a ``None`` reversibility becomes the conservative
        ``unknown`` (the wire enum has no null); ``requested_at`` is formatted as
        the airlock-canon-1 RFC 3339 string. There is no branch that could copy
        an arg, a key, or a result — those do not exist on ``PauseRequest``.
        """
        return cls(
            approval_ref=request.approval_ref,
            run_id=request.run_id,
            action_type=request.action_type,
            action_summary=request.summary,
            cost=request.cost,
            reversibility=(
                request.reversibility
                if request.reversibility is not None
                else Reversibility.UNKNOWN
            ),
            blast_radius_estimate=request.blast_radius_estimate,
            requested_at=rfc3339_utc(request.requested_at),
            sdk_version=sdk_version,
        )

    def to_json_bytes(self) -> bytes:
        """The exact request-body bytes to sign and send (compact, ordered)."""
        return self.model_dump_json().encode("utf-8")


def _default_time() -> float:
    return _time.time()


def _utcnow() -> datetime:
    return datetime.now(UTC)


class HttpApprovalTransport:
    """A signed-HTTP :class:`~airlock.transport.ApprovalTransport` (P3.4).

    Makes the two SDK -> cloud calls of the wire contract against the hosted
    control plane, each HMAC-signed with the per-customer secret. The webhook
    (call #3) is a SEPARATE receiver (:func:`webhook_app`) the customer mounts —
    this class never receives.

    Args:
        base_url: the control-plane origin, e.g. ``https://api.airlock.dev``.
        key_id: the ``ak_live_…`` key id, sent as ``Airlock-Key``.
        secret: the ``sk_live_…`` secret token — the HMAC key (its UTF-8 bytes,
            verbatim; signing.md §3). Signs both the create and the poll.
        timeout: per-request timeout in seconds (default 10).
        sdk_version: the ``sdk_version`` stamped on the create body (default the
            installed :data:`airlock.__version__`); diagnostics only, carries no
            payload.
        poll_interval: seconds between polls in :meth:`wait` (default 1.0). Only
            slept BETWEEN polls — a decision already present, or a zero
            ``timeout``, returns without sleeping.
        client: an httpx ``Client`` to use (tests pass one wrapping an
            ``httpx.MockTransport`` so there is NO real network). ``None`` builds
            a real client lazily on first use, from ``base_url`` + ``timeout``.
        time_fn: unix-seconds source for the signature timestamp (injectable so
            signing is deterministic in tests). Defaults to the wall clock.
        sleep_fn / monotonic_fn: injectable clock hooks for :meth:`wait`
            (default the real ``time.sleep`` / ``time.monotonic``) — the
            no-time.sleep test guard governs any accidental blocking wait.
    """

    def __init__(
        self,
        *,
        base_url: str,
        key_id: str,
        secret: str,
        timeout: float = 10.0,
        sdk_version: str | None = None,
        poll_interval: float = 1.0,
        client: httpx.Client | None = None,
        time_fn: Callable[[], float] | None = None,
        sleep_fn: Callable[[float], None] | None = None,
        monotonic_fn: Callable[[], float] | None = None,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError(f"poll_interval must be > 0, got {poll_interval!r}")
        self._base_url = base_url.rstrip("/")
        self._key_id = key_id
        self._secret = secret
        self._timeout = timeout
        self._sdk_version = sdk_version if sdk_version is not None else __version__
        self._poll_interval = poll_interval
        self._client = client
        self._time_fn = time_fn if time_fn is not None else _default_time
        self._sleep_fn = sleep_fn
        self._monotonic_fn = monotonic_fn
        # approval_ref -> approval_id, populated on send so the inline wait()
        # (same process, right after send) can poll GET /{approval_id}. The
        # DURABLE source for a fresh process is paused_runs.approval_id (the
        # @guard GATE path persists the receipt) — the reconciler backstop uses
        # fetch_decision(approval_id) directly with that.
        self._approval_ids: dict[str, str] = {}

    # -- lifecycle ---------------------------------------------------------

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            import httpx  # lazy: keep httpx off the base-import path (PLAN.md 3.1)

            self._client = httpx.Client(base_url=self._base_url, timeout=self._timeout)
        return self._client

    def close(self) -> None:
        """Close the underlying httpx client, if one was built/owned."""
        if self._client is not None:
            self._client.close()

    # -- call #1: create ---------------------------------------------------

    def send(self, request: PauseRequest) -> SendReceipt:
        """POST the approval (call #1) — idempotent, redelivery-safe.

        Maps the pause to the frozen wire body, signs the RAW bytes, and POSTs
        ``/api/v1/approvals``. A create (201) and an idempotent replay (200)
        are BOTH success (the server dedupes on ``approval_ref``); anything else
        raises :class:`ApprovalTransportError`. The hosted ``approval_id`` from
        the response is cached (for :meth:`wait`) and returned on the receipt so
        the GATE path can persist it on ``paused_runs`` for the backstop poll.
        """
        wire = ApprovalRequestWire.from_pause_request(request, sdk_version=self._sdk_version)
        raw = wire.to_json_bytes()
        response = self._request("POST", "/api/v1/approvals", raw)
        if response.status_code not in (200, 201):
            raise self._error("create approval", response)
        approval_id = self._json(response).get("approval_id")
        if isinstance(approval_id, str):
            self._approval_ids[request.approval_ref] = approval_id
        return SendReceipt(
            approval_ref=request.approval_ref,
            approval_id=approval_id if isinstance(approval_id, str) else None,
        )

    # -- call #2: poll (the reconciler backstop) ---------------------------

    def fetch_decision(self, approval_id: str) -> ApprovalDecision | None:
        """GET the approval's decision (call #2) — one signed poll, no waiting.

        Returns an :class:`~airlock.types.ApprovalDecision` once the control
        plane reports ``approved``/``rejected`` (recording
        ``decision_latency_ms`` VERBATIM — it is control-plane-computed, PLAN.md
        6.2), or ``None`` while still ``requested``. This is the primitive the
        reconciler backstop drives through ``apply_decision`` when a webhook
        never arrived (endpoint down / exhausted). Raises
        :class:`ApprovalTransportError` on any non-200 (a persisted
        ``approval_id`` should never 404).
        """
        path = f"/api/v1/approvals/{approval_id}"
        response = self._request("GET", path, b"")
        if response.status_code != 200:
            raise self._error("get approval", response)
        return self._decision_from_get(self._json(response))

    def wait(self, approval_ref: str, timeout: float) -> ApprovalDecision | None:
        """Poll GET /{approval_id} until decided or ``timeout`` — the inline path.

        Resolves ``approval_ref`` to the ``approval_id`` cached by :meth:`send`
        in THIS process, then polls :meth:`fetch_decision` every
        ``poll_interval`` seconds until a decision lands or ``timeout`` elapses
        (returning ``None`` — never raising for "no decision yet"; the pause
        stays durable and the backstop resumes it later). If ``send`` was not
        called in this process (no cached ``approval_id``), returns ``None``
        immediately: a fresh process resumes through the reconciler backstop
        (``fetch_decision`` with the persisted id), not this inline loop.
        """
        approval_id = self._approval_ids.get(approval_ref)
        if approval_id is None:
            return None
        deadline = self._monotonic() + timeout
        while True:
            decision = self.fetch_decision(approval_id)
            if decision is not None:
                return decision
            if self._monotonic() >= deadline:
                return None
            self._do_sleep(self._poll_interval)

    # -- signing + HTTP plumbing ------------------------------------------

    def _request(self, method: str, path: str, raw_body: bytes) -> httpx.Response:
        """Sign ``(method, path, raw_body)`` and issue the request over httpx.

        The signature covers the EXACT bytes sent (signing.md §2): the body is
        passed to httpx as ``content=raw_body`` (never re-serialized), and the
        signed ``path`` is the request target exactly as sent.
        """
        timestamp = str(int(self._time_fn()))
        signature = sign(
            self._secret,
            timestamp=timestamp,
            method=method,
            path_with_query=path,
            raw_body=raw_body,
        )
        headers = {
            HEADER_KEY: self._key_id,
            HEADER_TIMESTAMP: timestamp,
            HEADER_SIGNATURE: signature,
            "Content-Type": "application/json",
        }
        client = self._get_client()
        return client.request(method, path, content=raw_body, headers=headers)

    def _decision_from_get(self, data: dict[str, Any]) -> ApprovalDecision | None:
        status = data.get("status")
        if status not in ("approved", "rejected"):
            return None  # still 'requested' — no decision yet
        decision = HumanDecision.APPROVED if status == "approved" else HumanDecision.REJECTED
        return ApprovalDecision(
            decision=decision,
            decided_by=_opt_str(data.get("decided_by")),
            decided_by_display=_opt_str(data.get("decided_by_display")),
            decided_at=_parse_rfc3339(data.get("decided_at")),
            decision_latency_ms=_opt_int(data.get("decision_latency_ms")),
            reason=_opt_str(data.get("reason")),
        )

    @staticmethod
    def _json(response: httpx.Response) -> dict[str, Any]:
        try:
            body = response.json()
        except ValueError as exc:
            raise ApprovalTransportError(
                f"control plane returned a non-JSON body (status {response.status_code})",
                status_code=response.status_code,
            ) from exc
        if not isinstance(body, dict):
            raise ApprovalTransportError(
                f"control plane returned a non-object JSON body (status {response.status_code})",
                status_code=response.status_code,
            )
        return body

    @staticmethod
    def _error(what: str, response: httpx.Response) -> ApprovalTransportError:
        code: str | None = None
        message: str = ""
        try:
            body = response.json()
        except ValueError:
            body = None
        if isinstance(body, dict):
            raw_code = body.get("code")
            code = raw_code if isinstance(raw_code, str) else None
            raw_message = body.get("message")
            message = raw_message if isinstance(raw_message, str) else ""
        return ApprovalTransportError(
            f"{what} failed: HTTP {response.status_code}"
            + (f" ({code}: {message})" if code else ""),
            status_code=response.status_code,
            code=code,
        )

    def _monotonic(self) -> float:
        return self._monotonic_fn() if self._monotonic_fn is not None else _time.monotonic()

    def _do_sleep(self, seconds: float) -> None:
        if self._sleep_fn is not None:
            self._sleep_fn(seconds)
        else:
            _time.sleep(seconds)  # live: production sleeps; the test guard governs it


# ===========================================================================
# The webhook receiver (call #3, cloud -> customer) — a raw ASGI app.
# ===========================================================================


class WebhookReceiver:
    """A dependency-light ASGI receiver for the ``approval.decided`` push.

    A customer with an inbound endpoint mounts this (any ASGI server) with
    access to their :class:`~airlock.store.Store` and their signing ``secret``.
    Per request it: reads the RAW body, verifies the airlock-v1 HMAC on those
    bytes BEFORE parsing (bad signature / outside the ±300s window -> 401), then
    drives the decision through :func:`airlock.pause.apply_decision` (ADR-4
    ensure-committed) keyed on ``approval_ref``. Because ``apply_decision``
    dedupes on ``approval_ref`` and the commit LEDGER guards double-commit, a
    redelivery (at-least-once from the control plane, SPEC scenario 5) is a safe
    no-op returning 200 — exactly one effect regardless of how many pushes land.

    Status codes: 200 accepted (incl. a duplicate no-op); 401 bad/replayed
    signature; 400 malformed body or missing/invalid fields; 404 no paused run
    for the ``approval_ref`` (a decision this DB never proposed — wrong
    environment); 405 non-POST; 500 an unexpected recovery error (the control
    plane retries — e.g. the tool module is not imported yet). httpx is NOT
    imported here: a receive-only customer needs no ``http`` extra.

    Args mirror ``apply_decision``'s recovery wiring: ``store`` (the pause rows +
    ledger + audit chain), ``secret`` (the per-customer HMAC key), ``registry``
    (where an approved run finds its execute/effect/preconditions; defaults to
    the process-wide one ``@guard`` populates), ``event_sinks``,
    ``reconcile_after`` / ``execute_timeout`` (forwarded to ``commit_once``),
    ``wait_timeout``, and ``now_fn`` (the injectable clock).
    """

    def __init__(
        self,
        store: Store,
        secret: str,
        *,
        registry: Registry | None = None,
        event_sinks: Sequence[EventSink] = (),
        reconcile_after: timedelta | None = None,
        execute_timeout: timedelta | None = None,
        wait_timeout: float = 30.0,
        now_fn: Callable[[], datetime] | None = None,
        verify_now: Callable[[], float] | None = None,
    ) -> None:
        self._store = store
        self._secret = secret
        self._registry = registry
        self._event_sinks = tuple(event_sinks)
        self._reconcile_after = reconcile_after
        self._execute_timeout = execute_timeout
        self._wait_timeout = wait_timeout
        self._now_fn = now_fn if now_fn is not None else _utcnow
        self._verify_now = verify_now

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
        send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":  # pragma: no cover — mounted as an HTTP app
            raise ValueError(f"WebhookReceiver only serves http, got {scope['type']!r}")
        if scope["method"].upper() != "POST":
            await _respond(send, 405, {"code": "method_not_allowed", "message": "POST only."})
            return

        raw_body = await _read_body(receive)
        status, body = self._handle(scope, raw_body)
        await _respond(send, status, body)

    def _handle(
        self, scope: MutableMapping[str, Any], raw_body: bytes
    ) -> tuple[int, dict[str, Any]]:
        """Verify (raw bytes, before parse) then drive apply_decision. Sync core."""
        headers = _decode_headers(scope.get("headers", ()))
        path_with_query = _path_with_query(scope)
        ok = verify(
            self._secret,
            headers=headers,
            method=scope["method"],
            path_with_query=path_with_query,
            raw_body=raw_body,
            now=self._verify_now() if self._verify_now is not None else None,
        )
        if not ok:
            return 401, {
                "code": "invalid_signature",
                "message": "Missing or invalid signature, or timestamp outside the window.",
            }

        parsed = _parse_webhook(raw_body)
        if parsed is None:
            return 400, {"code": "malformed_body", "message": "Invalid approval.decided body."}
        approval_ref, decision = parsed

        from airlock.pause import apply_decision  # local: avoid any import cycle

        try:
            outcome = apply_decision(
                self._store,
                approval_ref,
                decision,
                registry=self._registry,
                event_sinks=self._event_sinks,
                reconcile_after=self._reconcile_after,
                execute_timeout=self._execute_timeout,
                wait_timeout=self._wait_timeout,
                now_fn=self._now_fn,
            )
        except UnknownApprovalRef:
            return 404, {
                "code": "unknown_approval_ref",
                "message": "No paused run for this approval_ref in this environment.",
            }
        return 200, {"status": outcome.status.value, "applied": outcome.applied}


def webhook_app(
    store: Store,
    secret: str,
    *,
    registry: Registry | None = None,
    event_sinks: Sequence[EventSink] = (),
    reconcile_after: timedelta | None = None,
    execute_timeout: timedelta | None = None,
    wait_timeout: float = 30.0,
    now_fn: Callable[[], datetime] | None = None,
    verify_now: Callable[[], float] | None = None,
) -> WebhookReceiver:
    """Build the mountable ASGI :class:`WebhookReceiver` (convenience factory)."""
    return WebhookReceiver(
        store,
        secret,
        registry=registry,
        event_sinks=event_sinks,
        reconcile_after=reconcile_after,
        execute_timeout=execute_timeout,
        wait_timeout=wait_timeout,
        now_fn=now_fn,
        verify_now=verify_now,
    )


# --- ASGI + parsing helpers -------------------------------------------------


async def _read_body(
    receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
) -> bytes:
    """Concatenate the request body across ASGI ``http.request`` chunks."""
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] != "http.request":  # pragma: no cover — disconnect
            break
        chunks.append(message.get("body", b"") or b"")
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


async def _respond(
    send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    status: int,
    body: dict[str, Any],
) -> None:
    import json

    payload = json.dumps(body).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": payload})


def _decode_headers(raw_headers: Any) -> dict[str, str]:
    """ASGI ``[(bytes, bytes), ...]`` -> ``{str: str}`` (latin-1, HTTP-safe)."""
    return {key.decode("latin-1"): value.decode("latin-1") for key, value in raw_headers}


def _path_with_query(scope: MutableMapping[str, Any]) -> str:
    """The signed request target — path plus ``?query`` if present (signing.md §2)."""
    path = scope.get("path") or "/"
    query = scope.get("query_string") or b""
    if query:
        return f"{path}?{query.decode('latin-1')}"
    return path


def _parse_webhook(raw_body: bytes) -> tuple[str, ApprovalDecision] | None:
    """Parse a verified ``approval.decided`` body into ``(approval_ref, decision)``.

    Returns ``None`` for anything that is not a well-formed decided webhook (bad
    JSON, wrong ``event``, missing ``approval_ref``, or a ``decision`` outside
    ``approved|rejected``) so the caller can 400. ``decision_latency_ms`` is
    carried VERBATIM (control-plane-computed, PLAN.md 6.2).
    """
    import json

    try:
        data = json.loads(raw_body)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("event") != _WEBHOOK_EVENT:
        return None
    approval_ref = data.get("approval_ref")
    raw_decision = data.get("decision")
    if not isinstance(approval_ref, str) or raw_decision not in ("approved", "rejected"):
        return None
    decision = ApprovalDecision(
        decision=HumanDecision(raw_decision),
        decided_by=_opt_str(data.get("decided_by")),
        decided_by_display=_opt_str(data.get("decided_by_display")),
        decided_at=_parse_rfc3339(data.get("decided_at")),
        decision_latency_ms=_opt_int(data.get("decision_latency_ms")),
        reason=_opt_str(data.get("reason")),
    )
    return approval_ref, decision


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _opt_int(value: object) -> int | None:
    # bool subclasses int; a JSON true/false is not a latency.
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _parse_rfc3339(value: object) -> datetime | None:
    """Parse an RFC 3339 timestamp string; ``None`` if absent/malformed.

    A malformed value is treated as absent rather than failing the whole
    decision — ``apply_decision`` stamps the SDK clock when ``decided_at`` is
    missing (the console stub does the same).
    """
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None
