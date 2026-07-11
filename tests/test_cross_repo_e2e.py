"""THE Phase-3 Definition of Done, verbatim — the REAL cross-repo E2E (P3.4).

SPEC.md Phase 3 DoD: "an agent gates an action, it appears in the hosted inbox, a
human approves, the SDK commits exactly once, audit recorded."

This boots the REAL ``airlock-cloud`` Rails control plane against a local
Postgres (``bin/rails server`` on a spare port, ``RAILS_ENV=development`` — the
decision path is synchronous; the Sidekiq webhook job is NOT exercised, the
customer is seeded with a blank webhook_url so nothing enqueues, and NO
Redis is touched). It seeds a Customer with known creds via the
``airlock:seed_e2e_customer`` rake task, then drives the full join over real
signed HTTP:

1. a @guard-gated action with a real :class:`HttpApprovalTransport` -> POST
   creates the approval on the hosted control plane (call #1);
2. the approval appears in the hosted DB (asserted via a rails runner);
3. a human approves it (a seeded decision via ``Approval#decide`` in a runner —
   the control plane computes ``decision_latency_ms`` from its own clock pair);
4. the SDK resumes — BOTH the real backstop GET poll (call #2) AND the webhook
   receiver (call #3, a signed ``approval.decided`` body constructed from the
   real decision) — and ``commit_once`` fires EXACTLY ONCE (effects_log ground
   truth), incl. the duplicate-delivery variant (one effect);
5. the local audit chain verifies end to end.

Two DBs, correct split: the SDK's ledger/audit live in the customer's Postgres
(``airlock_test``); only approval metadata transits the hosted plane
(``airlock_cloud_development``).

Skipped automatically where ruby / the airlock-cloud repo is absent (normal
airlock-python CI). Point ``AIRLOCK_CLOUD_DIR`` at the cloud repo to run it; it
MUST pass locally (the P3.4 DoD).
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from airlock import init
from airlock._signing import (
    HEADER_KEY,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    sign,
)
from airlock.audit import verify_chain
from airlock.errors import ActionPending
from airlock.policy import Policy
from airlock.reconcile import backstop_poll_paused
from airlock.transport.http import HttpApprovalTransport, webhook_app
from airlock.types import Decision, HumanDecision, PauseStatus
from tests import _pause_harness as harness
from tests._pause_harness import effect_key

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore
    from tests.conftest import EffectsLog

# The cloud repo: env override, else the sibling of this repo.
_REPO_ROOT = Path(__file__).resolve().parent.parent
CLOUD_DIR = Path(os.environ.get("AIRLOCK_CLOUD_DIR", _REPO_ROOT.parent / "airlock-cloud"))

E2E_KEY_ID = "ak_live_crossrepo_e2e01"
E2E_SECRET = "sk_live_crossrepo_e2e_secret_value_do_not_use"
WEBHOOK_PATH = "/airlock/webhooks"

_SKIP_REASON = (
    "cross-repo E2E needs ruby + the airlock-cloud repo "
    f"(looked in {CLOUD_DIR}); set AIRLOCK_CLOUD_DIR to run it"
)
_CAN_RUN = bool(shutil.which("ruby")) and (CLOUD_DIR / "bin" / "rails").is_file()

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(not _CAN_RUN, reason=_SKIP_REASON),
]


# ---------------------------------------------------------------------------
# Booting the real Rails control plane.
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _rails_env() -> dict[str, str]:
    env = dict(os.environ)
    env["RAILS_ENV"] = "development"
    env["E2E_KEY_ID"] = E2E_KEY_ID
    env["E2E_SECRET"] = E2E_SECRET
    env.pop("E2E_WEBHOOK_URL", None)  # blank => no Sidekiq enqueue (no Redis)
    # CRITICAL: strip the SDK's DATABASE_URL (its own Postgres, airlock_test) so
    # Rails uses ITS OWN database.yml (airlock_cloud_development). Leaking it
    # would collapse the data-plane/control-plane split onto one physical DB —
    # the two-DB separation is the whole point (SPEC.md 3). Also strip any DB
    # overrides Rails would otherwise honor.
    for db_var in ("DATABASE_URL", "PGDATABASE", "PGHOST", "PGPORT", "PGUSER"):
        env.pop(db_var, None)
    return env


def _run(args: list[str], *, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(CLOUD_DIR),
        env=_rails_env(),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


@pytest.fixture(scope="module")
def rails_server() -> Iterator[str]:
    """Prepare the DB, seed the customer, boot ``bin/rails server``; yield base_url."""
    prepare = _run(["bin/rails", "db:prepare"])
    if prepare.returncode != 0:  # pragma: no cover - environment-specific
        pytest.skip(f"bin/rails db:prepare failed:\n{prepare.stderr[-2000:]}")
    seed = _run(["bin/rails", "airlock:seed_e2e_customer"])
    if seed.returncode != 0:  # pragma: no cover - environment-specific
        pytest.skip(f"seed rake task failed:\n{seed.stderr[-2000:]}")

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        ["bin/rails", "server", "-p", str(port), "-b", "127.0.0.1", "-e", "development"],
        cwd=str(CLOUD_DIR),
        env=_rails_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_for_up(base_url, proc, deadline_s=90.0)
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:  # pragma: no cover
            proc.kill()


def _wait_for_up(base_url: str, proc: subprocess.Popen[str], *, deadline_s: float) -> None:
    """Poll ``/up`` until 200 or the deadline; never sleeps the test's own clock
    guard (this file is NOT under the no-time.sleep suite marker — it is an
    opt-in integration boot, not a determinism-sensitive unit test)."""
    deadline = time.monotonic() + deadline_s
    last_err = "no response"
    while time.monotonic() < deadline:
        if proc.poll() is not None:  # pragma: no cover
            out = proc.stdout.read() if proc.stdout else ""
            raise RuntimeError(f"rails server exited early ({proc.returncode}):\n{out[-2000:]}")
        try:
            resp = httpx.get(f"{base_url}/up", timeout=2.0)
            if resp.status_code == 200:
                return
            last_err = f"status {resp.status_code}"
        except httpx.HTTPError as exc:
            last_err = str(exc)
        time.sleep(0.5)
    raise RuntimeError(f"rails server did not report healthy at {base_url}/up ({last_err})")


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _transport(base_url: str) -> HttpApprovalTransport:
    # Real clock for signing timestamps (server verifies within +/-300s; same host).
    return HttpApprovalTransport(base_url=base_url, key_id=E2E_KEY_ID, secret=E2E_SECRET)


def _gate(store: PostgresStore, base_url: str, database_url: str, invoice: str) -> tuple[str, str]:
    """Gate the harness refund over the REAL transport; return (approval_ref, run_id)."""
    os.environ["AIRLOCK_TEST_DSN"] = database_url
    init(
        store=store,
        policy=Policy(default=Decision.GATE),
        transport=_transport(base_url),
        gate_wait=False,
    )
    try:
        harness.harness_refund(invoice)
    except ActionPending as pending:
        assert pending.approval_ref is not None and pending.run_id is not None
        return pending.approval_ref, pending.run_id
    raise AssertionError("gate must raise ActionPending under gate_wait=False")


def _runner(script: str) -> str:
    result = _run(["bin/rails", "runner", script])
    assert result.returncode == 0, f"rails runner failed:\n{result.stderr[-2000:]}\n{result.stdout}"
    return result.stdout.strip()


def _hosted_approval_count(approval_ref: str) -> int:
    out = _runner(
        f"print Customer.find_by!(key_id: {E2E_KEY_ID!r}).approvals"
        f".where(approval_ref: {approval_ref!r}).count"
    )
    return int(out)


def _approve_on_cloud(approval_ref: str) -> str:
    return _runner(
        f"a = Customer.find_by!(key_id: {E2E_KEY_ID!r}).approvals"
        f".find_by!(approval_ref: {approval_ref!r}); "
        'a.decide(decision: "approved", actor_id: "usr_e2e_reviewer", '
        'actor_display: "reviewer@e2e.test"); print a.reload.status'
    )


def _call_receiver(app: Any, raw: bytes, headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
    import asyncio

    scope: dict[str, Any] = {
        "type": "http",
        "method": "POST",
        "path": WEBHOOK_PATH,
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


def _rfc3339(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


# ---------------------------------------------------------------------------
# The DoD tests.
# ---------------------------------------------------------------------------


def test_phase3_dod_via_webhook_receiver_double_delivery(
    rails_server: str,
    store: PostgresStore,
    db: Engine,
    effects: EffectsLog,
    database_url: str,
) -> None:
    """The full Phase-3 DoD through the webhook receiver, delivered TWICE (one effect)."""
    base_url = rails_server
    invoice = "inv_e2e_webhook"

    # (1) Gate -> POST creates the hosted approval (call #1) and persists approval_id.
    approval_ref, run_id = _gate(store, base_url, database_url, invoice)
    run = store.load_paused_by_ref(approval_ref)
    assert run is not None and run.status is PauseStatus.PROPOSED
    assert run.approval_id is not None  # the create response's id, persisted for the backstop
    assert effects.count(effect_key(invoice)) == 0

    # (2) It appears in the hosted inbox/DB.
    assert _hosted_approval_count(approval_ref) == 1

    # (3) A human approves (seeded decision; control plane computes the latency).
    assert _approve_on_cloud(approval_ref) == "approved"

    # Read the REAL decision back over the signed GET poll (call #2) and build the
    # approval.decided webhook (call #3) from it, so the pushed decision is the
    # control plane's own.
    transport = _transport(base_url)
    decision = transport.fetch_decision(run.approval_id)
    assert decision is not None and decision.decision is HumanDecision.APPROVED
    assert decision.decision_latency_ms is not None and decision.decision_latency_ms >= 0

    body = {
        "event": "approval.decided",
        "delivery_id": "dl_e2e_0001",
        "approval_id": run.approval_id,
        "approval_ref": approval_ref,
        "run_id": run_id,
        "decision": "approved",
        "decided_by": decision.decided_by,
        "decided_by_display": decision.decided_by_display,
        "decided_at": _rfc3339(decision.decided_at),
        "decision_latency_ms": decision.decision_latency_ms,
        "reason": decision.reason,
    }
    raw = json.dumps(body).encode("utf-8")
    ts = int(time.time())
    signature = sign(
        E2E_SECRET, timestamp=ts, method="POST", path_with_query=WEBHOOK_PATH, raw_body=raw
    )
    headers = {
        HEADER_KEY: E2E_KEY_ID,
        HEADER_TIMESTAMP: str(ts),
        HEADER_SIGNATURE: signature,
        "content-type": "application/json",
    }

    app = webhook_app(store, E2E_SECRET)
    # (4) Deliver TWICE — resume commits exactly once; the duplicate is a no-op.
    s1, b1 = _call_receiver(app, raw, headers)
    s2, b2 = _call_receiver(app, raw, headers)
    assert (s1, b1["status"]) == (200, "committed")
    assert (s2, b2["status"]) == (200, "committed")

    # Assert: one hosted row, one effect, ledger committed, paused_run committed.
    assert _hosted_approval_count(approval_ref) == 1
    assert effects.count(effect_key(invoice)) == 1
    resumed = store.load_paused_by_ref(approval_ref)
    assert resumed is not None and resumed.status is PauseStatus.COMMITTED
    ledger = store.load(run.idempotency_key)
    assert ledger is not None and ledger.state.value == "committed"

    # (5) The local audit chain verifies end to end.
    verify_chain(store)


def test_phase3_dod_via_backstop_poll(
    rails_server: str,
    store: PostgresStore,
    db: Engine,
    effects: EffectsLog,
    database_url: str,
) -> None:
    """The full DoD through the REAL backstop GET poll (no webhook delivered)."""
    from datetime import timedelta

    base_url = rails_server
    invoice = "inv_e2e_backstop"

    approval_ref, _run_id = _gate(store, base_url, database_url, invoice)
    run = store.load_paused_by_ref(approval_ref)
    assert run is not None and run.approval_id is not None
    assert _hosted_approval_count(approval_ref) == 1

    assert _approve_on_cloud(approval_ref) == "approved"

    # No webhook is ever delivered: the backstop poll GETs the decision (call #2)
    # and drives it home through apply_decision (ensure-committed).
    transport = _transport(base_url)
    report = backstop_poll_paused(store, transport, older_than=timedelta(seconds=0))
    assert report.count("committed") == 1

    assert effects.count(effect_key(invoice)) == 1  # exactly one effect
    resumed = store.load_paused_by_ref(approval_ref)
    assert resumed is not None and resumed.status is PauseStatus.COMMITTED
    verify_chain(store)
