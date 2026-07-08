"""``ConsoleApprovalTransport`` — the file-backed stub (P2.3, deliverable A).

Pure unit tests (no DB): send() prints a boundary-safe summary, wait() polls the
JSON-lines approvals file and returns the decision or None, the file format is
honored, and — crucially for the no-time.sleep guard — a present decision or a
zero timeout returns WITHOUT sleeping (an injectable clock proves it).
"""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

import pytest

from airlock.transport import PauseRequest, SendReceipt
from airlock.transport.console import ConsoleApprovalTransport
from airlock.types import BlastRadius, HumanDecision, Money, Reversibility

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path


class _Clock:
    """A controllable monotonic clock: each sleep advances it by the slept span."""

    def __init__(self) -> None:
        self.t = 0.0
        self.sleeps = 0

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps += 1
        self.t += seconds


def _now() -> datetime:
    from datetime import UTC, datetime

    return datetime(2026, 7, 8, 12, 0, 0, tzinfo=UTC)


def _request(ref: str = "ref-123") -> PauseRequest:
    return PauseRequest(
        approval_ref=ref,
        run_id="run_abc",
        action_type="refund.create",
        summary="refund.create",
        requested_at=_now(),
        cost=Money(amount="12.50", currency="USD"),
        reversibility=Reversibility.IRREVERSIBLE,
        blast_radius_estimate=BlastRadius.HIGH,
    )


def _transport(
    path: Path, clock: _Clock, out: io.StringIO | None = None
) -> ConsoleApprovalTransport:
    return ConsoleApprovalTransport(
        path,
        out=out if out is not None else io.StringIO(),
        poll_interval=0.2,
        sleep_fn=clock.sleep,
        monotonic_fn=clock.monotonic,
    )


# ---------------------------------------------------------------------------
# send()
# ---------------------------------------------------------------------------


def test_send_prints_summary_and_returns_receipt(tmp_path: Path) -> None:
    out = io.StringIO()
    transport = _transport(tmp_path / "a.jsonl", _Clock(), out=out)
    receipt = transport.send(_request("ref-xyz"))
    assert receipt == SendReceipt(approval_ref="ref-xyz", approval_id=None)
    printed = out.getvalue()
    assert "ref-xyz" in printed
    assert "refund.create" in printed
    assert "12.5 USD" in printed  # risk metadata rendered (canonical decimal)
    assert "run_abc" in printed


def test_send_is_redelivery_safe(tmp_path: Path) -> None:
    transport = _transport(tmp_path / "a.jsonl", _Clock())
    r1 = transport.send(_request("dup"))
    r2 = transport.send(_request("dup"))
    assert r1 == r2  # sending twice is harmless


# ---------------------------------------------------------------------------
# wait() — present decision / timeout / no sleep
# ---------------------------------------------------------------------------


def test_wait_returns_present_decision_without_sleeping(tmp_path: Path) -> None:
    clock = _Clock()
    transport = _transport(tmp_path / "a.jsonl", clock)
    transport.record_decision("ref-1", HumanDecision.APPROVED, decided_by="usr_ada")
    decision = transport.wait("ref-1", timeout=5.0)
    assert decision is not None
    assert decision.decision is HumanDecision.APPROVED
    assert decision.decided_by == "usr_ada"
    assert clock.sleeps == 0  # found on the first scan; never slept


def test_wait_zero_timeout_no_decision_returns_none_without_sleeping(tmp_path: Path) -> None:
    clock = _Clock()
    transport = _transport(tmp_path / "missing.jsonl", clock)
    assert transport.wait("ref-1", timeout=0.0) is None
    assert clock.sleeps == 0  # one scan, deadline already reached


def test_wait_polls_until_deadline_then_returns_none(tmp_path: Path) -> None:
    clock = _Clock()
    transport = _transport(tmp_path / "a.jsonl", clock)
    assert transport.wait("ref-1", timeout=0.5) is None
    # deadline 0.5, poll_interval 0.2: scans at t=0,0.2,0.4 then t=0.6 >= 0.5.
    assert clock.sleeps == 3


def test_wait_rejects_and_carries_reason(tmp_path: Path) -> None:
    clock = _Clock()
    transport = _transport(tmp_path / "a.jsonl", clock)
    transport.record_decision(
        "ref-2", HumanDecision.REJECTED, decided_by="usr_ben", reason="too risky"
    )
    decision = transport.wait("ref-2", timeout=1.0)
    assert decision is not None
    assert decision.decision is HumanDecision.REJECTED
    assert decision.reason == "too risky"


# ---------------------------------------------------------------------------
# file format
# ---------------------------------------------------------------------------


def test_decision_for_another_ref_is_ignored(tmp_path: Path) -> None:
    clock = _Clock()
    transport = _transport(tmp_path / "a.jsonl", clock)
    transport.record_decision("other-ref", HumanDecision.APPROVED)
    assert transport.wait("ref-1", timeout=0.0) is None


def test_blank_and_malformed_lines_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    path.write_text(
        "\n"  # blank
        "not json at all\n"  # malformed
        '{"no_ref": true}\n'  # missing approval_ref
        '{"approval_ref": "ref-3", "decision": "approved"}\n',
        encoding="utf-8",
    )
    transport = _transport(path, _Clock())
    decision = transport.wait("ref-3", timeout=0.0)
    assert decision is not None and decision.decision is HumanDecision.APPROVED


def test_duplicate_decision_lines_return_the_first(tmp_path: Path) -> None:
    """Writing the same approval twice is safe — wait returns the first match
    (apply_decision dedupes downstream regardless)."""
    clock = _Clock()
    transport = _transport(tmp_path / "a.jsonl", clock)
    transport.record_decision("ref-4", HumanDecision.APPROVED, decided_by="usr_1")
    transport.record_decision("ref-4", HumanDecision.APPROVED, decided_by="usr_2")
    decision = transport.wait("ref-4", timeout=0.0)
    assert decision is not None and decision.decided_by == "usr_1"


def test_latency_verbatim_and_missing(tmp_path: Path) -> None:
    clock = _Clock()
    transport = _transport(tmp_path / "a.jsonl", clock)
    transport.record_decision("ref-5", HumanDecision.APPROVED, decision_latency_ms=4242)
    d = transport.wait("ref-5", timeout=0.0)
    assert d is not None and d.decision_latency_ms == 4242


def test_typoed_verdict_raises_loudly(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    path.write_text('{"approval_ref": "ref-6", "decision": "maybe"}\n', encoding="utf-8")
    transport = _transport(path, _Clock())
    with pytest.raises(ValueError):
        transport.wait("ref-6", timeout=0.0)


def test_poll_interval_must_be_positive(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="poll_interval"):
        ConsoleApprovalTransport(tmp_path / "a.jsonl", poll_interval=0.0)


def test_default_path_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "env-approvals.jsonl"
    monkeypatch.setenv("AIRLOCK_APPROVALS_FILE", str(target))
    transport = ConsoleApprovalTransport()
    assert transport.approvals_path == target
