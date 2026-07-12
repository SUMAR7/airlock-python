"""Tests that pin the hosted-gate demo's *claims* (examples/hosted_gated).

A broken example is worse than none — this one is the runnable promise for the
two human-in-the-loop features (reviewer context + reject reason codes), so these
tests drive its own ACT-1 / ACT-2 logic and assert the behavior that makes the
story TRUE:

- **approve** → the payout commits **exactly once** (one side effect), even when
  the approval is delivered twice, and the raw card-number arg never reaches the
  reviewer's view;
- **reject with a code** → **zero** side effects, and the chosen ``reason_code`` /
  ``reason`` are surfaced on ``ApprovalRejected`` so the agent can branch.

Deterministic, no network, no ``time.sleep`` (the autouse conftest guard would
fail any sleep — the demo drives the transport with ``gate_timeout=0.0``), base
install + SQLite. Each test runs in a scratch cwd so the dev store and approvals
file land in ``tmp``, never the repo.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

import airlock._guard as _guard

# Load the demo under a UNIQUE module name (not a plain ``import demo``): every
# example ships a ``demo.py``, so importing them all as top-level ``demo`` would
# collide in ``sys.modules`` (the first-imported one would shadow the rest). A
# path-based import with an explicit name keeps this example independent.
_DEMO_DIR = Path(__file__).resolve().parents[1] / "examples" / "hosted_gated"
_spec = importlib.util.spec_from_file_location("hosted_gated_demo", _DEMO_DIR / "demo.py")
assert _spec is not None and _spec.loader is not None
demo = importlib.util.module_from_spec(_spec)
sys.modules["hosted_gated_demo"] = demo
_spec.loader.exec_module(demo)


def test_act1_approved_commits_exactly_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ACT 1: a reviewer approves; the payout runs exactly once, twice-delivered."""
    monkeypatch.chdir(tmp_path)  # keep the dev store + approvals file out of the repo
    _guard._dev_store_warned = False

    result = demo.act1_approved()
    try:
        # Exactly one real payout side effect — even though act1_approved delivers
        # the approval twice (a duplicate webhook / a second retry).
        assert result.payouts == 1
        assert result.result == {"vendor": "acme-cloud", "amount_cents": 420_000}
    finally:
        demo.cleanup(result.handle)


def test_act1_reviewer_never_sees_raw_args(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The reviewer sees the curated summary/context — never the raw card number."""
    monkeypatch.chdir(tmp_path)
    _guard._dev_store_warned = False

    result = demo.act1_approved()
    try:
        seen = result.reviewer_saw
        # The integrator-authored summary + curated context DID transit:
        assert "Pay acme-cloud $4,200.00" in seen
        assert "vendor: acme-cloud" in seen
        assert "category: vendor payout" in seen
        # ...and the sensitive tool arg did NOT (raw args never auto-transit):
        assert "4111-1111-1111-1111" not in seen
    finally:
        demo.cleanup(result.handle)


def test_act2_rejected_surfaces_reason_code_and_runs_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ACT 2: a coded rejection surfaces the code, the agent branches, no effect runs."""
    monkeypatch.chdir(tmp_path)
    _guard._dev_store_warned = False

    result = demo.act2_rejected()
    try:
        # The reviewer's structured choice flowed back onto ApprovalRejected...
        assert result.reason_code == "unverified_vendor"
        assert result.reason == "bank details not on file"
        # ...the agent branched on the code deterministically...
        assert result.handled == "route to vendor onboarding"
        # ...and the money-moving side effect NEVER ran.
        assert result.payouts == 0
    finally:
        demo.cleanup(result.handle)


def test_demo_runs_end_to_end_and_leaves_no_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`python demo.py` runs clean and cleans up its dev store + approvals file."""
    monkeypatch.chdir(tmp_path)
    _guard._dev_store_warned = False

    demo.main()

    out = capsys.readouterr().out
    assert "Committed exactly once" in out
    assert "A rejection is control flow, not a dead end" in out
    # No artifacts left behind (idempotent re-runs).
    leftovers = (*demo._DB_FILES, demo._APPROVALS_FILE)
    assert not any((tmp_path / name).exists() for name in leftovers)


def test_demo_runs_as_documented_command(tmp_path: Path) -> None:
    """`python examples/hosted_gated/demo.py` works in a fresh process, base install."""
    proc = subprocess.run(
        [sys.executable, str(_DEMO_DIR / "demo.py")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Committed exactly once" in proc.stdout
    assert "A rejection is control flow, not a dead end" in proc.stdout
    leftovers = (*demo._DB_FILES, demo._APPROVALS_FILE)
    assert not any((tmp_path / name).exists() for name in leftovers)
