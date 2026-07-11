"""Tests that pin the double-refund demo's *claims* (examples/double_refund).

A broken demo is worse than none — it is the first thing a newcomer runs, and
it is the marketing promise ("without Airlock the agent double-charges; with
Airlock it charges exactly once") made executable. These tests drive the demo's
own ACT-1 / ACT-2 logic and assert the behavior that makes the story TRUE, so
the demo keeps working as the SDK evolves.

Deterministic, no network, no ``time.sleep`` (the autouse conftest guard would
fail any sleep), no Postgres — the demo runs on the base install + SQLite.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import airlock
import airlock._guard as _guard

# The demo is a script, not an installed package: put its directory on sys.path
# so `import demo` (and the demo's own `import fake_payment_api`) resolve.
_DEMO_DIR = Path(__file__).resolve().parents[1] / "examples" / "double_refund"
sys.path.insert(0, str(_DEMO_DIR))

# mypy cannot see these runtime-path modules (they live under examples/, not on
# the package path); the sys.path.insert above makes them importable at runtime.
import demo  # type: ignore[import-not-found]  # noqa: E402
from fake_payment_api import FakePaymentAPI  # type: ignore[import-not-found]  # noqa: E402


def test_fake_api_dedupes_on_idempotency_key() -> None:
    """The stand-in models a real idempotent payment API (ADR-2 clause a)."""
    api = FakePaymentAPI()

    # No key: every call is a distinct side effect.
    api.refund("ch_1", 5000)
    api.refund("ch_1", 5000)
    assert api.refund_count("ch_1") == 2

    # Same key: the second call is deduped — no new money moves.
    first = api.refund("ch_2", 5000, idempotency_key="k-abc")
    second = api.refund("ch_2", 5000, idempotency_key="k-abc")
    assert api.refund_count("ch_2") == 1
    assert first is second


def test_act1_without_airlock_double_charges() -> None:
    """ACT 1: the naive retry records TWO refunds — the status quo Airlock fixes."""
    api = demo.act1_without_airlock()
    assert api.refund_count(demo.CHARGE_ID) == 2


def test_act2_with_airlock_refunds_exactly_once() -> None:
    """ACT 2: the SAME retry is deduped — one side effect, no CommitFailed."""
    result = demo.act2_with_airlock()
    try:
        # Exactly one real refund side effect...
        assert result.api.refund_count(demo.CHARGE_ID) == 1
        # ...and the ledger short-circuited the retry BEFORE it reached the API
        # (the API was invoked once, not twice) — the ledger did the dedup.
        assert result.api.total_calls == 1
        # The retry returned the FIRST recorded result (deduped, no re-execute
        # and no raise) — scenario 1 in SPEC.md section 5.
        assert result.second == result.first
        assert result.first["refund_id"] == result.second["refund_id"]
    finally:
        demo.cleanup(result.handle)


def test_act2_uses_zero_config_sqlite_dev_store() -> None:
    """ACT 2 runs on the zero-config SQLite store and says so (PLAN.md 3.7)."""
    # Reset the one-shot latch so init()'s dev-store note is emitted here.
    _guard._dev_store_warned = False
    result = demo.act2_with_airlock()
    try:
        assert isinstance(result.handle, airlock.Airlock)
        assert "SQLite" in result.dev_note
        assert "airlock.db" in result.dev_note
    finally:
        demo.cleanup(result.handle)


def test_demo_runs_end_to_end_and_leaves_no_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`python demo.py` runs clean and cleans up ./airlock.db behind it."""
    # Run in a scratch cwd so the SQLite dev store lands there, not in the repo.
    monkeypatch.chdir(tmp_path)
    _guard._dev_store_warned = False

    demo.main()

    out = capsys.readouterr().out
    assert "❌ Customer refunded TWICE" in out
    assert "✅ Refunded exactly once" in out
    # No dev-store artifacts left behind (idempotent re-runs).
    assert not any((tmp_path / name).exists() for name in demo._DB_FILES)


def test_demo_runs_as_documented_command(tmp_path: Path) -> None:
    """`python examples/double_refund/demo.py` works in a fresh process, base install.

    A subprocess is the faithful test of the documented command: a fresh
    interpreter, the real ``@guard`` registration, and only the base install on
    the path — exactly what a stranger runs. It also leaves no ``./airlock.db``
    behind in its working directory.
    """
    proc = subprocess.run(
        [sys.executable, str(_DEMO_DIR / "demo.py")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Customer refunded TWICE" in proc.stdout
    assert "Refunded exactly once" in proc.stdout
    assert not any((tmp_path / name).exists() for name in demo._DB_FILES)
