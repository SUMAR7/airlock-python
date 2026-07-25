"""Tests that pin the async-agent demo's *claims* (examples/async_agent).

A broken demo is worse than none. This one makes three promises to a newcomer —
a retried async call refunds once, the event loop keeps running during a guarded
call, and five concurrent identical calls collapse to one effect — so those are
what we assert, by running the demo's own `main()` end to end.

Deterministic, no network, no Postgres: the demo runs on the base install +
SQLite, exactly as a reader will run it.
"""

from __future__ import annotations

import asyncio
import importlib.util
import subprocess
import sys
from pathlib import Path

# Load the demo under a UNIQUE module name (not a plain ``import demo``): every
# example ships a ``demo.py``, so importing them all as top-level ``demo`` would
# collide in ``sys.modules`` (the first-imported one would shadow the rest). A
# path-based import with an explicit name keeps this example independent.
_DEMO_DIR = Path(__file__).resolve().parents[1] / "examples" / "async_agent"
_spec = importlib.util.spec_from_file_location("async_agent_demo", _DEMO_DIR / "demo.py")
assert _spec is not None and _spec.loader is not None
demo = importlib.util.module_from_spec(_spec)
sys.modules["async_agent_demo"] = demo
_spec.loader.exec_module(demo)


def test_demo_runs_and_keeps_its_three_promises() -> None:
    """Drive the demo's own main(): its asserts ARE the promises, and we re-check
    the headline number here so a silently-weakened demo cannot pass."""
    demo.payment_api_calls.clear()
    asyncio.run(demo.main())

    # ch_demo once (retry deduped) + ch_parallel once (5 concurrent deduped).
    assert demo.payment_api_calls == ["ch_demo", "ch_parallel"], demo.payment_api_calls


def test_demo_script_exits_clean() -> None:
    """It must also work the way a reader actually runs it: `python demo.py`."""
    result = subprocess.run(
        [sys.executable, str(_DEMO_DIR / "demo.py")],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr[-800:]
    assert "exactly once" in result.stdout
    assert "audit verifies" in result.stdout
