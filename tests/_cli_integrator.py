"""A tiny integrator module the CLI test loads via ``--import``.

Importing this module registers recovery for ``cli.refund`` on the process-wide
default registry — exactly what ``python -m airlock reconcile --import`` relies
on so the reconciler can reconstruct the effect/execute for a bare ledger row.
"""

from __future__ import annotations

from typing import Any

from pydantic import JsonValue

from airlock.effects import Effect
from airlock.registry import register
from airlock.types import Verification

CLI_ACTION = "cli.refund"


def _verify(**_: Any) -> tuple[Verification, dict[str, str]]:
    # The effect landed before the (simulated) crash: the probe confirms it, so
    # recovery finalizes committed WITHOUT re-executing.
    return Verification.PRESENT, {"confirmed": "by probe"}


def _execute(downstream_key: str | None, **_: Any) -> JsonValue:
    raise AssertionError("CLI recovery of a present-verifiable row must not re-execute")


register(CLI_ACTION, Effect(verify=_verify), _execute)
