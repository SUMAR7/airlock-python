"""The crashpoint harness — one reusable crash-injection driver (PLAN.md 7).

Consolidation, not new behavior (P1.4 deliverable 2). Before P1.4 the crash
machinery was scattered: ``test_reconcile_crash.py`` had a ``_crash_worker``
that staged the commit flow by hand (calling ``store.claim`` /
``store.mark_executing`` / a manual ``log_effect`` directly, NOT
``commit_once``) and hard-coded three of the six named boundaries. This module
factors the whole thing into one place so P1.4 (and P2.3) reuse a single
implementation that drives the REAL :func:`airlock.commit.commit_once` flow to
a named crashpoint and dies via ``os._exit`` in a spawn subprocess.

**The six named boundaries** (PLAN.md 7 / SPEC.md 9), and the durable ledger
state each leaves once the process is killed there:

======================  ================  =====================================
crashpoint              durable state     effect applied?
======================  ================  =====================================
``after_claim``         ``pending``       no — the executing marker (which
                                          commits before the effect is invoked)
                                          has not been written, so a pending row
                                          provably never started its effect.
``after_executing_mark`` ``executing``    no — marked executing, died before
                                          ``execute`` ran.
``after_effect``        ``executing``     yes — ``execute`` returned (effect
                                          logged), died before post-verify.
``after_verify``        ``executing``     yes — post-verify ran, died before
                                          finalize.
``before_finalize_write`` ``executing``   yes — about to finalize; the write
                                          never happens.
``after_finalize_write`` terminal         yes — the finalize COMMITTED durably,
                                          then the process died before returning
                                          to the caller (the caller never saw
                                          the outcome, but the ledger did).
======================  ================  =====================================

**Why ``os._exit`` is SIGKILL-equivalent for our purposes.** ``os._exit(137)``
terminates immediately: it skips ``finally`` blocks, ``atexit`` handlers, and
``__del__`` — so no Python-level cleanup runs and the open DB connection dies
mid-transaction exactly as it would under ``SIGKILL``. Postgres rolls back the
in-flight transaction; whatever COMMITTED before the crashpoint is the last
durable state. The one supplementary true-``SIGKILL`` test per boundary class
(``test_crash_sigkill_equivalence.py``) validates this equivalence assumption
empirically rather than by assertion.

**The seam is a crash-injecting Store wrapper**, kept entirely in ``tests/`` so
no ``src/`` product code learns about crashpoints (scope fence). The wrapper
fires ``os._exit`` around the store calls that bracket four boundaries
(``after_claim`` / ``after_executing_mark`` / ``before_finalize_write`` /
``after_finalize_write``); the ``after_effect`` / ``after_verify`` boundaries
are fired by the ``execute`` / ``verify`` callables the harness supplies, which
the caller controls directly. Together they cover the real ``commit_once``
control flow end to end.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any

from pydantic import JsonValue
from sqlalchemy import create_engine, text

from airlock.commit import commit_once
from airlock.effects import Effect
from airlock.store.postgres import PostgresStore, normalize_postgres_url
from airlock.types import Claim, Guarantee, LedgerState

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

__all__ = [
    "CRASHPOINTS",
    "CRASH_EXIT_CODE",
    "CrashInjectingStore",
    "EffectLogger",
    "expected_state_after_crash",
    "run_commit_to_crashpoint",
]

#: The six named crash boundaries, in commit-flow order (PLAN.md 7 / SPEC.md 9).
CRASHPOINTS: tuple[str, ...] = (
    "after_claim",
    "after_executing_mark",
    "after_effect",
    "after_verify",
    "before_finalize_write",
    "after_finalize_write",
)

#: The exit code a crashpoint uses (128 + SIGKILL's 9) — a clean 0 would mean
#: the crashpoint never fired, which the tests assert against.
CRASH_EXIT_CODE = 137

#: Which boundaries leave the row still in-flight (vs. terminal after finalize).
_EFFECT_FREE_CRASHPOINTS = frozenset({"after_claim"})
_TERMINAL_CRASHPOINTS = frozenset({"after_finalize_write"})


def expected_state_after_crash(crashpoint: str) -> LedgerState:
    """The durable ledger state a kill at ``crashpoint`` leaves behind.

    ``after_claim`` -> ``pending`` (effect-free); ``after_finalize_write`` ->
    ``committed`` (the finalize landed); every other boundary -> ``executing``.
    """
    if crashpoint in _EFFECT_FREE_CRASHPOINTS:
        return LedgerState.PENDING
    if crashpoint in _TERMINAL_CRASHPOINTS:
        return LedgerState.COMMITTED
    return LedgerState.EXECUTING


def effect_applied_at_crash(crashpoint: str) -> bool:
    """Whether the side effect has run by the time ``crashpoint`` fires."""
    idx = CRASHPOINTS.index(crashpoint)
    return idx >= CRASHPOINTS.index("after_effect")


class EffectLogger:
    """Ground-truth side-effect counter on a dedicated autocommit connection.

    Mirrors ``tests.conftest.EffectsLog`` but is self-contained so a spawn
    subprocess (which re-imports this module fresh, WITHOUT the pytest fixture
    graph) can construct one from a DSN alone.
    """

    def __init__(self, dsn: str) -> None:
        self._engine = create_engine(normalize_postgres_url(dsn), isolation_level="AUTOCOMMIT")

    def log(self, key: str) -> None:
        with self._engine.connect() as conn:
            conn.execute(
                text("INSERT INTO effects_log (idempotency_key, worker_pid) VALUES (:key, :pid)"),
                {"key": key, "pid": os.getpid()},
            )

    def dispose(self) -> None:
        self._engine.dispose()


class CrashInjectingStore(PostgresStore):
    """A ``PostgresStore`` that ``os._exit``es at named crash boundaries.

    Deterministic like a mock, real like SIGKILL: the ``os._exit`` skips all
    Python cleanup and drops the DB connection mid-transaction. Only the four
    store-bracketed boundaries live here; ``after_effect`` / ``after_verify``
    are fired by the caller's ``execute`` / ``verify`` callables. The wrapper
    NEVER changes the store's behavior when its boundary is not the configured
    ``crashpoint`` — it is a pass-through the rest of the time.

    ``after_claim`` fires only when the claim is WON (a fresh ``pending`` row):
    a loser has nothing to crash after, and the harness's contract is "die with
    the row in state X", which requires having created it.
    """

    def __init__(self, dsn: str, crashpoint: str) -> None:
        super().__init__(dsn)
        if crashpoint not in CRASHPOINTS:
            raise ValueError(f"unknown crashpoint {crashpoint!r}; expected one of {CRASHPOINTS}")
        self._crashpoint = crashpoint

    def claim(
        self,
        key: str,
        action_type: str,
        guarantee: Guarantee,
        args_json: Mapping[str, JsonValue],
        downstream_key: str | None,
    ) -> Claim:
        claim = super().claim(key, action_type, guarantee, args_json, downstream_key)
        if self._crashpoint == "after_claim" and claim.won:
            os._exit(CRASH_EXIT_CODE)  # row is durably 'pending'
        return claim

    def mark_executing(self, key: str, epoch: int) -> bool:
        marked = super().mark_executing(key, epoch)
        if self._crashpoint == "after_executing_mark" and marked:
            os._exit(CRASH_EXIT_CODE)  # row is durably 'executing', no effect yet
        return marked

    def finalize(
        self,
        key: str,
        epoch: int,
        state: LedgerState,
        result_json: JsonValue,
        audit: object | None,
    ) -> bool:
        if self._crashpoint == "before_finalize_write":
            os._exit(CRASH_EXIT_CODE)  # about to finalize; the write never happens
        ok = super().finalize(key, epoch, state, result_json, audit)
        if self._crashpoint == "after_finalize_write":
            os._exit(CRASH_EXIT_CODE)  # finalize COMMITTED durably; die before returning
        return ok


def run_commit_to_crashpoint(
    dsn: str,
    *,
    key: str,
    action_type: str,
    crashpoint: str,
    guarantee: Guarantee,
    args_json: Mapping[str, JsonValue] | None = None,
) -> None:
    """Drive the REAL ``commit_once`` flow, dying via ``os._exit`` at ``crashpoint``.

    Meant to be the ``target`` of a spawn subprocess. It builds an
    :class:`EffectLogger` and a :class:`CrashInjectingStore` from ``dsn`` alone
    (no fixtures), an :class:`~airlock.effects.Effect` matching ``guarantee``,
    and an ``execute`` that logs exactly one effect then fires ``after_effect``
    if that is the boundary. The ``after_verify`` boundary is fired by the
    probe. If the crashpoint never fires (a logic error), it exits 0 — which
    the parent asserts against (``!= CRASH_EXIT_CODE``).

    ``guarantee`` selects the effect shape so the harness exercises every
    recovery-table branch:

    - ``verifiable`` -> ``Effect(verify=...)`` (probe present).
    - ``downstream_idempotent`` -> ``Effect(key_param=...)`` (downstream dedup).
    - ``none`` -> ``Effect()`` (at-most-once; no ``after_verify`` boundary).
    """
    # after_verify only exists for a VERIFIABLE effect (post-verify does not run
    # otherwise), so pairing it with another guarantee would run to completion and
    # exit 0 — a silent miss. Refuse the combination loudly rather than let a
    # crash test pass without ever crashing.
    if crashpoint == "after_verify" and guarantee is not Guarantee.VERIFIABLE:
        raise ValueError(
            "crashpoint 'after_verify' requires Guarantee.VERIFIABLE (post-verify only runs "
            f"for a verifiable effect); got {guarantee!r}"
        )
    args: Mapping[str, JsonValue] = args_json if args_json is not None else {"invoice": key}
    effects = EffectLogger(dsn)
    store = CrashInjectingStore(dsn, crashpoint)

    def execute(passed_downstream_key: str | None) -> JsonValue:
        effects.log(key)
        if crashpoint == "after_effect":
            os._exit(CRASH_EXIT_CODE)  # effect landed; die before post-verify
        return {"refund_id": f"re_{key}"}

    def verify(**_arg_map: Any) -> tuple[Any, dict[str, str]]:
        # Reached only for a VERIFIABLE effect (post-verify step). By here the
        # effect has landed, so a real probe would answer present; fire the
        # after_verify boundary before returning that verdict.
        from airlock.types import Verification

        if crashpoint == "after_verify":
            os._exit(CRASH_EXIT_CODE)
        return Verification.PRESENT, {"refund_id": f"re_{key}"}

    effect = _effect_for(guarantee, verify)
    # No reconcile_after: this owner just runs the flow to the crashpoint. The
    # PARENT process advances a fake clock and reconciles afterwards.
    commit_once(
        store,
        key=key,
        action_type=action_type,
        execute=execute,
        effect=effect,
        args_json=args,
    )
    # Unreachable when the crashpoint fires; a clean return exits 0.
    effects.dispose()
    store.close()


def _effect_for(guarantee: Guarantee, verify: Callable[..., Any]) -> Effect:
    if guarantee is Guarantee.VERIFIABLE:
        return Effect(verify=verify)
    if guarantee is Guarantee.DOWNSTREAM_IDEMPOTENT:
        return Effect(key_param="idempotency_key")
    return Effect()  # none — at-most-once


def rebase_last_attempt(engine: Engine, key: str, when: datetime) -> None:
    """Re-stamp a crashed row's ``last_attempt_at`` onto the fake clock timeline.

    A crash subprocess necessarily used its own real clock; the reconciler runs
    on the fake clock. Aligning ``last_attempt_at`` keeps the staleness trigger
    deterministic (advance the clock, never sleep). State/attempts/effects are
    untouched — only the timeline the stale scan reads.
    """
    with engine.begin() as conn:
        rowcount = conn.execute(
            text("UPDATE commit_records SET last_attempt_at = :when WHERE idempotency_key = :key"),
            {"when": when, "key": key},
        ).rowcount
    if rowcount != 1:
        raise AssertionError(f"expected exactly one row to rebase for {key!r}, got {rowcount}")
