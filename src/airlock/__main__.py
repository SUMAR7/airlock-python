"""``python -m airlock`` — the reconciler CLI (PLAN.md 4.2, the cron/k8s model).

Usage::

    python -m airlock reconcile --store $DATABASE_URL --import mymodule \
        --execute-timeout SECONDS [--older-than SECONDS] [--on-absent retry|abort]

``--import`` loads the integrator's module(s) so their
:func:`airlock.registry.register` calls run BEFORE the sweep — the reconciler
needs each ``action_type``'s effect/execute/preconditions to recover its rows
(a row whose action_type is unregistered is left untouched, counted
``unregistered``). ``--store`` is a Postgres DSN dispatched through
:func:`airlock.store.from_url`. ``--older-than`` is the reconcile timeout in
seconds (the row must be stale by this much).

``--execute-timeout`` is REQUIRED and load-bearing (PLAN.md 4.1 step 4 / 10
point 2): it is the operator's assertion of the longest an owner's ``execute``
can run. The reconciler REFUSES to run unless ``--older-than`` strictly exceeds
it (validated via :class:`airlock.reconcile.ExecuteWindow` before any scan), so
a reconciler can never probe a row while its original owner might still be
legitimately mid-execute — the residual double-execute the epoch fence exists to
close. The CLI cannot infer this bound, so the operator must state it; a
misconfigured pair (``--older-than <= --execute-timeout``) exits non-zero
without touching a single row.

This is a one-shot sweep — the operator schedules it (cron, k8s CronJob). It
is NOT a daemon: an always-on background loop is explicitly out of P1.3 scope.
Exit code is 0 on a completed pass (even with escalations — those are
reported, not errors), non-zero only on a setup failure (bad DSN, import
error, bad arguments).
"""

from __future__ import annotations

import argparse
import importlib
import sys
from collections.abc import Sequence
from datetime import timedelta

from airlock.reconcile import ExecuteWindow, OnAbsent, ReconcileReport, reconcile
from airlock.store import from_url

__all__ = ["main"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m airlock",
        description="Airlock — recover stale in-flight commit rows (verify-first).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    rec = sub.add_parser(
        "reconcile",
        help="Run one verify-first reconciliation pass over stale in-flight rows.",
        description=(
            "Scan stale in-flight commit_records rows and recover each once, verify-first, "
            "never blind-re-executing (PLAN.md 4.2). --import the module(s) that register "
            "your action types so their recovery logic is available."
        ),
    )
    rec.add_argument(
        "--store",
        required=True,
        metavar="DSN",
        help="Postgres DSN for the commit ledger (e.g. postgresql://host/db).",
    )
    rec.add_argument(
        "--import",
        dest="imports",
        action="append",
        default=[],
        metavar="MODULE",
        help=(
            "Import this module before reconciling so its airlock.register(...) calls run "
            "(repeatable). Without the module that registers an action_type, its rows cannot "
            "be recovered."
        ),
    )
    rec.add_argument(
        "--older-than",
        type=float,
        default=300.0,
        metavar="SECONDS",
        help=(
            "Recover rows whose last attempt is older than this many seconds (the reconcile "
            "timeout; default 300). MUST strictly exceed --execute-timeout (PLAN.md 4.1: "
            "execute_timeout < reconcile_after); the reconciler refuses to run otherwise."
        ),
    )
    rec.add_argument(
        "--execute-timeout",
        type=float,
        required=True,
        metavar="SECONDS",
        help=(
            "REQUIRED: the longest an owner's execute can run, in seconds (PLAN.md 4.1 step 4). "
            "--older-than MUST strictly exceed it, or the reconciler refuses to run — this is "
            "what guarantees an owner is out of execute before its row is recover-eligible, so "
            "the reconciler never probes a live owner's row (the residual double-execute the "
            "epoch fence closes)."
        ),
    )
    rec.add_argument(
        "--on-absent",
        choices=[member.value for member in OnAbsent],
        default=OnAbsent.ABORT.value,
        help=(
            "When an effect is provably absent / never started: 'retry' re-runs the execute "
            "path (re-validating preconditions first), 'abort' finalizes aborted. "
            "Default 'abort' (fail safe)."
        ),
    )
    return parser


def _summarize(report: ReconcileReport) -> str:
    if report.total == 0:
        return "reconcile: no stale in-flight rows"
    parts = [f"{outcome.value}={count}" for outcome, count in sorted(report.counts.items())]
    return f"reconcile: {report.total} row(s) — " + ", ".join(parts)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code (0 = pass completed)."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.older_than <= 0:
        parser.error(f"--older-than must be positive, got {args.older_than}")
    if args.execute_timeout <= 0:
        parser.error(f"--execute-timeout must be positive, got {args.execute_timeout}")

    older_than = timedelta(seconds=args.older_than)
    execute_timeout = timedelta(seconds=args.execute_timeout)
    # Refuse a misconfigured window BEFORE importing modules / opening the store
    # / scanning a single row (PLAN.md 4.1: execute_timeout < reconcile_after).
    # ExecuteWindow.__post_init__ raises ValueError on older_than <= execute_timeout.
    try:
        ExecuteWindow(execute_timeout=execute_timeout, reconcile_after=older_than)
    except ValueError as exc:
        parser.error(str(exc))

    for module_name in args.imports:
        try:
            importlib.import_module(module_name)
        except ImportError as exc:
            parser.error(f"--import {module_name!r} failed: {exc}")

    try:
        store = from_url(args.store)
    except (ValueError, ImportError, NotImplementedError) as exc:
        parser.error(f"--store {args.store!r} could not be opened: {exc}")

    try:
        report = reconcile(
            store,
            older_than=older_than,
            on_absent=OnAbsent(args.on_absent),
            execute_timeout=execute_timeout,
        )
    finally:
        close = getattr(store, "close", None)
        if callable(close):
            close()

    print(_summarize(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
