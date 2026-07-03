"""The ``Store`` protocol (PLAN.md section 3.3) and DSN dispatch.

P1.1 surface: ``claim`` / ``mark_executing`` / ``record_error`` /
``finalize`` / ``load``. P1.3 adds the two reconciler methods
(``stale_inflight``, ``bump_epoch``). The pause methods arrive in P2.3 and
``append_audit`` in P2.2 — do not add them early.

This module must stay import-light: importing it (or ``airlock`` itself) must
never import sqlalchemy/psycopg. Backends are imported lazily inside
``from_url``.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
from typing import Protocol

from pydantic import JsonValue

from airlock.types import Claim, CommitRecord, Guarantee, LedgerState

__all__ = ["Store", "from_url"]


class Store(Protocol):
    """Commit-ledger persistence (ADR-1).

    Every transition is a guarded UPDATE whose rowcount is the truth about
    who owns the row — a ``False`` return means this caller lost a race (the
    epoch fence) and must not execute or override. Implementations never
    SELECT-then-UPDATE.
    """

    def claim(
        self,
        key: str,
        action_type: str,
        guarantee: Guarantee,
        args_json: Mapping[str, JsonValue],
        downstream_key: str | None,
    ) -> Claim:
        """INSERT ... ON CONFLICT (idempotency_key) DO NOTHING, committed in
        its own transaction before anything else executes (PLAN.md 4.1 step 1).

        Returns ``Claim(won=True, record=<fresh pending row>)`` when the
        insert landed, else ``Claim(won=False, record=<existing row>)``.
        """
        ...

    def mark_executing(self, key: str, epoch: int) -> bool:
        """Durable CAS ``pending -> executing WHERE attempts = epoch``, its own
        transaction, committed BEFORE the effect is invoked (PLAN.md 4.1 step 3).

        Returns ``False`` when fenced (rowcount 0): ownership moved on — the
        caller must NOT execute.
        """
        ...

    def record_error(self, key: str, epoch: int, error_json: JsonValue) -> bool:
        """Record failure/recovery evidence, leaving the row's state unchanged.

        Epoch-guarded UPDATE of ``error_json`` only, in its own transaction —
        the state does not change, so it is legal on any IN-FLIGHT row
        (``pending`` or ``executing``): ``commit_once`` calls it after the
        executing mark, and the reconciler records the ``reconciled``/aborted
        reason on the ``pending`` abort path BEFORE the ``pending -> aborted``
        finalize (the row is still ``pending`` then). It is refused on terminal
        rows — a fenced or late writer must not scribble on a resolved row
        (invariant I5). Returns ``False`` when fenced. (Not part of the PLAN
        3.3 sketch; added so the ledger keeps the evidence the reconciler and
        operators need.)
        """
        ...

    def finalize(
        self,
        key: str,
        epoch: int,
        state: LedgerState,
        result_json: JsonValue,
        audit: object | None,
    ) -> bool:
        """CAS to a terminal state ``WHERE attempts = epoch``, ONE transaction.

        Allowed transitions (PLAN.md 3.2 semantics — the state machine makes
        false claims unrepresentable, PLAN.md section 10 point 1):

        - ``executing -> committed`` (sets ``committed_at``)
        - ``pending|executing -> aborted``
        - ``executing -> failed|unknown`` — both are statements about an
          executed effect, so they are refused from ``pending``, which
          provably never started its effect.

        Returns ``False`` when fenced — the reconciler owns resolution; never
        override.

        ``audit`` is a documented no-op seam in P1.1: the parameter is
        accepted but nothing is persisted. P2.2 adds the hash-chained audit
        append INSIDE this same transaction without changing this signature
        (PLAN.md section 10 sequencing).
        """
        ...

    def load(self, key: str) -> CommitRecord | None:
        """Plain read of the row for ``key``, or ``None`` if never claimed."""
        ...

    def stale_inflight(self, older_than: timedelta) -> list[CommitRecord]:
        """Return the stale in-flight rows for the reconciler (PLAN.md 4.2).

        A row is stale-in-flight when its state is ``pending`` or
        ``executing`` AND its ``last_attempt_at`` is older than
        ``now_fn() - older_than`` — the ONLY recovery trigger (SPEC.md
        section 5: "a pending row older than the reconcile timeout is the only
        trigger for recovery"). The partial index
        ``commit_records_inflight_idx`` (PLAN.md 5.1) supports the scan.

        Rows are selected ``FOR UPDATE SKIP LOCKED`` so two concurrent
        reconcilers never contend on the same row: each row is handed to at
        most one reconciler per pass. The lock is released when the reading
        transaction commits; the reconciler takes durable ownership via
        :meth:`bump_epoch` (the epoch fence), NOT by holding this lock across
        its verification I/O.
        """
        ...

    def bump_epoch(self, key: str, older_than: timedelta) -> int | None:
        """Take over a stale in-flight row: bump the epoch, return the new one.

        The reconciler takeover fence (PLAN.md 4.2, section 10 point 2):
        atomically ``attempts = attempts + 1`` and ``last_attempt_at = now``,
        returning the NEW epoch — but ONLY while the row is still in-flight
        (``pending`` or ``executing``) AND still stale (``last_attempt_at``
        older than ``now_fn() - older_than``). Returns ``None`` when the row
        is already terminal OR was refreshed by another actor since the
        ``stale_inflight`` read (another reconciler already took it over, or
        the original owner is alive and just re-touched it) — the caller skips
        it.

        This is the ONLY source of reclaim epochs (the P1.1 carry-forward
        resolution): ``claim`` hardcodes ``attempts = 1`` for fresh rows, so a
        row at epoch > 1 was necessarily reclaimed by a reconciler. Because
        the original owner's ``mark_executing`` / ``finalize`` /
        ``record_error`` all carry ``WHERE attempts = <its epoch>``, a bumped
        row fences the original owner: it can no longer execute or finalize.
        """
        ...


def from_url(url: str) -> Store:
    """Build a Store from a DSN. P1.1 dispatches ``postgresql://`` only.

    SQLite is a Phase 4 quickstart deliverable (PLAN.md section 10, point 10)
    and the in-memory unit-test store lands with the store matrix — neither
    exists yet, by design.
    """
    if "://" not in url:
        raise ValueError(f"not a DSN: {url!r} (expected e.g. postgresql://host/db)")
    scheme = url.split("://", 1)[0]
    dialect = scheme.split("+", 1)[0].lower()
    if dialect in ("postgres", "postgresql"):
        try:
            from airlock.store.postgres import PostgresStore
        except ImportError as exc:
            raise ImportError(
                "the Postgres store needs the 'postgres' extra "
                "(sqlalchemy + psycopg): pip install 'airlock[postgres]'"
            ) from exc
        return PostgresStore(url)
    raise NotImplementedError(
        f"no Store backend for URL scheme {scheme!r} in P1.1 — Postgres is the substrate "
        "of record (PLAN.md section 7); SQLite arrives in P4.1 (PLAN.md section 8)."
    )
