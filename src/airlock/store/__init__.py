"""The ``Store`` protocol (PLAN.md section 3.3) and DSN dispatch.

P1.1 surface only: ``claim`` / ``mark_executing`` / ``record_error`` /
``finalize`` / ``load``. The reconciler methods (``stale_inflight``,
``bump_epoch``) arrive in P1.3, the pause methods in P2.3, and
``append_audit`` in P2.2 — do not add them early.

This module must stay import-light: importing it (or ``airlock`` itself) must
never import sqlalchemy/psycopg. Backends are imported lazily inside
``from_url``.
"""

from __future__ import annotations

from collections.abc import Mapping
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
        """Record why an execute attempt raised, leaving the row ``executing``.

        Epoch-guarded UPDATE of ``error_json`` only, in its own transaction —
        the state does not change because the effect's status is honestly
        unknown; the P1.3 reconciler resolves the row. Returns ``False`` when
        fenced. (Not part of the PLAN 3.3 sketch; added so the ledger keeps
        the failure evidence the reconciler and operators need.)
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
