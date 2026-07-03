"""``python -m airlock reconcile`` — the CLI invocation model (PLAN.md 4.2).

The CLI is a thin wrapper over :func:`airlock.reconcile.reconcile`: it
``--import``s the integrator module so registration runs, opens the store from
the ``--store`` DSN, and runs one verify-first pass. These tests drive
``airlock.__main__.main`` directly (argv list) rather than a subprocess — the
recovery logic is covered elsewhere; here we pin the CLI wiring, argument
handling, and exit codes.

The seeded row is backdated directly (its ``last_attempt_at`` set into the
past) so a small ``--older-than`` triggers recovery under the CLI's real
clock — no fake clock reaches the CLI, and no ``time.sleep`` is used.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from airlock.__main__ import main
from airlock.registry import registry
from airlock.types import Guarantee, LedgerState
from tests._cli_integrator import CLI_ACTION
from tests.conftest import read_row

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore


@pytest.fixture(autouse=True)
def _clean_default_registry() -> None:
    """The integrator module registers on the process-wide registry at import;
    ensure it is present but do not leak other tests' registrations."""
    # importing tests._cli_integrator (above) already registered CLI_ACTION.
    assert registry.get(CLI_ACTION) is not None


def _seed_backdated_executing_row(store: PostgresStore, engine: Engine, key: str) -> None:
    """Claim + mark executing, then backdate last_attempt_at into the past so
    the CLI's real-clock staleness check fires with a small --older-than."""
    store.claim(key, CLI_ACTION, Guarantee.VERIFIABLE, {"invoice": "inv_cli"}, None)
    assert store.mark_executing(key, 1)
    past = datetime.now(UTC) - timedelta(hours=1)
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE commit_records SET last_attempt_at = :past WHERE idempotency_key = :key"),
            {"past": past, "key": key},
        )


def test_cli_reconciles_a_stale_row_present_probe_commits(
    store: PostgresStore, db: Engine, database_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CLI imports the integrator, opens the store, and recovers a stale
    executing+verifiable row whose probe says PRESENT -> committed."""
    key = "k-cli-present"
    _seed_backdated_executing_row(store, db, key)

    exit_code = main(
        [
            "reconcile",
            "--store",
            database_url,
            "--import",
            "tests._cli_integrator",
            "--older-than",
            "60",
        ]
    )
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "committed=1" in out
    assert read_row(db, key).state == LedgerState.COMMITTED.value


def test_cli_no_stale_rows_reports_nothing_to_do(
    store: PostgresStore, db: Engine, database_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["reconcile", "--store", database_url, "--import", "tests._cli_integrator"])
    assert exit_code == 0
    assert "no stale in-flight rows" in capsys.readouterr().out


def test_cli_rejects_nonpositive_older_than(database_url: str) -> None:
    with pytest.raises(SystemExit):
        main(["reconcile", "--store", database_url, "--older-than", "0"])


def test_cli_reports_bad_import(database_url: str) -> None:
    with pytest.raises(SystemExit):
        main(["reconcile", "--store", database_url, "--import", "does.not.exist"])


def test_cli_reports_bad_store_dsn() -> None:
    with pytest.raises(SystemExit):
        main(["reconcile", "--store", "not-a-dsn", "--import", "tests._cli_integrator"])


def test_cli_requires_a_subcommand() -> None:
    with pytest.raises(SystemExit):
        main([])
