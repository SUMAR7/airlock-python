"""``python -m airlock audit verify`` — the verifier CLI (PLAN.md 5.2).

Drives ``airlock.__main__.main`` directly (argv list). The verification logic
is covered in tests/test_audit_chain.py; here we pin the CLI wiring: exit
codes (0 verified / 1 tamper / 2 usage), checkpoint flags, and output shape.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from airlock.__main__ import main
from airlock.types import AuditEvent

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

    from airlock.store.postgres import PostgresStore

NOW = datetime(2026, 7, 6, 12, 0, 0, tzinfo=UTC)


def _seed(store: PostgresStore, count: int = 3) -> None:
    for n in range(1, count + 1):
        store.append_audit(AuditEvent(event_type="action_event", payload={"n": n}, created_at=NOW))


@contextmanager
def _tamper(db: Engine) -> Iterator[None]:
    with db.begin() as conn:
        conn.execute(text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only"))
    try:
        yield
    finally:
        with db.begin() as conn:
            conn.execute(text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only"))


def test_cli_verify_ok(
    store: PostgresStore, database_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed(store)
    assert main(["audit", "verify", "--store", database_url]) == 0
    out = capsys.readouterr().out
    assert "OK" in out and "4 row(s)" in out and "head seq=3" in out


def test_cli_verify_detects_tamper_exit_1(
    store: PostgresStore, db: Engine, database_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed(store)
    with _tamper(db), db.begin() as conn:
        conn.execute(text("UPDATE audit_events SET run_id = 'hax' WHERE seq = 2"))
    assert main(["audit", "verify", "--store", database_url]) == 1
    err = capsys.readouterr().err
    assert "FAILED at seq 2" in err
    assert "P0" in err


def test_cli_verify_from_checkpoint(
    store: PostgresStore, database_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed(store, 2)
    head = store.audit_head()
    assert head is not None
    _seed(store, 2)  # two more rows after the checkpoint
    assert (
        main(
            [
                "audit",
                "verify",
                "--store",
                database_url,
                "--from-seq",
                str(head.seq),
                "--from-hash",
                head.row_hash.hex(),
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert f"from checkpoint seq {head.seq}" in out
    assert "3 row(s)" in out  # the checkpoint row + 2 appended after


def test_cli_verify_checkpoint_flags_must_pair() -> None:
    with pytest.raises(SystemExit):
        main(["audit", "verify", "--store", "postgresql://x/y", "--from-seq", "1"])
    with pytest.raises(SystemExit):
        main(["audit", "verify", "--store", "postgresql://x/y", "--from-hash", "ab" * 32])


def test_cli_verify_rejects_bad_hash() -> None:
    for bad in ("not-hex", "abcd"):  # non-hex; wrong length
        with pytest.raises(SystemExit):
            main(
                [
                    "audit",
                    "verify",
                    "--store",
                    "postgresql://x/y",
                    "--from-seq",
                    "1",
                    "--from-hash",
                    bad,
                ]
            )


def test_cli_verify_rejects_bad_store_dsn() -> None:
    with pytest.raises(SystemExit):
        main(["audit", "verify", "--store", "not-a-dsn"])


def test_cli_audit_requires_a_subcommand() -> None:
    with pytest.raises(SystemExit):
        main(["audit"])
