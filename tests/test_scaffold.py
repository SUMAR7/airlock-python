"""Package-surface tests: metadata, the import-light guard, lazy re-exports.

The import-light guard (PLAN.md section 3.1) asserts extras' modules are not
IMPORTED by the base package — regardless of whether they are installed. As of
P1.1 it also covers the ledger modules: sqlalchemy loads only inside
``airlock.store.postgres``, which is imported lazily by ``from_url``.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

import airlock


def test_version() -> None:
    assert airlock.__version__ == "0.0.1"


def test_base_import_is_light() -> None:
    """A fresh interpreter importing airlock's base modules must not load extras."""
    code = (
        "import sys\n"
        "import airlock\n"
        "import airlock.commit\n"
        "import airlock.errors\n"
        "import airlock.store\n"
        "import airlock.store._schema\n"
        "import airlock.types\n"
        "assert 'sqlalchemy' not in sys.modules, 'sqlalchemy leaked into the base import'\n"
        "assert 'httpx' not in sys.modules, 'httpx leaked into the base import'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"import-light guard failed:\n{result.stderr}"


def test_lazy_public_surface() -> None:
    """PEP 562 re-exports resolve to the real objects."""
    from airlock.commit import commit_once
    from airlock.errors import AirlockError, CommitWaitTimeout
    from airlock.store import Store, from_url
    from airlock.types import Claim, CommitOutcome, CommitRecord, Guarantee, LedgerState

    assert airlock.commit_once is commit_once
    assert airlock.AirlockError is AirlockError
    assert airlock.CommitWaitTimeout is CommitWaitTimeout
    assert airlock.Store is Store
    assert airlock.from_url is from_url
    assert airlock.Claim is Claim
    assert airlock.CommitOutcome is CommitOutcome
    assert airlock.CommitRecord is CommitRecord
    assert airlock.Guarantee is Guarantee
    assert airlock.LedgerState is LedgerState


def test_unknown_attribute_raises() -> None:
    with pytest.raises(AttributeError, match="no attribute 'reconcile'"):
        _ = airlock.reconcile
