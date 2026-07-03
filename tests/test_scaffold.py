"""Package-surface tests: metadata, the import-light guard, lazy re-exports.

The import-light guard (PLAN.md section 3.1) is enforced in an environment
with extras UNINSTALLED: the core CI job syncs without extras and runs this
module, so a stray module-level ``import sqlalchemy`` anywhere in the base
package fails hard — including in modules the sys.modules assertion below
does not list. The postgres CI job runs it again with extras installed to pin
that the base package still does not IMPORT them. As of P1.1 the guard covers
the ledger modules: sqlalchemy loads only inside ``airlock.store.postgres``,
which is imported lazily by ``from_url``.
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
        "import airlock._canonical\n"
        "import airlock.commit\n"
        "import airlock.effects\n"
        "import airlock.errors\n"
        "import airlock.idempotency\n"
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
    from airlock._canonical import CANON_VERSION, canonical_bytes, canonical_json, decimal_string
    from airlock.commit import commit_once
    from airlock.effects import Effect
    from airlock.errors import (
        AirlockError,
        AtMostOnceWarning,
        CanonicalizationError,
        CommitWaitTimeout,
        VerificationUnknown,
    )
    from airlock.idempotency import build_arg_map, derive_key, namespace_user_key
    from airlock.store import Store, from_url
    from airlock.types import (
        Claim,
        CommitOutcome,
        CommitRecord,
        Guarantee,
        LedgerState,
        Verification,
    )

    assert airlock.CANON_VERSION is CANON_VERSION
    assert airlock.canonical_bytes is canonical_bytes
    assert airlock.canonical_json is canonical_json
    assert airlock.decimal_string is decimal_string
    assert airlock.commit_once is commit_once
    assert airlock.Effect is Effect
    assert airlock.AirlockError is AirlockError
    assert airlock.AtMostOnceWarning is AtMostOnceWarning
    assert airlock.CanonicalizationError is CanonicalizationError
    assert airlock.CommitWaitTimeout is CommitWaitTimeout
    assert airlock.VerificationUnknown is VerificationUnknown
    assert airlock.build_arg_map is build_arg_map
    assert airlock.derive_key is derive_key
    assert airlock.namespace_user_key is namespace_user_key
    assert airlock.Store is Store
    assert airlock.from_url is from_url
    assert airlock.Claim is Claim
    assert airlock.CommitOutcome is CommitOutcome
    assert airlock.CommitRecord is CommitRecord
    assert airlock.Guarantee is Guarantee
    assert airlock.LedgerState is LedgerState
    assert airlock.Verification is Verification


def test_unknown_attribute_raises() -> None:
    with pytest.raises(AttributeError, match="no attribute 'does_not_exist'"):
        _ = airlock.does_not_exist
