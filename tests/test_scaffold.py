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
        "import airlock.events\n"
        "import airlock._guard\n"
        "import airlock.idempotency\n"
        "import airlock.policy\n"
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
    from airlock._guard import Airlock, guard, init
    from airlock.commit import commit_once
    from airlock.effects import Effect
    from airlock.errors import (
        ActionDenied,
        ActionPending,
        AirlockError,
        AtMostOnceWarning,
        CanonicalizationError,
        CommitWaitTimeout,
        GateNotSupported,
        PreconditionFailed,
        VerificationUnknown,
    )
    from airlock.events import EventSink, PolicyDecisionEvent
    from airlock.idempotency import build_arg_map, derive_key, namespace_user_key
    from airlock.policy import ActionContext, Policy, PolicyBackend, Rule
    from airlock.store import Store, from_url
    from airlock.types import (
        BlastRadius,
        Claim,
        CommitOutcome,
        CommitRecord,
        Decision,
        Guarantee,
        LedgerState,
        Money,
        Reversibility,
        Verification,
    )

    assert airlock.CANON_VERSION is CANON_VERSION
    assert airlock.canonical_bytes is canonical_bytes
    assert airlock.canonical_json is canonical_json
    assert airlock.decimal_string is decimal_string
    assert airlock.commit_once is commit_once
    assert airlock.Effect is Effect
    assert airlock.ActionDenied is ActionDenied
    assert airlock.ActionPending is ActionPending
    assert airlock.AirlockError is AirlockError
    assert airlock.AtMostOnceWarning is AtMostOnceWarning
    assert airlock.CanonicalizationError is CanonicalizationError
    assert airlock.CommitWaitTimeout is CommitWaitTimeout
    assert airlock.GateNotSupported is GateNotSupported
    assert airlock.PreconditionFailed is PreconditionFailed
    assert airlock.VerificationUnknown is VerificationUnknown
    assert airlock.EventSink is EventSink
    assert airlock.PolicyDecisionEvent is PolicyDecisionEvent
    assert airlock.Airlock is Airlock
    assert airlock.guard is guard
    assert airlock.init is init
    assert airlock.build_arg_map is build_arg_map
    assert airlock.derive_key is derive_key
    assert airlock.namespace_user_key is namespace_user_key
    assert airlock.ActionContext is ActionContext
    assert airlock.Policy is Policy
    assert airlock.PolicyBackend is PolicyBackend
    assert airlock.Rule is Rule
    assert airlock.Store is Store
    assert airlock.from_url is from_url
    assert airlock.BlastRadius is BlastRadius
    assert airlock.Claim is Claim
    assert airlock.CommitOutcome is CommitOutcome
    assert airlock.CommitRecord is CommitRecord
    assert airlock.Decision is Decision
    assert airlock.Guarantee is Guarantee
    assert airlock.LedgerState is LedgerState
    assert airlock.Money is Money
    assert airlock.Reversibility is Reversibility
    assert airlock.Verification is Verification


def test_guard_public_name_is_the_function_not_a_submodule() -> None:
    """Regression: the public ``guard`` must be the decorator FUNCTION under any
    import order — never a submodule shadow.

    The implementation module is ``airlock._guard`` (private), so the public
    name ``guard`` has no same-named submodule to collide with. Were the module
    still ``airlock.guard``, importing it would bind the MODULE onto the package
    namespace as ``airlock.guard`` and permanently shadow the lazy re-export, so
    both ``airlock.guard`` and ``from airlock import guard`` would return the
    module instead of the decorator (order-dependently). This runs in a fresh
    interpreter that imports the private module FIRST, then asserts every public
    access form still yields the function.
    """
    code = (
        "import airlock._guard\n"  # would shadow if the module were named 'guard'
        "import airlock\n"
        "from airlock import guard as imported_guard\n"
        "from airlock._guard import guard as real_guard\n"
        "assert airlock.guard is real_guard, 'airlock.guard is not the function'\n"
        "assert imported_guard is real_guard, 'from airlock import guard is not the function'\n"
        "import types\n"
        "assert not isinstance(airlock.guard, types.ModuleType), 'guard resolved to a module'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, f"guard public name regressed to a submodule:\n{result.stderr}"


def test_unknown_attribute_raises() -> None:
    with pytest.raises(AttributeError, match="no attribute 'does_not_exist'"):
        _ = airlock.does_not_exist
