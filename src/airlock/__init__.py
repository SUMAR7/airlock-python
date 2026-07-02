"""Airlock — gate irreversible agent actions, commit exactly once, prove it.

The public surface is re-exported lazily (PEP 562) so ``import airlock`` stays
import-light: optional extras (sqlalchemy/psycopg, httpx) are only imported by
the modules that need them, and only when used — enforced by a CI guard.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__version__ = "0.0.1"

if TYPE_CHECKING:
    from airlock.commit import commit_once as commit_once
    from airlock.errors import AirlockError as AirlockError
    from airlock.errors import CommitWaitTimeout as CommitWaitTimeout
    from airlock.store import Store as Store
    from airlock.store import from_url as from_url
    from airlock.types import Claim as Claim
    from airlock.types import CommitOutcome as CommitOutcome
    from airlock.types import CommitRecord as CommitRecord
    from airlock.types import Guarantee as Guarantee
    from airlock.types import LedgerState as LedgerState

_EXPORTS: dict[str, str] = {
    "commit_once": "airlock.commit",
    "AirlockError": "airlock.errors",
    "CommitWaitTimeout": "airlock.errors",
    "Store": "airlock.store",
    "from_url": "airlock.store",
    "Claim": "airlock.types",
    "CommitOutcome": "airlock.types",
    "CommitRecord": "airlock.types",
    "Guarantee": "airlock.types",
    "LedgerState": "airlock.types",
}

__all__ = ["__version__", *sorted(_EXPORTS)]


def __getattr__(name: str) -> Any:
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    value: Any = getattr(importlib.import_module(module_name), name)
    globals()[name] = value  # cache for subsequent lookups
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
