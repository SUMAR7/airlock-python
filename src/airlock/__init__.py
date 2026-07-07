"""Airlock — gate irreversible agent actions, commit exactly once, prove it.

The public surface is re-exported lazily (PEP 562) so ``import airlock`` stays
import-light: optional extras (sqlalchemy/psycopg, httpx) are only imported by
the modules that need them, and only when used — enforced by a CI guard.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__version__ = "0.0.1"

if TYPE_CHECKING:
    from airlock._canonical import CANON_VERSION as CANON_VERSION
    from airlock._canonical import canonical_bytes as canonical_bytes
    from airlock._canonical import canonical_json as canonical_json
    from airlock._canonical import decimal_string as decimal_string
    from airlock._guard import Airlock as Airlock
    from airlock._guard import guard as guard
    from airlock._guard import init as init
    from airlock.audit import ChainReport as ChainReport
    from airlock.audit import compute_row_hash as compute_row_hash
    from airlock.audit import verify_chain as verify_chain
    from airlock.commit import commit_once as commit_once
    from airlock.effects import Effect as Effect
    from airlock.errors import ActionDenied as ActionDenied
    from airlock.errors import ActionPending as ActionPending
    from airlock.errors import AirlockError as AirlockError
    from airlock.errors import AtMostOnceWarning as AtMostOnceWarning
    from airlock.errors import AuditChainError as AuditChainError
    from airlock.errors import CanonicalizationError as CanonicalizationError
    from airlock.errors import CommitFailed as CommitFailed
    from airlock.errors import CommitWaitTimeout as CommitWaitTimeout
    from airlock.errors import GateNotSupported as GateNotSupported
    from airlock.errors import PreconditionFailed as PreconditionFailed
    from airlock.errors import VerificationUnknown as VerificationUnknown
    from airlock.events import ActionEvent as ActionEvent
    from airlock.events import EventSink as EventSink
    from airlock.events import PostVerify as PostVerify
    from airlock.idempotency import build_arg_map as build_arg_map
    from airlock.idempotency import derive_key as derive_key
    from airlock.idempotency import namespace_user_key as namespace_user_key
    from airlock.policy import ActionContext as ActionContext
    from airlock.policy import Policy as Policy
    from airlock.policy import PolicyBackend as PolicyBackend
    from airlock.policy import Rule as Rule
    from airlock.store import Store as Store
    from airlock.store import from_url as from_url
    from airlock.types import ActionOutcome as ActionOutcome
    from airlock.types import AuditEvent as AuditEvent
    from airlock.types import AuditHead as AuditHead
    from airlock.types import AuditRow as AuditRow
    from airlock.types import BlastRadius as BlastRadius
    from airlock.types import Claim as Claim
    from airlock.types import CommitOutcome as CommitOutcome
    from airlock.types import CommitRecord as CommitRecord
    from airlock.types import Decision as Decision
    from airlock.types import Guarantee as Guarantee
    from airlock.types import HumanDecision as HumanDecision
    from airlock.types import LedgerState as LedgerState
    from airlock.types import Money as Money
    from airlock.types import Reversibility as Reversibility
    from airlock.types import Verification as Verification

_EXPORTS: dict[str, str] = {
    "CANON_VERSION": "airlock._canonical",
    "canonical_bytes": "airlock._canonical",
    "canonical_json": "airlock._canonical",
    "decimal_string": "airlock._canonical",
    "ChainReport": "airlock.audit",
    "compute_row_hash": "airlock.audit",
    "verify_chain": "airlock.audit",
    "commit_once": "airlock.commit",
    "Effect": "airlock.effects",
    "ActionDenied": "airlock.errors",
    "ActionPending": "airlock.errors",
    "AirlockError": "airlock.errors",
    "AtMostOnceWarning": "airlock.errors",
    "AuditChainError": "airlock.errors",
    "CanonicalizationError": "airlock.errors",
    "CommitFailed": "airlock.errors",
    "CommitWaitTimeout": "airlock.errors",
    "GateNotSupported": "airlock.errors",
    "PreconditionFailed": "airlock.errors",
    "VerificationUnknown": "airlock.errors",
    "ActionEvent": "airlock.events",
    "EventSink": "airlock.events",
    "PostVerify": "airlock.events",
    "Airlock": "airlock._guard",
    "guard": "airlock._guard",
    "init": "airlock._guard",
    "build_arg_map": "airlock.idempotency",
    "derive_key": "airlock.idempotency",
    "namespace_user_key": "airlock.idempotency",
    "ActionContext": "airlock.policy",
    "Policy": "airlock.policy",
    "PolicyBackend": "airlock.policy",
    "Rule": "airlock.policy",
    "Store": "airlock.store",
    "from_url": "airlock.store",
    "ActionOutcome": "airlock.types",
    "AuditEvent": "airlock.types",
    "AuditHead": "airlock.types",
    "AuditRow": "airlock.types",
    "BlastRadius": "airlock.types",
    "Claim": "airlock.types",
    "CommitOutcome": "airlock.types",
    "CommitRecord": "airlock.types",
    "Decision": "airlock.types",
    "Guarantee": "airlock.types",
    "HumanDecision": "airlock.types",
    "LedgerState": "airlock.types",
    "Money": "airlock.types",
    "Reversibility": "airlock.types",
    "Verification": "airlock.types",
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
