"""The action registry shared by ``commit_once`` (inline) and the reconciler.

Cross-process recovery is the reason this exists. When a reconciler (a
different process, possibly a `python -m airlock reconcile` cron job) finds a
stale in-flight row, all it has is the persisted ``commit_records`` row:
``action_type``, ``args_json``, ``downstream_key``, ``guarantee``. To recover
it must reconstruct three things the original caller passed to ``commit_once``
but that were never persisted as code — the :class:`~airlock.effects.Effect`
(its ``verify`` probe and key mapping), the ``execute`` callable, and the
``preconditions`` check. The registry is the lookup from ``action_type`` to
those three, populated at import time and shared by both invocation paths.

**One registry, two populators, two consumers.** In P1.3 there is no
``@guard`` yet, so integrators populate it explicitly with :func:`register`
(or ``Registry.register``); the reconciler CLI loads the integrator module via
``--import`` so that registration runs. In P2.1 the ``@guard`` decorator will
populate THIS SAME registry from the decorated function — same shape, so the
reconciler needs no change. ``commit_once`` itself does not require the
registry (its caller passes ``effect``/``execute``/``preconditions``
directly); the registry is what lets a *reconciler* reconstruct that same call
from a bare ledger row.

**Calling convention (the arg_map contract).** The reconciler only ever has
``args_json`` — the canonical arg_map — to work with, so every registered
callable is invoked with that map splatted as keyword arguments, exactly like
``Effect.verify(**arg_map)`` (PLAN.md 4.2: "the probe calling convention is
``verify`` called with the rehydrated arg_map as kwargs"; this task extends
that convention to ``execute`` and ``preconditions``):

- ``execute(downstream_key, **arg_map) -> JsonValue`` — the side effect. It
  receives the downstream idempotency key first (positionally, as
  ``commit_once`` passes it) and the rehydrated arguments as kwargs. Accept
  ``**_`` for args it does not need.
- ``preconditions(**arg_map) -> bool`` — re-validated before any (re-)execute
  (scenario 8 applied to recovery); ``None`` means "no preconditions" and is
  treated as always-satisfied.

An ``execute`` written for the registry therefore has a superset of the
``commit_once`` ``execute`` signature (which is ``execute(downstream_key)``):
binding the extra ``**arg_map`` is backward compatible for a callable that
ignores it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from pydantic import JsonValue

from airlock.effects import Effect

__all__ = ["Registration", "Registry", "register", "registry"]


@dataclass(frozen=True)
class Registration:
    """Everything the reconciler needs to recover one ``action_type``.

    Attributes:
        effect: the ADR-2 declaration — supplies the ``verify`` probe (the
            ``verifiable`` recovery path), the downstream-key derivation (the
            ``downstream_idempotent`` re-issue path), and the guarantee.
        execute: the side effect, invoked ``execute(downstream_key,
            **arg_map)`` — the reconciler re-runs it on the ``pending`` retry
            path and the ``executing``/``absent`` retry path, under the
            bumped epoch.
        preconditions: re-validated before any (re-)execute, invoked
            ``preconditions(**arg_map)``; ``None`` means always-satisfied.
    """

    effect: Effect
    execute: Callable[..., JsonValue]
    preconditions: Callable[..., bool] | None = None


class Registry:
    """A mutable ``action_type -> Registration`` map (shared, import-time).

    Registration is intentionally strict: re-registering the same
    ``action_type`` with a DIFFERENT registration raises, because a silent
    overwrite would make the reconciler recover an action with the wrong
    effect/execute — a recipe for a double-commit or a lost side effect.
    Re-registering the identical registration (a module imported twice) is a
    harmless no-op.
    """

    def __init__(self) -> None:
        self._registrations: dict[str, Registration] = {}

    def register(
        self,
        action_type: str,
        effect: Effect,
        execute: Callable[..., JsonValue],
        preconditions: Callable[..., bool] | None = None,
    ) -> Registration:
        """Register (or idempotently re-register) recovery for ``action_type``.

        Raises:
            ValueError: empty ``action_type``, or ``action_type`` already
                registered with a *different* registration.
        """
        if not action_type:
            raise ValueError("action_type must be a non-empty string")
        registration = Registration(effect=effect, execute=execute, preconditions=preconditions)
        existing = self._registrations.get(action_type)
        if existing is not None and existing != registration:
            raise ValueError(
                f"action_type {action_type!r} is already registered with a different "
                "effect/execute/preconditions — refusing to overwrite: the reconciler would "
                "recover the action with the wrong recovery logic. Register each action_type "
                "exactly once (import the defining module once)."
            )
        self._registrations[action_type] = registration
        return registration

    def get(self, action_type: str) -> Registration | None:
        """Return the registration for ``action_type``, or ``None``."""
        return self._registrations.get(action_type)

    def __contains__(self, action_type: object) -> bool:
        return action_type in self._registrations

    def __len__(self) -> int:
        return len(self._registrations)


#: The process-wide default registry. ``@guard`` (P2.1) and the reconciler CLI
#: use this one unless a caller passes an explicit :class:`Registry`.
registry = Registry()


def register(
    action_type: str,
    effect: Effect,
    execute: Callable[..., JsonValue],
    preconditions: Callable[..., bool] | None = None,
) -> Registration:
    """Register recovery for ``action_type`` on the default :data:`registry`."""
    return registry.register(action_type, effect, execute, preconditions)
