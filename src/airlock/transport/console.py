"""``ConsoleApprovalTransport`` — the P2.3 stub transport (SPEC.md Phase 2).

The MVP ships with NO hosted control plane (that is Phase 3), so a gated action
reaches a human through a local file instead of the network. This transport is
exactly the "CLI/file approve" stub SPEC.md Phase 2 calls for:

- :meth:`send` prints a one-line summary of the :class:`~airlock.transport.
  PauseRequest` (identifiers + risk metadata — never tool args, by construction:
  ``PauseRequest`` cannot carry them) to a stream, so an operator watching the
  console sees what is waiting. It is redelivery-safe: printing the same
  ``approval_ref`` twice is harmless (the durable pause already exists).
- :meth:`wait` polls an **approvals file** for a decision matching the
  ``approval_ref`` and returns it, or ``None`` once ``timeout`` seconds elapse
  (never raising for "no decision yet" — the caller then raises
  :class:`~airlock.errors.ActionPending` and the pause stays durable for a later
  resume).

The approvals file — the format
-------------------------------
A UTF-8 text file of **JSON Lines** — one JSON object per line. Each line is one
decision::

    {"approval_ref": "1b4e...-uuid", "decision": "approved", "decided_by": "usr_ada"}
    {"approval_ref": "9c2f...-uuid", "decision": "rejected", "reason": "too risky", "reason_code": "not_authorized"}

Recognised keys per line:

- ``approval_ref`` (str, required) — the SDK-minted reference the decision is for
  (the only cross-boundary key, PLAN.md 6.1). Lines for other refs are ignored.
- ``decision`` (str, required) — ``"approved"`` or ``"rejected"`` (the
  :class:`~airlock.types.HumanDecision` vocabulary).
- ``decided_by`` (str, optional) — an opaque actor id (``usr_...``), never an
  email (PLAN.md 10.6).
- ``decided_by_display`` (str, optional) — a human-readable name/email.
- ``decision_latency_ms`` (int, optional) — recorded verbatim if present;
  otherwise ``apply_decision`` computes it from the SDK clock pair (PLAN.md 6.2).
- ``reason`` (str, optional) — a free-text note.
- ``reason_code`` (str, optional) — the structured rejection code the human
  chose from the set the action offered (``@guard(reject_reasons=...)``, P3.9);
  surfaced on :attr:`~airlock.errors.ApprovalRejected.reason_code`.

The **first** line matching ``approval_ref`` wins; duplicate lines for the same
ref are harmless (``apply_decision`` is idempotent — writing an approval twice
cannot double-commit, which is exactly what the MVP end-to-end test proves).
Blank lines and lines that do not parse as a JSON object with an
``approval_ref`` are skipped (a partial concurrent append is simply re-read on
the next poll).

Both interactive and scripted use are supported by the same mechanism: an
operator (or a tiny wrapper CLI) appends a decision line by hand, and a test
appends one with :meth:`record_decision`. There is no interactive ``input()``
prompt — blocking on stdin would not survive a restart, and the whole point of
ADR-4 is that the decision outlives the process.

Import-light: stdlib + pydantic (``airlock.types``) only — no sockets, no
extras (PLAN.md 3.1). The HTTP transport is P3.4 and deliberately absent.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from airlock.transport import PauseRequest, SendReceipt
from airlock.types import ApprovalDecision, HumanDecision

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ["DEFAULT_APPROVALS_FILE", "ConsoleApprovalTransport"]

#: The approvals file used when none is passed and ``AIRLOCK_APPROVALS_FILE`` is
#: unset. A relative path so a quickstart writes it into the working directory.
DEFAULT_APPROVALS_FILE = "airlock-approvals.jsonl"


class ConsoleApprovalTransport:
    """A file-backed stub :class:`~airlock.transport.ApprovalTransport` (P2.3).

    Args:
        approvals_path: the JSON Lines approvals file. Defaults to the
            ``AIRLOCK_APPROVALS_FILE`` environment variable, then
            :data:`DEFAULT_APPROVALS_FILE`. Reading a missing file is not an
            error — it just means "no decision yet".
        out: where :meth:`send` prints its summary (default ``sys.stdout``);
            pass any text stream (or a capture buffer in tests).
        poll_interval: seconds between file polls in :meth:`wait` (default
            0.2). Only slept BETWEEN polls: a decision already present, or a
            zero ``timeout``, returns without sleeping at all.
        sleep_fn / monotonic_fn: injectable clock hooks for deterministic
            tests (default the real ``time.sleep`` / ``time.monotonic``).
    """

    def __init__(
        self,
        approvals_path: str | os.PathLike[str] | None = None,
        *,
        out: TextIO | None = None,
        poll_interval: float = 0.2,
        sleep_fn: Callable[[float], None] | None = None,
        monotonic_fn: Callable[[], float] | None = None,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError(f"poll_interval must be > 0, got {poll_interval!r}")
        resolved = (
            approvals_path
            if approvals_path is not None
            else os.environ.get("AIRLOCK_APPROVALS_FILE", DEFAULT_APPROVALS_FILE)
        )
        self._path = Path(resolved)
        self._out = out if out is not None else sys.stdout
        self._poll_interval = poll_interval
        # ``None`` means "use the live time module": the poll then resolves
        # ``time.sleep`` / ``time.monotonic`` dynamically at each call, so
        # production sleeps for real while the test suite's no-time.sleep guard
        # governs any accidental blocking wait (a gate that waits with no
        # decision fails fast in tests instead of hanging). Injected hooks (the
        # console unit tests) bypass both deterministically.
        self._sleep_fn = sleep_fn
        self._monotonic_fn = monotonic_fn

    def _monotonic(self) -> float:
        return self._monotonic_fn() if self._monotonic_fn is not None else time.monotonic()

    def _do_sleep(self, seconds: float) -> None:
        if self._sleep_fn is not None:
            self._sleep_fn(seconds)
        else:
            time.sleep(seconds)  # live: production sleeps; the test guard governs it

    @property
    def approvals_path(self) -> Path:
        """The approvals file this transport reads decisions from."""
        return self._path

    def send(self, request: PauseRequest) -> SendReceipt:
        """Print the pause summary; return a receipt (redelivery-safe).

        No hosted ``approval_id`` exists for a local transport, so the receipt
        carries only the ``approval_ref`` it delivered (the reconciler backstop
        poll is a P3.x concern). Printing is best-effort framing for a human;
        the durable record is the ``paused_runs`` row, already persisted.
        """
        cost = f"{request.cost.amount} {request.cost.currency}" if request.cost is not None else "—"
        reversibility = (
            request.reversibility.value if request.reversibility is not None else "unknown"
        )
        blast = (
            request.blast_radius_estimate.value
            if request.blast_radius_estimate is not None
            else "unknown"
        )
        context_lines = ""
        if request.review_context:
            rendered = "\n".join(
                f"          - {key}: {value}" for key, value in request.review_context.items()
            )
            context_lines = f"\n          context:\n{rendered}"
        print(
            f"[airlock] approval requested: {request.summary} "
            f"(action={request.action_type}, cost={cost}, reversibility={reversibility}, "
            f"blast_radius={blast})\n"
            f"          approval_ref={request.approval_ref} run_id={request.run_id}"
            f"{context_lines}\n"
            f"          approve/reject by appending a line to {self._path}",
            file=self._out,
        )
        return SendReceipt(approval_ref=request.approval_ref)

    def wait(self, approval_ref: str, timeout: float) -> ApprovalDecision | None:
        """Poll the approvals file for ``approval_ref`` up to ``timeout`` seconds.

        Returns the decision as soon as a matching line appears, or ``None``
        when ``timeout`` elapses. A decision already in the file is returned on
        the FIRST scan with no sleep; ``timeout <= 0`` scans exactly once and
        returns ``None`` if nothing matches (so it never sleeps either).
        """
        deadline = self._monotonic() + timeout
        while True:
            decision = self._scan(approval_ref)
            if decision is not None:
                return decision
            if self._monotonic() >= deadline:
                return None
            self._do_sleep(self._poll_interval)

    def record_decision(
        self,
        approval_ref: str,
        decision: HumanDecision | str,
        *,
        decided_by: str | None = None,
        decided_by_display: str | None = None,
        decision_latency_ms: int | None = None,
        reason: str | None = None,
        reason_code: str | None = None,
    ) -> None:
        """Append one decision line to the approvals file (interactive/test helper).

        The same file :meth:`wait` polls. Writing the SAME ``approval_ref``
        twice is safe — ``apply_decision`` deduplicates, so a double-delivered
        approval still commits exactly once.
        """
        value = decision.value if isinstance(decision, HumanDecision) else HumanDecision(decision)
        line: dict[str, object] = {"approval_ref": approval_ref, "decision": value}
        if decided_by is not None:
            line["decided_by"] = decided_by
        if decided_by_display is not None:
            line["decided_by_display"] = decided_by_display
        if decision_latency_ms is not None:
            line["decision_latency_ms"] = decision_latency_ms
        if reason is not None:
            line["reason"] = reason
        if reason_code is not None:
            line["reason_code"] = reason_code
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(line) + "\n")

    def _scan(self, approval_ref: str) -> ApprovalDecision | None:
        """Return the FIRST decision matching ``approval_ref``, or ``None``.

        Tolerant of partial concurrent appends: blank lines and lines that do
        not parse as a JSON object carrying this ``approval_ref`` are skipped
        (the next poll re-reads). A line whose ``decision`` is not a valid
        :class:`~airlock.types.HumanDecision` raises — a typo'd verdict is an
        operator error worth surfacing, not silently ignoring.
        """
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue  # a partial append; re-read next poll
            if not isinstance(obj, dict) or obj.get("approval_ref") != approval_ref:
                continue
            raw_decision = obj.get("decision")
            if not isinstance(raw_decision, str):
                continue
            decision = HumanDecision(raw_decision)  # raises loudly on a typo'd verdict
            decided_at = _parse_decided_at(obj.get("decided_at"))
            return ApprovalDecision(
                decision=decision,
                decided_by=_opt_str(obj.get("decided_by")),
                decided_by_display=_opt_str(obj.get("decided_by_display")),
                decided_at=decided_at,
                decision_latency_ms=_opt_int(obj.get("decision_latency_ms")),
                reason=_opt_str(obj.get("reason")),
                reason_code=_opt_str(obj.get("reason_code")),
            )
        return None


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _opt_int(value: object) -> int | None:
    # bool is an int subclass; exclude it — a JSON true/false is not a latency.
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _parse_decided_at(value: object) -> datetime | None:
    """Parse an optional RFC 3339 ``decided_at`` string; ``None`` if absent/bad.

    A local transport usually omits it (``apply_decision`` stamps the SDK
    clock); when a line carries one we honour it, but a malformed value is
    treated as absent rather than failing the whole decision.
    """
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None
