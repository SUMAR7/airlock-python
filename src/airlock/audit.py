"""Hash-chain compute + verify for ``audit_events`` (ADR-5, PLAN.md 5.2).

The chain rule
==============

Every audit row stores ``prev_hash`` and::

    row_hash = SHA-256( prev_hash (32 raw bytes) || canonical_bytes(envelope) )

where the **envelope** covers ``{seq, run_id, action_type, event_type,
created_at, payload}`` — hashing only the payload would leave the other
columns tamperable (PLAN.md 5.2). Canonicalization is ``airlock-canon-1`` via
the ONE shared implementation, :mod:`airlock._canonical` (the standalone
contract is ``/contracts/canonical-json.md``) — never reimplemented here.

Envelope field encoding (normative, frozen):

- ``seq``: JSON integer (chain position; ``0`` is genesis).
- ``run_id`` / ``action_type``: JSON string or ``null``.
- ``event_type``: JSON string.
- ``created_at``: RFC 3339 UTC string with microsecond precision and a ``Z``
  suffix (``YYYY-MM-DDTHH:MM:SS.ffffffZ`` — the airlock-canon-1 timestamp
  convention). The hashed value and the stored ``TIMESTAMPTZ`` column are the
  SAME instant: the SDK stamps the timestamp (injectable ``now_fn``, never
  ``DEFAULT now()``), hashes its rendering, and stores the datetime; a
  verifier re-renders the stored column and must get the identical string.
- ``payload``: the JSON object stored in ``payload_json``, restricted to the
  ``airlock-canon-1`` value domain (floats rejected at emit time, ...).

Hashing happens **in the SDK only** — the DB stays dumb (no hash triggers);
the DB's job is append-only enforcement (trigger + REVOKE) and the chain-head
row lock that serializes appenders (``airlock.store``).

Genesis (a universal constant)
==============================

``seq=0``, ``prev_hash = 0x00 * 32``, ``event_type = "genesis"``,
``run_id = action_type = null``, ``created_at`` fixed at the epoch
(``1970-01-01T00:00:00.000000Z``) and the documented payload
:data:`GENESIS_PAYLOAD`. Every field is a constant, so the genesis
``row_hash`` (:data:`GENESIS_ROW_HASH`) is identical across every
installation — verification checks it byte-for-byte, which pins the chain's
anchor as well as its links. ``ensure_schema`` inserts the genesis row and the
chain head idempotently.

Verification
============

:func:`verify_chain` streams rows ``ORDER BY seq`` (O(n), constant memory —
the store yields rows from a server-side cursor) and checks, per row: gapless
``seq``, ``prev_hash`` linkage, and the recomputed ``row_hash``; plus the
genesis constant at ``seq=0`` and, at the end, that ``audit_chain_head``
matches the last row. Checkpoint verification (``from_seq=N, from_hash=H``)
anchors at an externally-noted ``(seq, row_hash)`` pair instead of genesis and
verifies only the delta — O(delta). Any failure raises
:class:`~airlock.errors.AuditChainError` naming the offending ``seq``.

CLI: ``python -m airlock audit verify --store DSN [--from-seq N --from-hash H]``.

Import-light: stdlib + pydantic (via ``airlock.types``) only.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol

from pydantic import BaseModel, ConfigDict, JsonValue

from airlock._canonical import canonical_bytes
from airlock.errors import AuditChainError
from airlock.types import AuditHead, AuditRow

if TYPE_CHECKING:
    from collections.abc import Iterator

__all__ = [
    "GENESIS_CREATED_AT",
    "GENESIS_EVENT_TYPE",
    "GENESIS_PAYLOAD",
    "GENESIS_ROW_HASH",
    "ZERO_HASH",
    "AuditStore",
    "ChainReport",
    "compute_row_hash",
    "envelope",
    "rfc3339_utc",
    "verify_chain",
]

#: The genesis row's ``prev_hash``: 32 zero bytes (PLAN.md 5.2).
ZERO_HASH: bytes = b"\x00" * 32

#: The genesis row's ``event_type``.
GENESIS_EVENT_TYPE = "genesis"

#: The documented genesis payload (PLAN.md 5.1): names the chain rule and the
#: canonicalization it is defined over. Frozen — any change would change
#: GENESIS_ROW_HASH and orphan every existing chain.
GENESIS_PAYLOAD: dict[str, JsonValue] = {
    "chain": "airlock-audit-v1",
    "canon": "airlock-canon-1",
}

#: The genesis row's ``created_at``: the fixed epoch instant, NOT an install
#: timestamp — so the genesis row (and its hash) is a universal constant. It is
#: still an SDK-supplied value (a frozen constant, never ``DEFAULT now()``).
GENESIS_CREATED_AT: datetime = datetime(1970, 1, 1, tzinfo=UTC)


def rfc3339_utc(value: datetime) -> str:
    """Render a tz-aware datetime as the canonical RFC 3339 UTC string.

    ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` — microsecond precision, ``Z`` suffix, the
    airlock-canon-1 timestamp convention (/contracts/canonical-json.md §5).
    Exactly this rendering is hashed into the envelope, so it is frozen.

    Raises:
        ValueError: ``value`` is naive (no tzinfo). A naive timestamp has no
            defined UTC instant; hashing a guess would make the chain
            unverifiable across timezones.
    """
    if value.tzinfo is None:
        raise ValueError(
            f"audit timestamps must be timezone-aware, got naive {value!r} — a naive "
            "datetime has no defined UTC instant and would make the hashed envelope "
            "unverifiable"
        )
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def envelope(
    *,
    seq: int,
    run_id: str | None,
    action_type: str | None,
    event_type: str,
    created_at: datetime,
    payload: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    """Build the hash envelope for one row (PLAN.md 5.2).

    Covers every chain-meaningful column — ``{seq, run_id, action_type,
    event_type, created_at, payload}`` — so none of them is tamperable without
    breaking the recomputed hash.
    """
    return {
        "seq": seq,
        "run_id": run_id,
        "action_type": action_type,
        "event_type": event_type,
        "created_at": rfc3339_utc(created_at),
        "payload": payload,
    }


def compute_row_hash(
    prev_hash: bytes,
    *,
    seq: int,
    run_id: str | None,
    action_type: str | None,
    event_type: str,
    created_at: datetime,
    payload: dict[str, JsonValue],
) -> bytes:
    """``SHA-256(prev_hash || canonical_bytes(envelope))`` — the chain rule.

    Raises:
        ValueError: ``prev_hash`` is not exactly 32 bytes (a truncated or
            hex-encoded hash silently forks the chain, so the length is
            checked here as well as by the DDL CHECK).
        CanonicalizationError: the payload (or an envelope string) lies
            outside the ``airlock-canon-1`` domain.
    """
    if len(prev_hash) != 32:
        raise ValueError(f"prev_hash must be exactly 32 raw bytes, got {len(prev_hash)}")
    body = envelope(
        seq=seq,
        run_id=run_id,
        action_type=action_type,
        event_type=event_type,
        created_at=created_at,
        payload=payload,
    )
    return hashlib.sha256(prev_hash + canonical_bytes(body)).digest()


def _genesis_row_hash() -> bytes:
    return compute_row_hash(
        ZERO_HASH,
        seq=0,
        run_id=None,
        action_type=None,
        event_type=GENESIS_EVENT_TYPE,
        created_at=GENESIS_CREATED_AT,
        payload=GENESIS_PAYLOAD,
    )


#: The universal genesis ``row_hash`` — a constant of the format (every field
#: of the genesis envelope is frozen above). Verification compares the stored
#: genesis row against this byte-for-byte.
GENESIS_ROW_HASH: bytes = _genesis_row_hash()


class AuditStore(Protocol):
    """The read surface :func:`verify_chain` needs (a Store subset).

    ``iter_audit`` must yield rows ``ORDER BY seq`` from a streaming cursor
    (constant memory); ``audit_head`` reads the ``audit_chain_head`` singleton.
    """

    def iter_audit(self, start_seq: int = 0) -> Iterator[AuditRow]: ...

    def audit_head(self) -> AuditHead | None: ...


class ChainReport(BaseModel):
    """The result of a successful :func:`verify_chain` pass."""

    model_config = ConfigDict(frozen=True)

    #: Rows whose hashes were recomputed and matched.
    rows_verified: int
    #: seq of the first row verified (0 for a full pass, N for a checkpoint pass).
    from_seq: int
    #: The verified head position (== audit_chain_head).
    head_seq: int
    head_hash: bytes


def verify_chain(
    store: AuditStore,
    *,
    from_seq: int | None = None,
    from_hash: bytes | None = None,
) -> ChainReport:
    """Verify the audit chain end-to-end (or from a checkpoint) — O(n) / O(delta).

    Full pass (``from_seq=None``): streams every row ``ORDER BY seq`` in one
    pass with constant memory, checking per row that ``seq`` is gapless, that
    ``prev_hash`` equals the previous row's ``row_hash``, and that the stored
    ``row_hash`` equals the recomputed
    ``SHA-256(prev_hash || canonical_bytes(envelope))``; the genesis row must
    match the :data:`GENESIS_ROW_HASH` constant exactly, and at the end
    ``audit_chain_head`` must match the last row (a truncated tail — deleted
    trailing rows — is caught here).

    Checkpoint pass (``from_seq=N, from_hash=H``): anchors at an
    externally-noted ``(seq, row_hash)`` pair — the row at ``N`` must exist,
    its stored AND recomputed ``row_hash`` must equal ``H`` — then verifies
    only rows ``N..head`` (O(delta)). Rows before ``N`` are vouched for by the
    checkpoint, exactly like a partial blockchain sync.

    Args:
        store: anything exposing ``iter_audit``/``audit_head``
            (:class:`AuditStore`); the Postgres store qualifies.
        from_seq: checkpoint seq, or ``None`` for a full pass.
        from_hash: the 32-byte ``row_hash`` externally noted for ``from_seq``.
            Required with ``from_seq``; both or neither.

    Returns:
        A :class:`ChainReport` on success.

    Raises:
        AuditChainError: the chain is broken/tampered — the message and the
            ``seq`` attribute name the first offending row (or ``head`` issues
            via the last seq).
        ValueError: inconsistent checkpoint arguments.
    """
    if (from_seq is None) != (from_hash is None):
        raise ValueError("from_seq and from_hash must be supplied together (or neither)")
    if from_seq is not None and from_seq < 0:
        raise ValueError(f"from_seq must be >= 0, got {from_seq}")
    if from_hash is not None and len(from_hash) != 32:
        raise ValueError(f"from_hash must be exactly 32 raw bytes, got {len(from_hash)}")

    start_seq = 0 if from_seq is None else from_seq
    prev_row_hash: bytes | None = None  # None until the anchor row is verified
    last_seq: int | None = None
    last_hash: bytes | None = None
    count = 0

    for row in store.iter_audit(start_seq):
        if last_seq is None:
            _verify_anchor(row, from_seq=from_seq, from_hash=from_hash)
        else:
            if row.seq != last_seq + 1:
                raise AuditChainError(
                    f"audit chain has a seq gap: row {last_seq} is followed by row "
                    f"{row.seq} (expected {last_seq + 1}) — a row was deleted or the "
                    "gapless append protocol was bypassed",
                    seq=row.seq,
                )
            if row.prev_hash != last_hash:
                raise AuditChainError(
                    f"audit chain link broken at seq {row.seq}: its prev_hash does not "
                    f"equal row {last_seq}'s row_hash",
                    seq=row.seq,
                )
        recomputed = compute_row_hash(
            row.prev_hash,
            seq=row.seq,
            run_id=row.run_id,
            action_type=row.action_type,
            event_type=row.event_type,
            created_at=row.created_at,
            payload=row.payload,
        )
        if recomputed != row.row_hash:
            raise AuditChainError(
                f"audit row {row.seq} is tampered: its stored row_hash does not match "
                "the hash recomputed from its envelope "
                "(seq/run_id/action_type/event_type/created_at/payload)",
                seq=row.seq,
            )
        prev_row_hash = row.row_hash
        last_seq, last_hash = row.seq, row.row_hash
        count += 1

    _ = prev_row_hash
    if last_seq is None or last_hash is None:
        if from_seq is not None:
            raise AuditChainError(
                f"checkpoint row seq {from_seq} does not exist — the chain was truncated "
                "below the checkpoint, or the checkpoint is from a different database",
                seq=from_seq,
            )
        raise AuditChainError(
            "audit chain is empty: the genesis row (seq 0) is missing — run "
            "ensure_schema() to initialize the chain",
            seq=0,
        )

    head = store.audit_head()
    if head is None:
        raise AuditChainError(
            "audit_chain_head is missing — the chain cannot be appended to or "
            "tail-verified; run ensure_schema()",
            seq=last_seq,
        )
    if head.seq != last_seq or head.row_hash != last_hash:
        raise AuditChainError(
            f"audit_chain_head does not match the last row: head says (seq={head.seq}), "
            f"the chain ends at (seq={last_seq}) — trailing rows were deleted or the "
            "head was tampered",
            seq=last_seq,
        )
    return ChainReport(
        rows_verified=count,
        from_seq=start_seq,
        head_seq=last_seq,
        head_hash=last_hash,
    )


def _verify_anchor(row: AuditRow, *, from_seq: int | None, from_hash: bytes | None) -> None:
    """Verify the first streamed row: the genesis constant, or the checkpoint."""
    if from_seq is None:
        # Full pass: the anchor is genesis, a universal constant.
        if row.seq != 0:
            raise AuditChainError(
                f"audit chain does not start at genesis: first row has seq {row.seq} "
                "(expected 0) — the genesis row was deleted",
                seq=row.seq,
            )
        if row.prev_hash != ZERO_HASH:
            raise AuditChainError(
                "genesis row is tampered: prev_hash is not 32 zero bytes",
                seq=0,
            )
        if row.row_hash != GENESIS_ROW_HASH:
            raise AuditChainError(
                "genesis row is tampered: its row_hash does not equal the frozen "
                "genesis constant (event_type/payload/created_at must be the "
                "documented genesis values)",
                seq=0,
            )
        return
    # Checkpoint pass: the anchor is the externally-noted (seq, hash) pair.
    if row.seq != from_seq:
        raise AuditChainError(
            f"checkpoint row seq {from_seq} does not exist: the first row at or above "
            f"it has seq {row.seq} — the checkpointed row was deleted",
            seq=from_seq,
        )
    if row.row_hash != from_hash:
        raise AuditChainError(
            f"checkpoint mismatch at seq {from_seq}: the stored row_hash does not equal "
            "the externally-noted checkpoint hash — history below the head was rewritten",
            seq=from_seq,
        )
