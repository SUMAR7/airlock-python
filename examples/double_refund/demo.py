"""The double-refund demo: the same retry, told twice.

Run it::

    python demo.py

**ACT 1 — WITHOUT Airlock.** A naive agent issues a refund, then a retry (a
duplicated tool call, a crash-and-resume, an over-eager agent) fires the same
refund AGAIN. Nothing dedupes it, so the customer is refunded TWICE.

**ACT 2 — WITH Airlock.** The exact same tool, wrapped in ``@guard``. Airlock's
commit ledger (ADR-1) claims the action under a deterministic idempotency key
(SPEC.md ADR-2) and passes that key downstream to the payment API. The retry
sees the ledger conflict, returns the first result, and NEVER runs the side
effect again — the customer is refunded exactly once.

Zero infrastructure: ``airlock.init()`` with no store argument uses a local
SQLite file (``./airlock.db``), created and cleaned up by this script.
"""

from __future__ import annotations

import sys
import warnings
from pathlib import Path
from typing import NamedTuple

# Let `from fake_payment_api import ...` resolve whether this file is run as a
# script (its directory is already sys.path[0]) or imported by the test suite.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import airlock
from airlock import Decision, Effect, Money, Policy, Reversibility, Rule
from airlock.store.sqlite import SqliteStore

from fake_payment_api import FakePaymentAPI

#: The charge we refund and the amount ($50.00), shared by both acts.
CHARGE_ID = "ch_demo_ABC123"
AMOUNT_CENTS = 5000

#: SQLite dev-store artifacts init() creates in the working directory.
_DB_FILES = ("airlock.db", "airlock.db-wal", "airlock.db-shm")


def _dollars(cents: int) -> str:
    """Format integer cents as a dollar string, no float rounding surprises."""
    return f"${cents // 100}.{cents % 100:02d}"


# ---------------------------------------------------------------------------
# The payment provider + the guarded refund tool.
#
# In a real app ``payment_api`` is your Stripe client and ``issue_refund`` is
# your tool function; here the provider is the in-memory fake so we can count
# refunds. ``issue_refund`` looks the provider up by name at call time, so each
# act can install a fresh one.
# ---------------------------------------------------------------------------
payment_api = FakePaymentAPI()


@airlock.guard(
    "payment.refund",
    cost=Money(amount="50.00", currency="USD"),
    reversibility=Reversibility.IRREVERSIBLE,
    effect=Effect(key_param="idempotency_key"),  # Airlock's key flows to the API
)
def issue_refund(
    charge_id: str, amount_cents: int, *, idempotency_key: str | None = None
) -> dict[str, str | int]:
    """Refund a charge through the payment provider (the guarded tool)."""
    refund = payment_api.refund(charge_id, amount_cents, idempotency_key=idempotency_key)
    # Return a JSON-safe dict: Airlock records it on the commit ledger, and a
    # deduped retry gets THIS exact result back without re-running the tool.
    return {"refund_id": refund.id, "charge_id": refund.charge_id, "amount_cents": refund.amount_cents}


def act1_without_airlock() -> FakePaymentAPI:
    """ACT 1: a naive agent refunds, then retries — and double-charges."""
    api = FakePaymentAPI()

    def naive_refund_tool() -> None:
        # No idempotency key, no ledger — every call moves money again.
        api.refund(CHARGE_ID, AMOUNT_CENTS)

    naive_refund_tool()  # the agent issues the refund
    naive_refund_tool()  # a retry / duplicated tool call / crash-resume fires it AGAIN
    return api


class Act2Result(NamedTuple):
    """What ACT 2 produced — enough for the test to assert the story is true."""

    first: dict[str, str | int]
    second: dict[str, str | int]
    api: FakePaymentAPI
    handle: airlock.Airlock
    dev_note: str


def act2_with_airlock() -> Act2Result:
    """ACT 2: the SAME retry, wrapped in @guard — deduped by the commit ledger."""
    global payment_api
    payment_api = FakePaymentAPI()  # fresh provider (issue_refund looks it up by name)

    # Zero-config: no `store=` => a local SQLite dev store at ./airlock.db, with a
    # one-time note that production should use Postgres. An AUTO policy so this
    # refund commits inline (in a real app you'd GATE high-value refunds).
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        handle = airlock.init(
            policy=Policy(rules=[Rule(match="payment.refund", decision=Decision.AUTO)]),
        )
    dev_note = str(caught[0].message) if caught else ""

    first = issue_refund(CHARGE_ID, AMOUNT_CENTS)  # commits exactly once
    second = issue_refund(CHARGE_ID, AMOUNT_CENTS)  # the SAME retry — deduped
    return Act2Result(first=first, second=second, api=payment_api, handle=handle, dev_note=dev_note)


def cleanup(handle: airlock.Airlock | None = None) -> None:
    """Close the dev store and delete ./airlock.db so re-runs start clean."""
    if handle is not None and isinstance(handle.store, SqliteStore):
        handle.store.close()
    for name in _DB_FILES:
        path = Path(name)
        if path.exists():
            path.unlink()


def main() -> None:
    print("=" * 70)
    print("Airlock — the double-refund demo")
    print("The same refund, retried once. Watch what each version does.")
    print("=" * 70)

    print("\nACT 1 — WITHOUT Airlock")
    print("-" * 70)
    print("A naive agent issues a refund, then a retry fires the SAME refund again.")
    api1 = act1_without_airlock()
    count1 = api1.refund_count(CHARGE_ID)
    print(f"  refunds actually issued for {CHARGE_ID}: {count1}")
    print(
        f"  ❌ Customer refunded {'TWICE' if count1 == 2 else f'{count1}x'} "
        f"({_dollars(AMOUNT_CENTS)} charged back {count1} times, "
        f"{_dollars(AMOUNT_CENTS * count1)} total)"
    )

    print("\nACT 2 — WITH Airlock")
    print("-" * 70)
    result = act2_with_airlock()
    if result.dev_note:
        print(f"  note: {result.dev_note}\n")
    print("The same tool wrapped in @guard. The agent issues the refund, then retries.")
    count2 = result.api.refund_count(CHARGE_ID)
    print(f"  refunds actually issued for {CHARGE_ID}: {count2}")
    print(f"  times the payment API was even called:  {result.api.total_calls}")
    print("  ✅ Refunded exactly once (the retry was deduped by the commit ledger)")

    print("\nWhat happened")
    print("-" * 70)
    print("  - @guard derived one deterministic idempotency key from the call args.")
    print("  - The first call CLAIMED that key in the commit ledger and ran the refund,")
    print(f"    passing the key downstream to the API (refund {result.first['refund_id']}).")
    print("  - The retry hit the SAME ledger key, so Airlock returned the first result")
    print("    without touching the payment API again:")
    print(f"       first  -> {result.first}")
    print(f"       retry  -> {result.second}   (identical: {result.first == result.second})")
    print("  - Two layers of dedup (ledger + downstream key) => the side effect fires once.")
    print("\nSee README.md for the 3-line quickstart and the ADR-1/ADR-2 references.")

    cleanup(result.handle)


if __name__ == "__main__":
    main()
