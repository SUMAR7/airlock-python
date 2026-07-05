"""The Hypothesis property machine — the core of P1.4 (PLAN.md 7, invariants I1-I5).

A single-threaded :class:`hypothesis.stateful.RuleBasedStateMachine`
(:class:`CommitMachine`) drives the REAL ledger + reconciler
(``PostgresStore`` + ``commit_once`` + ``reconcile``) through randomized
interleavings of propose / duplicate_call / crash_at(boundary) / advance_clock /
reconcile / restart, mixing all three guarantee modes, and asserts the P1.4
invariant subset after EVERY step by diffing the real system against a simple
in-Python reference model.

**Crash model (PLAN.md 7).** This layer crashes by abruptly DROPPING the DB
connection so Postgres rolls back the open transaction — the identical
DB-visible outcome to process death, and far faster than a subprocess. The
``os._exit``-in-subprocess suite (``test_reconcile_crash.py``,
``test_crash_sigkill_equivalence.py``) owns the orthogonal "did Python cleanup
lie" dimension; this layer owns breadth of interleavings. Each named boundary is
driven by running the ``commit_once`` steps by hand up to the boundary and then
either stopping (the relevant transaction already committed) or dropping the
connection mid-transaction (proving no partial write leaks).

**The reference model** (:class:`_Model`) tracks, per key: the expected terminal
or in-flight ``LedgerState``, the ``Guarantee``, the ground-truth downstream
``effect_count``, the committed ``result``, and — once terminal — a frozen
snapshot used to assert monotonicity (I5). The downstream world
(:class:`_Downstream`) models the three guarantee mechanisms so ``effect_count``
is real ground truth, not a guess:

- ``downstream_idempotent`` dedupes on the downstream key (FakeStripe-style):
  re-issue with the same key lands the effect at most once.
- ``verifiable`` lands a real effect and a probe can later confirm presence.
- ``none`` has neither: every execute lands a raw effect, and a crashed row is
  finalized ``unknown`` and NEVER retried.

**Invariants asserted after every step (PLAN.md 7, the P1.4 subset I1-I5):**

- **I1** — for every key, ``effect_count <= 1`` (the product; the prime directive).
- **I2** — ``state == committed`` implies ``effect_count == 1``.
- **I3** — ``guarantee == none`` never appears in a reconciler RETRY; a crash
  after the executing-mark on a ``none`` row lands ``unknown``, never re-executed.
- **I4** — SCOPED FOR P1.4: the full chained-hash audit is P2.2, so I4 here
  asserts the weaker available property — the evidence/error trail and ledger
  terminal states are internally consistent (no committed row without a result;
  no unknown/failed row claiming success). The real chained-hash I4 lands in P2.2.
- **I5** — terminal ledger states (committed/aborted/failed/unknown) are
  monotone: once terminal, a row never changes state or effect_count (the
  reference model snapshots terminal rows and diffs them every step).

**I6 (paused_runs DAG) and I7 (action_event validation) are OUT OF SCOPE for
P1.4** — they need P2.3 ``paused_runs`` and P2.2 events, which do not exist yet.
They are intentionally NOT stubbed; see the TODO at the bottom of this module.
"""

from __future__ import annotations

import os
import warnings
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule
from pydantic import JsonValue
from sqlalchemy import create_engine, text

from airlock.commit import commit_once
from airlock.effects import Effect
from airlock.errors import (
    AtMostOnceWarning,
    CommitWaitTimeout,
    ExecuteTimeout,
    VerificationUnknown,
)
from airlock.reconcile import OnAbsent, reconcile
from airlock.registry import Registry
from airlock.store.postgres import PostgresStore, normalize_postgres_url
from airlock.types import (
    TERMINAL_LEDGER_STATES,
    Guarantee,
    LedgerState,
    Verification,
)

#: The whole module is the property machine — marker lets CI run it as its own
#: derandomized leg (``pytest -m property``), separate from concurrency/crash/race.
pytestmark = pytest.mark.property

# ---------------------------------------------------------------------------
# Strategies (PLAN.md 7): payloads via fixed_dictionaries so duplicate payloads
# collide BY CONSTRUCTION; guarantee & crash boundary via sampled_from.
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/airlock_test")
OLDER_THAN = timedelta(seconds=60)
# Advancing by more than OLDER_THAN makes an in-flight row cross the staleness
# cutoff deterministically (never time.sleep).
BIG_ADVANCE = 120.0

# A SMALL payload space so duplicate keys collide by construction (airlock-canon-1:
# amount is a decimal STRING, never a float; account is sampled from a tiny set).
_ACCOUNTS = ("acct_a", "acct_b")
_AMOUNTS = ("10.00", "12.50", "0")

_action_payload = st.fixed_dictionaries(
    {
        "account": st.sampled_from(_ACCOUNTS),
        "amount": st.sampled_from(_AMOUNTS),
    }
)
_guarantee = st.sampled_from(
    [Guarantee.DOWNSTREAM_IDEMPOTENT, Guarantee.VERIFIABLE, Guarantee.NONE]
)

# The named crash boundaries this layer drives (PLAN.md 7). after_finalize_write
# is omitted here (it lands terminal with the finalize committed — the os._exit
# suite covers it; here every crash is a mid/pre-finalize interruption, which is
# the interesting recovery surface).
_CRASH_BOUNDARIES = st.sampled_from(
    [
        "after_claim",
        "after_executing_mark",
        "after_effect",
        "after_verify",
        "before_finalize_write",
    ]
)


def _key_for(action_type: str, payload: dict[str, str]) -> str:
    """A stable ledger key for (action_type, payload) — collide by construction.

    Not the real ``derive_key`` (that is exercised in ``test_idempotency.py``);
    here a readable deterministic key keeps counterexamples legible while still
    colliding whenever the payload collides.
    """
    return f"{action_type}:{payload['account']}:{payload['amount']}"


# ---------------------------------------------------------------------------
# The downstream world — ground truth for effect_count across all three modes.
# ---------------------------------------------------------------------------


class _Downstream:
    """Models the downstream side effect for all three guarantee modes.

    ``effect_count(key)`` is the REAL number of side effects that landed for a
    ledger key — the quantity I1 bounds at 1. For downstream_idempotent, dedup
    on the downstream key collapses re-issues; for verifiable, a probe reads
    back presence; for none, every execute lands a raw effect.
    """

    def __init__(self) -> None:
        # ledger key -> number of real effects that landed
        self._effects: dict[str, int] = {}
        # downstream key -> stored response (downstream_idempotent dedup table)
        self._di_responses: dict[str, dict[str, Any]] = {}

    # --- downstream_idempotent -------------------------------------------------
    def di_apply(self, ledger_key: str, downstream_key: str) -> dict[str, Any]:
        if downstream_key in self._di_responses:
            return self._di_responses[downstream_key]  # deduped: NO new effect
        self._effects[ledger_key] = self._effects.get(ledger_key, 0) + 1
        resp = {"refund_id": f"re_di_{downstream_key}"}
        self._di_responses[downstream_key] = resp
        return resp

    # --- verifiable ------------------------------------------------------------
    def verifiable_apply(self, ledger_key: str) -> dict[str, Any]:
        self._effects[ledger_key] = self._effects.get(ledger_key, 0) + 1
        return {"refund_id": f"re_v_{ledger_key}"}

    def verifiable_probe(self, ledger_key: str) -> tuple[Verification, dict[str, Any]]:
        present = self._effects.get(ledger_key, 0) >= 1
        return (
            (Verification.PRESENT if present else Verification.ABSENT),
            {"present": present},
        )

    # --- none ------------------------------------------------------------------
    def none_apply(self, ledger_key: str) -> dict[str, Any]:
        self._effects[ledger_key] = self._effects.get(ledger_key, 0) + 1
        return {"refund_id": f"re_n_{ledger_key}"}

    def effect_count(self, ledger_key: str) -> int:
        return self._effects.get(ledger_key, 0)


# ---------------------------------------------------------------------------
# The reference model — what the ledger SHOULD look like, per key.
# ---------------------------------------------------------------------------


class _KeyModel:
    """The modelled expectation for one ledger key."""

    def __init__(self, action_type: str, guarantee: Guarantee, payload: dict[str, str]) -> None:
        self.action_type = action_type
        self.guarantee = guarantee
        self.payload = payload
        # Whether this key is known to have reached a terminal state. Tracked in
        # PURE PYTHON (never read back from the DB) so the machine's control flow
        # is deterministic given the step sequence — a Hypothesis stateful
        # machine MUST NOT branch on external (DB) state, or replay/shrink draws a
        # different rule structure (FlakyStrategyDefinition). DB reads happen only
        # in invariants, which do not draw.
        self.model_terminal = False
        # Terminal snapshot for I5 monotonicity: (state, effect_count) once frozen.
        self.terminal_state: LedgerState | None = None
        self.terminal_effect_count: int | None = None

    def freeze_terminal(self, state: LedgerState, effect_count: int) -> None:
        if self.terminal_state is None:
            self.terminal_state = state
            self.terminal_effect_count = effect_count
        self.model_terminal = True


# ---------------------------------------------------------------------------
# The machine.
# ---------------------------------------------------------------------------


class CommitMachine(RuleBasedStateMachine):
    """Drive the real ledger + reconciler through randomized interleavings.

    Each example gets a fresh machine whose ``__init__`` TRUNCATEs the ledger, so
    runs never leak state into each other (Hypothesis reuses the process across
    examples). The machine drives ONE shared ``airlock_test`` database, so it must
    never run concurrently with another DB-backed test job against the same DSN —
    two truncating machines would wipe each other's rows. (CI runs test jobs
    serially; this only bites if you hand-run parallel jobs against one DB.)
    """

    def __init__(self) -> None:
        super().__init__()
        self._fake_now = datetime(2026, 7, 5, 12, 0, 0, tzinfo=UTC)
        self.store = PostgresStore(DATABASE_URL, now_fn=self._now)
        self.downstream = _Downstream()
        self.model: dict[str, _KeyModel] = {}
        # A raw autocommit engine for setup/inspection (never the store's pool).
        self._raw = create_engine(
            normalize_postgres_url(DATABASE_URL), isolation_level="AUTOCOMMIT"
        )
        # A SEPARATE non-autocommit engine used ONLY to model the connection-drop
        # crash: raw_connection() on it begins a real transaction, so issuing the
        # finalize UPDATE and then abruptly closing WITHOUT commit rolls it back
        # (Postgres discards it) — the identical DB-visible outcome to process
        # death mid-finalize. The autocommit _raw engine would COMMIT the UPDATE
        # instead (autocommit is on for its connections), which would silently
        # turn the crash into a real finalize — the exact trap this split avoids.
        self._crash_engine = create_engine(normalize_postgres_url(DATABASE_URL))
        with self._raw.connect() as conn:
            conn.execute(text("TRUNCATE commit_records RESTART IDENTITY"))
        self.action_type = "prop.refund"

    def _now(self) -> datetime:
        return self._fake_now

    def teardown(self) -> None:
        self.store.close()
        self._raw.dispose()
        self._crash_engine.dispose()

    # --- effect / probe / execute wiring ---------------------------------------

    def _effect_for(self, guarantee: Guarantee) -> Effect:
        if guarantee is Guarantee.DOWNSTREAM_IDEMPOTENT:
            return Effect(key_param="idempotency_key")
        if guarantee is Guarantee.VERIFIABLE:
            return Effect(verify=self._make_probe())
        return Effect()  # none

    def _make_probe(self) -> Callable[..., tuple[Verification, dict[str, Any]]]:
        downstream = self.downstream

        def verify(*, account: str, amount: str, **_: Any) -> tuple[Verification, dict[str, Any]]:
            key = f"{self.action_type}:{account}:{amount}"
            return downstream.verifiable_probe(key)

        return verify

    def _make_execute(self, guarantee: Guarantee, key: str) -> Callable[..., JsonValue]:
        downstream = self.downstream

        def execute(downstream_key: str | None, **_: Any) -> JsonValue:
            if guarantee is Guarantee.DOWNSTREAM_IDEMPOTENT:
                assert downstream_key is not None
                return downstream.di_apply(key, downstream_key)
            if guarantee is Guarantee.VERIFIABLE:
                return downstream.verifiable_apply(key)
            return downstream.none_apply(key)

        return execute

    # --- rules -----------------------------------------------------------------

    @rule(payload=_action_payload, guarantee=_guarantee)
    def propose(self, payload: dict[str, str], guarantee: Guarantee) -> None:
        """Propose+commit an action to completion (no crash) via commit_once.

        Duplicate payloads collide by construction, so this doubles as scenario
        1 (sequential duplicate) whenever the same (payload, guarantee) recurs.
        A guarantee mismatch on an existing key is skipped (the ledger would
        raise the cross-action guard; the model keeps one guarantee per key).
        """
        key = _key_for(self.action_type, payload)
        km = self.model.get(key)
        if km is not None and km.guarantee is not guarantee:
            return  # same key must keep one guarantee; skip the mismatch
        if km is None:
            km = _KeyModel(self.action_type, guarantee, payload)
            self.model[key] = km

        self._commit_once_call(key, km)

    @rule()
    @precondition(lambda self: bool(self.model))
    def duplicate_call(self) -> None:
        """Retry an existing key (scenario 1/2 on the sequential path)."""
        key = self._some_key()
        km = self.model[key]
        self._commit_once_call(key, km)

    def _commit_once_call(self, key: str, km: _KeyModel) -> None:
        effect = self._effect_for(km.guarantee)
        inner = self._make_execute(km.guarantee, key)

        def execute(downstream_key: str | None) -> JsonValue:
            return inner(downstream_key)

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", AtMostOnceWarning)
                commit_once(
                    self.store,
                    key=key,
                    action_type=self.action_type,
                    execute=execute,
                    effect=effect,
                    args_json=dict(km.payload),
                    reconcile_after=OLDER_THAN,
                    now_fn=self._now,
                    wait=False,
                )
        except (CommitWaitTimeout, VerificationUnknown, ExecuteTimeout):
            # Losing to an in-flight row, or an honest non-answer: the ledger
            # holds the claim; recovery handles it. These are legal outcomes,
            # never a re-execute.
            pass

    @rule(boundary=_CRASH_BOUNDARIES, payload=_action_payload, guarantee=_guarantee)
    def crash_at(self, boundary: str, payload: dict[str, str], guarantee: Guarantee) -> None:
        """Drive the commit flow to ``boundary`` and crash (drop the connection).

        Runs the ``commit_once`` steps by hand up to the boundary. For a boundary
        whose relevant transaction already committed (after_claim /
        after_executing_mark / after_effect), the "crash" is simply stopping
        there (the durable state is already written). For before_finalize_write
        we open a finalize transaction and DROP the raw connection before COMMIT,
        proving Postgres rolls it back with no partial write. after_verify is a
        no-op transition on the ledger (verify does not write), so it lands like
        after_effect.
        """
        key = _key_for(self.action_type, payload)
        km = self.model.get(key)
        if km is not None and km.guarantee is not guarantee:
            return
        # A crash only makes sense on a fresh or in-flight row; a terminal row
        # cannot be re-claimed (ON CONFLICT returns the terminal row). Decide this
        # from the MODEL (pure Python), never a DB read: a stateful machine that
        # branches on external DB state draws a different rule structure on
        # replay/shrink (FlakyStrategyDefinition). The model tracks terminality
        # deterministically from the step sequence.
        if km is not None and km.model_terminal:
            return
        if km is None:
            km = _KeyModel(self.action_type, guarantee, payload)
            self.model[key] = km

        # The downstream key commit_once would derive + persist for this effect
        # (None for verifiable/none; the ledger key for downstream_idempotent) —
        # stored on the row so the reconciler's re-issue uses the SAME key
        # (stored == sent, PLAN.md 3.4), exactly as commit_once does.
        downstream_key = self._effect_for(guarantee).downstream_key_for(key)

        # Step 1 — claim (its own committed txn). A loser (row already in flight)
        # just returns; there is nothing new to crash.
        claim = self.store.claim(key, self.action_type, guarantee, dict(km.payload), downstream_key)
        if not claim.won:
            return
        epoch = claim.record.attempts
        if boundary == "after_claim":
            return  # durably 'pending', effect-free

        # Step 3 — mark executing (its own committed txn, before any effect).
        if not self.store.mark_executing(key, epoch):
            return  # fenced; nothing to crash
        if boundary == "after_executing_mark":
            return  # durably 'executing', no effect yet

        # Step 4 — the side effect (lands in the downstream world / ground truth).
        execute = self._make_execute(guarantee, key)
        execute(downstream_key)
        if boundary in ("after_effect", "after_verify"):
            # verify does not write to the ledger, so after_verify is
            # DB-indistinguishable from after_effect: row 'executing', effect in.
            return

        # boundary == before_finalize_write: open a finalize txn on a RAW
        # connection and drop it before COMMIT — Postgres rolls it back, so the
        # row stays 'executing' with no partial finalize (the connection-drop
        # crash PLAN.md 7 asks this layer to exercise).
        self._drop_connection_mid_finalize(key, epoch)
        # HARNESS SELF-CHECK: the crash must have ROLLED BACK, leaving the row
        # 'executing' — not silently committed the "leaked" finalize (the
        # autocommit trap). If this ever fails, the crash mechanism regressed and
        # this boundary would stop testing recovery at all.
        crashed = self.store.load(key)
        assert crashed is not None and crashed.state is LedgerState.EXECUTING, (
            "before_finalize_write crash did not roll back: the connection-drop "
            "must leave the row 'executing', never commit the partial finalize"
        )

    def _drop_connection_mid_finalize(self, key: str, epoch: int) -> None:
        """Issue the finalize UPDATE on a raw conn, then abruptly close before
        COMMIT — proving the open transaction rolls back with no partial write.

        Uses the NON-autocommit ``_crash_engine``: its raw connection begins a
        real transaction, so closing without commit rolls the UPDATE back. (The
        autocommit ``_raw`` engine would commit it — see ``__init__``.) After
        this the row is durably still 'executing' with no partial finalize.
        """
        raw = self._crash_engine.raw_connection()
        try:
            cur = raw.cursor()
            # Same shape as PostgresStore.finalize's committed UPDATE, but we
            # never commit: dropping the connection rolls it back.
            cur.execute(
                "UPDATE commit_records SET state = 'committed', "
                "result_json = '{\"leaked\": true}'::jsonb, committed_at = now() "
                "WHERE idempotency_key = %s AND attempts = %s AND state = 'executing'",
                (key, epoch),
            )
            # Deliberately DO NOT commit. Abruptly close -> rollback (crash).
        finally:
            raw.close()

    @rule()
    def advance_clock(self) -> None:
        """Advance the FakeClock past the reconcile timeout (never time.sleep)."""
        self._fake_now = self._fake_now + timedelta(seconds=BIG_ADVANCE)

    @rule(on_absent=st.sampled_from([OnAbsent.RETRY, OnAbsent.ABORT]))
    def do_reconcile(self, on_absent: OnAbsent) -> None:
        """Run one reconcile pass over all stale in-flight rows.

        Uses one registry (:meth:`_registry_for_all`) whose execute/probe read
        the real downstream world by the row's rehydrated (account, amount), so
        any stale row can be recovered guarantee-correctly. Uses the same
        FakeClock, so only rows advanced past OLDER_THAN are eligible.
        """
        reconcile(
            self.store,
            older_than=OLDER_THAN,
            on_absent=on_absent,
            execute_timeout=None,  # controlled in-process; window vouched for
            now_fn=self._now,
            registry=self._registry_for_all(),
        )

    def _registry_for_all(self) -> Registry:
        """One registry whose execute/probe dispatch on the row's own payload.

        Every key shares ``action_type`` but differs in guarantee/payload. The
        reconciler picks the recovery-table BRANCH from the ROW's stored
        ``commit_records.guarantee`` (not the registration), so this single
        registration only needs to supply a working execute + probe that read the
        real downstream world by the rehydrated (account, amount). The Effect
        carries both ``key_param`` (so downstream_idempotent rows re-issue with
        the stored key) and ``verify`` (so verifiable rows probe); execute lands
        the effect per the ROW's own guarantee, looked up from the model — so
        effect_count stays exact regardless of which registration is used.
        """
        downstream = self.downstream
        model = self.model
        action_type = self.action_type

        def probe(*, account: str, amount: str, **_: Any) -> tuple[Verification, dict[str, Any]]:
            key = f"{action_type}:{account}:{amount}"
            return downstream.verifiable_probe(key)

        def execute(
            downstream_key: str | None, *, account: str, amount: str, **_: Any
        ) -> JsonValue:
            key = f"{action_type}:{account}:{amount}"
            km = model.get(key)
            guarantee = km.guarantee if km is not None else Guarantee.VERIFIABLE
            if guarantee is Guarantee.DOWNSTREAM_IDEMPOTENT:
                assert downstream_key is not None
                return downstream.di_apply(key, downstream_key)
            if guarantee is Guarantee.NONE:
                return downstream.none_apply(key)
            return downstream.verifiable_apply(key)

        reg = Registry()
        reg.register(action_type, Effect(key_param="idempotency_key", verify=probe), execute)
        return reg

    @rule()
    def restart(self) -> None:
        """Discard in-memory owner state, keep the DB (a process restart).

        Rebuilds the store on a fresh connection pool; the ledger is untouched.
        Models scenario 6's spirit at the commit layer: recovery must depend
        only on durable ledger state, never on in-process memory.
        """
        self.store.close()
        self.store = PostgresStore(DATABASE_URL, now_fn=self._now)

    # --- helpers ---------------------------------------------------------------

    def _some_key(self) -> str:
        # Deterministic pick (first modelled key) — Hypothesis controls sequencing
        # via rule ordering; we do not need extra randomness here.
        return next(iter(self.model))

    def _real_rows(self) -> dict[str, Any]:
        with self._raw.connect() as conn:
            rows = (
                conn.execute(
                    text(
                        "SELECT idempotency_key, state, guarantee, result_json, error_json,"
                        " committed_at, attempts FROM commit_records"
                    )
                )
                .mappings()
                .all()
            )
        return {row["idempotency_key"]: row for row in rows}

    # --- invariants (I1-I5), asserted after EVERY step -------------------------

    @invariant()
    def i1_effect_count_at_most_one(self) -> None:
        """I1: for every key, the real downstream effect_count is <= 1."""
        for key in self.model:
            count = self.downstream.effect_count(key)
            assert count <= 1, f"I1 VIOLATED: key {key!r} has effect_count={count} (> 1)"

    @invariant()
    def i2_committed_implies_one_effect(self) -> None:
        """I2: a committed row has exactly one real effect."""
        rows = self._real_rows()
        for key, row in rows.items():
            if row["state"] == LedgerState.COMMITTED.value:
                count = self.downstream.effect_count(key)
                assert count == 1, (
                    f"I2 VIOLATED: key {key!r} is committed but effect_count={count} (!= 1)"
                )

    @invariant()
    def i3_none_never_retried(self) -> None:
        """I3: a guarantee=none row never lands committed via retry.

        A crash after the executing-mark on a none row must resolve to unknown
        (never re-executed), so a none row is NEVER 'committed' unless the
        ORIGINAL execute completed and finalized in one uncrashed commit_once —
        in which case effect_count is still exactly 1 (I2 covers that). What I3
        forbids specifically: a none row reaching 'committed' with MORE than one
        effect, or a reconciler producing a retried-committed none row. We assert
        the strong form: a none row is never committed with effect_count != 1, and
        a crashed none row (left executing) reconciles to unknown, not committed.
        """
        rows = self._real_rows()
        for key, row in rows.items():
            if row["guarantee"] != Guarantee.NONE.value:
                continue
            state = row["state"]
            count = self.downstream.effect_count(key)
            if state == LedgerState.COMMITTED.value:
                # Only reachable via a single clean commit_once — one effect.
                assert count == 1, (
                    f"I3 VIOLATED: none key {key!r} committed with effect_count={count}"
                )
            # A none row is NEVER re-executed by recovery: unknown is terminal
            # and never retried. If it is unknown, effect_count is 0 or 1, never >1
            # (I1 already guarantees <=1); nothing more to assert here.

    @invariant()
    def i4_evidence_and_terminal_states_consistent(self) -> None:
        """I4 (P1.4 SCOPE): evidence/terminal-state internal consistency.

        The full chained-hash audit is P2.2 (TODO below). Here we assert the
        weaker available property: no committed row without a result, and no
        unknown/failed row that claims success (result present while error/absent
        semantics say the effect did not land). Concretely:

        - committed  => result_json is not NULL AND committed_at is not NULL.
        - aborted    => committed_at is NULL and result_json is NULL (we chose not
          to execute; nothing was produced).
        - failed     => committed_at is NULL (executed, confirmed absent — no
          success timestamp).
        - unknown    => committed_at is NULL (cannot claim success).
        """
        rows = self._real_rows()
        for key, row in rows.items():
            state = row["state"]
            if state == LedgerState.COMMITTED.value:
                assert row["committed_at"] is not None, f"I4: committed {key!r} has no committed_at"
                assert row["result_json"] is not None, f"I4: committed {key!r} has no result"
            elif state == LedgerState.ABORTED.value:
                assert row["committed_at"] is None, f"I4: aborted {key!r} claims committed_at"
                assert row["result_json"] is None, f"I4: aborted {key!r} has a result"
            elif state in (LedgerState.FAILED.value, LedgerState.UNKNOWN.value):
                assert row["committed_at"] is None, (
                    f"I4: {state} {key!r} claims committed_at (a success timestamp)"
                )

    @invariant()
    def i5_terminal_states_are_monotone(self) -> None:
        """I5: once terminal, a row never changes state or effect_count.

        The model snapshots (state, effect_count) the first time it observes a
        row terminal; every subsequent step must find the SAME state and the SAME
        effect_count for that key. A terminal row that flipped state, or whose
        effect_count moved, is a monotonicity break — the exact class of bug a
        double-commit or a resurrected row would show.
        """
        rows = self._real_rows()
        for key, row in rows.items():
            state = LedgerState(row["state"])
            km = self.model.get(key)
            if km is None:
                continue
            count = self.downstream.effect_count(key)
            if state in TERMINAL_LEDGER_STATES:
                if km.terminal_state is None:
                    km.freeze_terminal(state, count)
                else:
                    assert km.terminal_state == state, (
                        f"I5 VIOLATED: terminal key {key!r} changed state "
                        f"{km.terminal_state.value!r} -> {state.value!r}"
                    )
                    assert km.terminal_effect_count == count, (
                        f"I5 VIOLATED: terminal key {key!r} effect_count changed "
                        f"{km.terminal_effect_count} -> {count}"
                    )


# The Hypothesis test the machine compiles to. Settings (max_examples, deadline,
# derandomize, the suppressed DB-backed health checks) come from the active
# profile — "ci" is derandomized with a fixed budget and no deadline (see
# tests/conftest.py). No per-test override: the profile is the single knob.
TestCommitMachine = CommitMachine.TestCase


# ---------------------------------------------------------------------------
# I6 / I7 — OUT OF SCOPE for P1.4 (do NOT stub).
#
# TODO(P2.3): I6 — paused_runs.status follows the ADR-4 DAG only
#   (proposed -> approved|rejected -> committed|aborted). Needs the paused_runs
#   table and apply_decision, which land in P2.3. Add a `propose_gate` /
#   `approve` / `reject` / `duplicate_webhook` rule set and an I6 invariant then.
#
# TODO(P2.2): I7 — every terminal call produced exactly one schema-valid
#   action_event. Needs the action_event.v1 model + JSON Schema + the audit
#   events table, which land in P2.2. Add an I7 invariant that reads back the
#   emitted events and validates them against the pinned schema then.
#
# Leaving these as named TODOs (not empty rules/invariants) so the machine never
# gives false confidence about properties it does not yet exercise.
# ---------------------------------------------------------------------------
