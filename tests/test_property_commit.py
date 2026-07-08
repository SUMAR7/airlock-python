"""The Hypothesis property machine — the core of P1.4 (PLAN.md 7, invariants I1-I5).

A single-threaded :class:`hypothesis.stateful.RuleBasedStateMachine`
(:class:`CommitMachine`) drives the REAL ledger + reconciler
(``PostgresStore`` + ``commit_once`` + ``reconcile``) through randomized
interleavings of propose / duplicate_call / crash_at(boundary) / advance_clock /
reconcile / restart / slow_owner_fenced_reconcile, mixing all three guarantee
modes, and asserts the P1.4 invariant subset after EVERY step by diffing the
real system against a simple in-Python reference model.

**Determinism discipline (PLAN.md 7, the FlakyStrategyDefinition trap).** A
Hypothesis stateful machine MUST NOT let any draw, ``@precondition``, or
control-flow decision depend on external (DB) state — replay/shrink re-runs the
rule sequence and a DB-dependent branch would draw a DIFFERENT rule structure,
which Hypothesis rejects as flaky. So EVERY branch below is decided from the
in-Python reference model (``self.model``) alone; the DB is read EXCLUSIVELY
inside ``@invariant`` methods (which never draw) and inside the fenced-owner
self-checks of the concurrency rule (which assert, never branch a draw).

**Ground truth is the ``effects_log`` autocommit table, not memory (PLAN.md 7).**
The quantity I1 bounds — ``effect_count`` — is read back from the shared
``effects_log`` table on a FRESH autocommit connection, exactly like the
concurrency suite, so the count is an independent record of real ``execute()``
side effects rather than a mirror of the code under test. The in-Python
:class:`_Downstream` stays as the dedup/probe MECHANISM (FakeStripe-style
downstream_idempotent dedup, the verifiable probe), but every raw effect it
lands ALSO writes one ``effects_log`` row, and the invariants count THOSE.

**Isolation (PLAN.md 10 — the machine must never collide with another test).**
Each machine instance mints a UNIQUE action_type prefix (``prop.<uuid>.``) and
every ledger key / action_type it uses carries that prefix, so its rows are
globally distinct from every other DB-backed test's rows AND from every other
Hypothesis example's rows. Cleanup is a SCOPED ``DELETE ... WHERE action_type
LIKE 'prop.%'`` (never ``TRUNCATE``), and ``_real_rows`` reads ONLY this
machine's prefix — so the machine can neither truncate nor observe another
test's rows, and the full ``pytest`` run is collision-free without serializing
jobs.

**Crash model (PLAN.md 7).** This layer crashes by abruptly DROPPING a
non-pooled DB connection so Postgres rolls back the open transaction — the
identical DB-visible outcome to process death, and far faster than a subprocess.
The ``os._exit``-in-subprocess suite (``test_reconcile_crash.py``,
``test_crash_sigkill_equivalence.py``) owns the orthogonal "did Python cleanup
lie" dimension; this layer owns breadth of interleavings. The connection-drop
uses a FRESH ``NullPool`` connection that is explicitly rolled back and hard
closed, so the "leaked finalize" can never be committed by a pool's
reset-on-return (the trap the old pooled ``_crash_engine`` left open).

**The reference model** (:class:`_KeyModel`) tracks, per key: the expected
terminal-ness (pure Python), the ``Guarantee``, and — once terminal — a frozen
snapshot used to assert monotonicity (I5).

**Invariants asserted after every step (PLAN.md 7, the P1.4 subset I1-I5):**

- **I1** — for every key, ``effect_count <= 1`` (the product; the prime
  directive), counted from ``effects_log``.
- **I2** — ``state == committed`` implies ``effect_count == 1``.
- **I3** — the real scenario-7 property: a ``guarantee=none`` row that crashed
  while ``executing`` and was then reconciled lands terminal ``unknown`` (never
  ``committed``, never retried), and the reconcile did not increase its
  ``effect_count``. A ``none`` row is never re-executed by recovery.
- **I4** — THE REAL INVARIANT (upgraded in P2.2 from the P1.4 weakened form):
  after every step the FULL hash-chained audit trail verifies end-to-end
  (``verify_chain``: genesis constant, gapless seq, prev_hash linkage,
  recomputed row hashes, head match). The chain is example-scoped — each
  machine truncates the audit tables and re-seeds genesis (a harness reset,
  same as the db fixture's per-test TRUNCATE; the chain is global by
  construction so scoped DELETEs are impossible by design) — which keeps the
  full-chain verify O(example) and deterministic. Every ``commit_once`` in
  the machine carries an event context, so terminal transitions append
  chained action_events inside their finalize transactions and the reconcile
  rules append reconcile events: I4 exercises the finalize+append atomicity
  under the whole interleaving space. The P1.4 evidence-consistency check is
  retained as I4b.
- **I5** — terminal ledger states (committed/aborted/failed/unknown) are
  monotone: once terminal, a row never changes state or effect_count.

**I6 (paused_runs DAG) and I7 (action_event validation) landed in P2.3.** The
``propose_gate`` / ``approve`` / ``reject`` / ``duplicate_webhook`` rules drive
the durable pause through ``apply_decision``; **I6** asserts every observed
``paused_runs.status`` transition is a legal ADR-4 edge (and the DB agrees with
the model), and **I7** schema-validates every emitted ``action_event`` against
``/contracts/events/action_event.v1.json`` and pins EXACTLY ONE per terminal
gate resolution (a double-delivered approval must not emit a second).
"""

from __future__ import annotations

import json
import os
import uuid
import warnings
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule
from jsonschema import Draft202012Validator
from pydantic import JsonValue
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from airlock.audit import verify_chain
from airlock.commit import commit_once
from airlock.effects import Effect
from airlock.errors import (
    AtMostOnceWarning,
    AuditChainError,
    CommitWaitTimeout,
    ExecuteTimeout,
    VerificationUnknown,
)
from airlock.events import ActionEvent, ActionEventContext
from airlock.pause import apply_decision, build_serialized_state
from airlock.reconcile import OnAbsent, reconcile
from airlock.registry import Registry
from airlock.store._schema import ensure_schema, seed_genesis
from airlock.store.postgres import PostgresStore, normalize_postgres_url
from airlock.types import (
    PAUSE_TRANSITIONS,
    TERMINAL_LEDGER_STATES,
    ApprovalDecision,
    Decision,
    Guarantee,
    HumanDecision,
    LedgerState,
    PauseStatus,
    Reversibility,
    Verification,
)

# The action_event.v1 JSON Schema — I7 validates every emitted event against it.
_SCHEMA_PATH = Path(__file__).parent.parent / "contracts" / "events" / "action_event.v1.json"
_ACTION_EVENT_VALIDATOR = Draft202012Validator(json.loads(_SCHEMA_PATH.read_text()))

# The five legal ADR-4 status edges, as string pairs.
_LEGAL_PAUSE_EDGES: frozenset[tuple[str, str]] = frozenset(
    (a.value, b.value) for a, b in PAUSE_TRANSITIONS
)


def _pause_reachable_closure() -> dict[str, set[str]]:
    """DAG reachability over the ADR-4 edges (each status reaches itself + heirs).

    I6 observes paused_runs.status only BETWEEN rules, but one ``apply_decision``
    call legally walks several edges at once (proposed → approved → committed),
    so an intermediate status may never be snapshotted. The invariant therefore
    checks REACHABILITY (status ∈ reachable(prev)), which still forbids every
    illegal move — an approved→rejected flip, a re-opened terminal row, a
    resurrected run — while allowing a legal multi-edge drive.
    """
    nodes = {s.value for s in PauseStatus}
    reach: dict[str, set[str]] = {n: {n} for n in nodes}
    changed = True
    while changed:
        changed = False
        for a, b in _LEGAL_PAUSE_EDGES:
            if not reach[a] >= reach[b]:
                reach[a] |= reach[b]
                changed = True
    return reach


_PAUSE_REACHABLE: dict[str, set[str]] = _pause_reachable_closure()

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

#: Every machine's rows share this SQL LIKE prefix; the scoped DELETE / read use
#: it so the machine touches only ``prop.*`` rows, never another test's.
_PROP_PREFIX = "prop."

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


# ---------------------------------------------------------------------------
# The downstream world — the dedup/probe MECHANISM. Ground truth for
# effect_count is the effects_log table (see _EffectsLog), NOT this object.
# ---------------------------------------------------------------------------


class _EffectsLog:
    """Ground-truth side-effect counter on a dedicated autocommit connection.

    Independent of any ledger transaction (PLAN.md 7): a raw effect is counted
    the instant it is logged. Reads happen on a FRESH connection so an effect
    landed by any transaction is visible immediately. Keys carry the machine's
    unique prefix, so counts are naturally scoped per example without truncating
    the shared table.
    """

    def __init__(self, dsn: str) -> None:
        self._engine = create_engine(normalize_postgres_url(dsn), isolation_level="AUTOCOMMIT")

    def log(self, key: str) -> None:
        with self._engine.connect() as conn:
            conn.execute(
                text("INSERT INTO effects_log (idempotency_key, worker_pid) VALUES (:key, :pid)"),
                {"key": key, "pid": os.getpid()},
            )

    def count(self, key: str) -> int:
        with self._engine.connect() as conn:
            found = conn.execute(
                text("SELECT count(*) FROM effects_log WHERE idempotency_key = :key"),
                {"key": key},
            ).scalar_one()
        return int(found)

    def dispose(self) -> None:
        self._engine.dispose()


class _Downstream:
    """Models the downstream dedup/probe mechanism for all three guarantee modes.

    Every RAW effect it lands is also logged to the ``effects_log`` table
    (:class:`_EffectsLog`), which is the ground truth the invariants count.
    ``downstream_idempotent`` dedupes on the downstream key so a re-issue with
    the same key logs NO new effect; ``verifiable`` reads presence back from the
    effects_log count; ``none`` logs a raw effect on every execute.
    """

    def __init__(self, effects: _EffectsLog) -> None:
        self._effects = effects
        # downstream key -> stored response (downstream_idempotent dedup table)
        self._di_responses: dict[str, dict[str, Any]] = {}

    # --- downstream_idempotent -------------------------------------------------
    def di_apply(self, ledger_key: str, downstream_key: str) -> dict[str, Any]:
        if downstream_key in self._di_responses:
            return self._di_responses[downstream_key]  # deduped: NO new effect
        self._effects.log(ledger_key)
        resp = {"refund_id": f"re_di_{downstream_key}"}
        self._di_responses[downstream_key] = resp
        return resp

    # --- verifiable ------------------------------------------------------------
    def verifiable_apply(self, ledger_key: str) -> dict[str, Any]:
        self._effects.log(ledger_key)
        return {"refund_id": f"re_v_{ledger_key}"}

    def verifiable_probe(self, ledger_key: str) -> tuple[Verification, dict[str, Any]]:
        present = self._effects.count(ledger_key) >= 1
        return (
            (Verification.PRESENT if present else Verification.ABSENT),
            {"present": present},
        )

    # --- none ------------------------------------------------------------------
    def none_apply(self, ledger_key: str) -> dict[str, Any]:
        self._effects.log(ledger_key)
        return {"refund_id": f"re_n_{ledger_key}"}


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
        # is deterministic given the step sequence (see the module docstring on
        # FlakyStrategyDefinition). DB reads happen only in invariants.
        self.model_terminal = False
        # I3 (scenario 7): a `none` row that crashed while executing and was then
        # reconciled MUST land terminal `unknown`, never committed/retried, and
        # the reconcile must not add an effect. Set when such a crash is staged.
        self.none_crashed_executing = False
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

    Each example gets a fresh machine whose ``__init__`` mints a UNIQUE
    action_type prefix and scrubs any stale ``prop.*`` rows with a SCOPED
    ``DELETE`` (never ``TRUNCATE``), so runs never leak state into each other and
    the machine never touches another DB-backed test's rows (PLAN.md 10). Ground
    truth for ``effect_count`` is the ``effects_log`` autocommit table.
    """

    def __init__(self) -> None:
        super().__init__()
        self._fake_now = datetime(2026, 7, 5, 12, 0, 0, tzinfo=UTC)
        # A unique prefix per machine instance -> globally distinct rows/keys.
        self.prefix = f"{_PROP_PREFIX}{uuid.uuid4().hex}."
        self.action_type = f"{self.prefix}refund"
        #: The gated action type (P2.3): its runs live in paused_runs and resolve
        #: through apply_decision, distinct from the AUTO ledger action above.
        self.gate_action = f"{self.prefix}gate.refund"
        #: ref -> {run_id, key, status, decision} — the modelled pause state.
        self.gate_model: dict[str, dict[str, Any]] = {}
        #: ref -> last DB status observed (I6 watches the actual transitions).
        self._gate_last_status: dict[str, str] = {}
        self.store = PostgresStore(DATABASE_URL, now_fn=self._now)
        # A raw autocommit engine for schema/scoped-cleanup/inspection (never the
        # store's pool).
        self._raw = create_engine(
            normalize_postgres_url(DATABASE_URL), isolation_level="AUTOCOMMIT"
        )
        ensure_schema(self._raw)
        self._ensure_effects_log()
        self.effects = _EffectsLog(DATABASE_URL)
        self.downstream = _Downstream(self.effects)
        self.model: dict[str, _KeyModel] = {}
        # SCOPED cleanup: only this suite's rows, and only ones that could linger
        # from an earlier prop.* example. With a fresh uuid prefix there is
        # nothing to delete, but the scoped DELETE is the structural guarantee
        # that the machine can never wipe another test's rows (PLAN.md 10 fix).
        with self._raw.connect() as conn:
            conn.execute(
                text("DELETE FROM commit_records WHERE action_type LIKE :like"),
                {"like": f"{_PROP_PREFIX}%"},
            )
            # Paused runs (P2.3) are scoped and cleaned the same way.
            conn.execute(
                text("DELETE FROM paused_runs WHERE action_type LIKE :like"),
                {"like": f"{_PROP_PREFIX}%"},
            )
        # Audit-chain reset (I4, P2.2). The chain is GLOBAL by construction —
        # one gapless hash chain per database — so per-example isolation cannot
        # be a scoped DELETE (deleting audit rows is exactly what the chain
        # exists to detect, and it would corrupt the chain for every later
        # verify). Instead each example starts a FRESH chain: truncate + re-seed
        # genesis, the same harness-level reset the db fixture performs per
        # test. This is safe for the same reason the fixture's TRUNCATE is:
        # the suite runs examples sequentially against the test database. With
        # the chain example-scoped, the I4 invariant can verify the FULL chain
        # after every step at O(example) cost.
        with self._raw.connect() as conn:
            conn.execute(text("TRUNCATE audit_events, audit_chain_head RESTART IDENTITY"))
        seed_genesis(self._raw)

    def _ensure_effects_log(self) -> None:
        """Create the ground-truth ``effects_log`` table if missing.

        The conftest session fixture creates it too, but the property leg runs as
        a plain ``unittest`` TestCase that does not pull that fixture graph, so
        the machine ensures it itself — the machine is self-contained under
        ``pytest -m property`` on a fresh database.
        """
        with self._raw.connect() as conn:
            conn.execute(
                text(
                    "CREATE TABLE IF NOT EXISTS effects_log ("
                    " id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
                    " idempotency_key TEXT NOT NULL,"
                    " worker_pid INT NOT NULL,"
                    " logged_at TIMESTAMPTZ NOT NULL DEFAULT now())"
                )
            )

    def _now(self) -> datetime:
        return self._fake_now

    def teardown(self) -> None:
        self.store.close()
        self.effects.dispose()
        # Scoped cleanup on the way out too, so a killed run leaves no prop.* rows
        # and this machine's effects_log rows do not accumulate in the shared
        # table across a session. Both scopes are keyed to this suite / this
        # machine, never another test's rows (PLAN.md 10).
        with self._raw.connect() as conn:
            conn.execute(
                text("DELETE FROM commit_records WHERE action_type LIKE :like"),
                {"like": f"{_PROP_PREFIX}%"},
            )
            conn.execute(
                text("DELETE FROM paused_runs WHERE action_type LIKE :like"),
                {"like": f"{_PROP_PREFIX}%"},
            )
            conn.execute(
                text("DELETE FROM effects_log WHERE idempotency_key LIKE :like"),
                {"like": f"{self.prefix}%"},
            )
        self._raw.dispose()

    def _key_for(self, payload: dict[str, str]) -> str:
        """A stable, machine-scoped ledger key for a payload — collide by
        construction whenever the payload recurs, distinct across machines."""
        return f"{self.action_type}:{payload['account']}:{payload['amount']}"

    # --- effect / probe / execute wiring ---------------------------------------

    def _effect_for(self, guarantee: Guarantee) -> Effect:
        if guarantee is Guarantee.DOWNSTREAM_IDEMPOTENT:
            return Effect(key_param="idempotency_key")
        if guarantee is Guarantee.VERIFIABLE:
            return Effect(verify=self._make_probe())
        return Effect()  # none

    def _make_probe(self) -> Callable[..., tuple[Verification, dict[str, Any]]]:
        downstream = self.downstream
        action_type = self.action_type

        def verify(*, account: str, amount: str, **_: Any) -> tuple[Verification, dict[str, Any]]:
            key = f"{action_type}:{account}:{amount}"
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
        A guarantee mismatch on an existing key is skipped (the ledger keeps one
        guarantee per key). Decided from the MODEL only.
        """
        key = self._key_for(payload)
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

    @rule(payload=_action_payload, guarantee=_guarantee)
    def claim_dedup(self, payload: dict[str, str], guarantee: Guarantee) -> None:
        """ADR-1 claim dedup: a SECOND claim of the same key must NOT win.

        The exactly-once guard is ``INSERT ... ON CONFLICT (idempotency_key) DO
        NOTHING`` — the claim itself is the concurrency gate that makes scenario
        2 safe (SPEC.md 5 rows 1-2). This rule pins that primitive directly: on a
        fresh key, the first claim wins; a second and third claim of the SAME key
        must report ``won == False`` and return the SAME existing row. A claim
        that mistakenly reports ``won`` for a duplicate (an ``ON CONFLICT DO
        NOTHING`` regressed to ``DO UPDATE``, or dropped entirely) hands two
        independent callers the row and green-lights two side effects — the
        double-commit the prime directive forbids. Terminality/first-claim status
        is decided from the MODEL only (pure Python), never a DB read.
        """
        key = self._key_for(payload)
        km = self.model.get(key)
        if km is not None and km.guarantee is not guarantee:
            return
        already_claimed = km is not None
        if km is None:
            km = _KeyModel(self.action_type, guarantee, payload)
            self.model[key] = km

        downstream_key = self._effect_for(guarantee).downstream_key_for(key)
        claim = self.store.claim(key, self.action_type, guarantee, dict(km.payload), downstream_key)

        if already_claimed:
            # The model knows this key was claimed before — the claim MUST lose.
            assert not claim.won, (
                f"CLAIM DEDUP BROKEN: re-claim of existing key {key!r} reported won=True "
                "(ON CONFLICT DO NOTHING regressed — two callers would both execute)"
            )
        else:
            # First claim of a fresh key wins; an IMMEDIATE second claim must lose.
            assert claim.won, f"CLAIM DEDUP BROKEN: first claim of fresh key {key!r} lost"
            second = self.store.claim(
                key, self.action_type, guarantee, dict(km.payload), downstream_key
            )
            assert not second.won, (
                f"CLAIM DEDUP BROKEN: second claim of just-claimed key {key!r} reported "
                "won=True (ON CONFLICT DO NOTHING regressed — double-commit hole)"
            )

    def _commit_once_call(self, key: str, km: _KeyModel) -> None:
        effect = self._effect_for(km.guarantee)
        inner = self._make_execute(km.guarantee, key)

        def execute(downstream_key: str | None) -> JsonValue:
            return inner(downstream_key)

        # An event context on every commit_once call (P2.2): terminal
        # transitions append a chained action_event INSIDE their finalize
        # transaction, so I4 exercises the finalize+append seam under the
        # machine's full interleaving space, not just reconcile events. The
        # minted run_id/event_id do not influence any draw or branch
        # (determinism discipline holds).
        event_ctx = ActionEventContext(
            run_id=f"run_{uuid.uuid4().hex}",
            policy_decision=Decision.AUTO,
            reversibility=Reversibility.IRREVERSIBLE,
        )
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
                    event_context=event_ctx,
                )
        except (CommitWaitTimeout, VerificationUnknown, ExecuteTimeout):
            # Losing to an in-flight row, or an honest non-answer: the ledger
            # holds the claim; recovery handles it. Legal, never a re-execute.
            pass

    @rule(boundary=_CRASH_BOUNDARIES, payload=_action_payload, guarantee=_guarantee)
    def crash_at(self, boundary: str, payload: dict[str, str], guarantee: Guarantee) -> None:
        """Drive the commit flow to ``boundary`` and crash (drop the connection).

        Runs the ``commit_once`` steps by hand up to the boundary. For a boundary
        whose relevant transaction already committed (after_claim /
        after_executing_mark / after_effect), the "crash" is simply stopping
        there. For before_finalize_write we open a finalize transaction on a
        FRESH non-pooled connection and drop it before COMMIT, proving Postgres
        rolls it back with no partial write. after_verify is a no-op transition
        on the ledger (verify does not write), so it lands like after_effect.
        Every branch here is decided from the MODEL (pure Python).
        """
        key = self._key_for(payload)
        km = self.model.get(key)
        if km is not None and km.guarantee is not guarantee:
            return
        # A crash only makes sense on a fresh or in-flight row; a terminal row
        # cannot be re-claimed. Decide from the MODEL (pure Python), never a DB
        # read (FlakyStrategyDefinition — see the module docstring).
        if km is not None and km.model_terminal:
            return
        if km is None:
            km = _KeyModel(self.action_type, guarantee, payload)
            self.model[key] = km

        downstream_key = self._effect_for(guarantee).downstream_key_for(key)

        # Step 1 — claim (its own committed txn). A loser just returns.
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
            # A none row now sits 'executing' with no effect; if the model later
            # reconciles it, it must land 'unknown' (I3). Record the intent.
            if guarantee is Guarantee.NONE:
                km.none_crashed_executing = True
            return

        # Step 4 — the side effect (lands in effects_log / ground truth).
        execute = self._make_execute(guarantee, key)
        execute(downstream_key)
        if guarantee is Guarantee.NONE:
            km.none_crashed_executing = True
        if boundary in ("after_effect", "after_verify"):
            # verify does not write to the ledger, so after_verify is
            # DB-indistinguishable from after_effect: row 'executing', effect in.
            return

        # boundary == before_finalize_write: open a finalize txn on a FRESH
        # non-pooled connection and drop it before COMMIT — Postgres rolls it
        # back, so the row stays 'executing' with no partial finalize.
        self._drop_connection_mid_finalize(key, epoch)
        # HARNESS SELF-CHECK: the crash must have ROLLED BACK, leaving the row
        # 'executing' — not silently committed the "leaked" finalize.
        crashed = self.store.load(key)
        assert crashed is not None and crashed.state is LedgerState.EXECUTING, (
            "before_finalize_write crash did not roll back: the connection-drop "
            "must leave the row 'executing', never commit the partial finalize"
        )

    def _drop_connection_mid_finalize(self, key: str, epoch: int) -> None:
        """Issue the finalize UPDATE on a FRESH non-pooled connection, roll it
        back, and hard-close — proving the open transaction rolls back with no
        partial write, and no pool reset-on-return can ever COMMIT the leak.

        A ``NullPool`` engine hands out a brand-new DBAPI connection and disposes
        it on close (no pool to return to), so there is no reset-on-return path
        that could commit the pending UPDATE. We explicitly ``rollback()`` before
        ``close()`` too, so the abort is issued by us, deterministically — the
        row is durably still 'executing' with no partial finalize.
        """
        engine = create_engine(normalize_postgres_url(DATABASE_URL), poolclass=NullPool)
        try:
            raw = engine.raw_connection()
            try:
                cur = raw.cursor()
                # Same shape as PostgresStore.finalize's committed UPDATE, but we
                # never commit: we roll back and hard-close (the crash).
                cur.execute(
                    "UPDATE commit_records SET state = 'committed', "
                    "result_json = '{\"leaked\": true}'::jsonb, committed_at = now() "
                    "WHERE idempotency_key = %s AND attempts = %s AND state = 'executing'",
                    (key, epoch),
                )
                # Deliberately DO NOT commit. Roll back explicitly, then close.
                raw.rollback()
            finally:
                raw.close()
        finally:
            engine.dispose()

    @rule()
    def advance_clock(self) -> None:
        """Advance the FakeClock past the reconcile timeout (never time.sleep)."""
        self._fake_now = self._fake_now + timedelta(seconds=BIG_ADVANCE)

    @rule(on_absent=st.sampled_from([OnAbsent.RETRY, OnAbsent.ABORT]))
    def do_reconcile(self, on_absent: OnAbsent) -> None:
        """Run one reconcile pass over all stale in-flight rows.

        Uses one registry whose execute/probe read the real downstream world by
        the row's rehydrated (account, amount). Uses the same FakeClock, so only
        rows advanced past OLDER_THAN are eligible. A modelled none row that
        crashed while executing (``none_crashed_executing``) is finalized
        ``unknown`` here — asserted by I3, which reads the DB state directly.
        """
        reconcile(
            self.store,
            older_than=OLDER_THAN,
            on_absent=on_absent,
            execute_timeout=None,  # controlled in-process; window vouched for
            now_fn=self._now,
            registry=self._registry_for_all(),
        )

    @rule(payload=_action_payload)
    def slow_owner_fenced_reconcile(self, payload: dict[str, str]) -> None:
        """The slow-owner-vs-reconciler epoch-fence interleaving (PLAN.md 7 / I5).

        This is the interleaving the epoch fence exists to defend and that the
        randomized machine otherwise never generates — a fenced owner at epoch N
        racing a reconciler that took the row over at epoch N+1 but LEFT IT
        ``executing`` (an escalation). It brings ``test_reconcile_race``'s overlap
        into the machine so an epoch-fence regression is caught:

        1. Leave a ``verifiable`` owner ``executing`` at epoch N (claim +
           mark_executing; no finalize) — a slow owner mid-execute.
        2. advance_clock past staleness and run a reconcile whose probe answers
           ``unknown`` — the reconciler bumps to N+1 (fencing the owner) and
           ESCALATES, leaving the row ``executing`` at N+1. This is the crucial
           shape: the row's STATE still matches ``finalize``'s state guard, so the
           ONLY thing standing between the owner and a wrong ``committed`` is the
           ``AND attempts = :epoch`` epoch guard.
        3. Attempt the ORIGINAL owner's epoch-N ``finalize`` / ``mark_executing``
           / ``record_error`` and ASSERT each is fenced (returns False).

        Why this catches the mutation battery where a probe-present recovery does
        not: after a normal recovery the row is already ``committed`` and
        ``finalize``'s state guard alone fences the owner, hiding a dropped epoch
        guard. Here the row is left ``executing`` at the bumped epoch, so:

        - epoch guard dropped on ``finalize``  -> owner (epoch N) commits over the
          reconciler's N+1 row: assertion fires (fence broken).
        - ``bump_epoch`` does not increment    -> the row stays at epoch N, so the
          owner's epoch-N ``finalize`` matches (state executing + epoch N): fence
          broken.
        - epoch guard dropped on ``mark_executing`` -> owner re-marks the N+1 row:
          assertion fires.

        The owner never lands an effect (it blocks before executing, like a slow
        owner abandoned pre-effect), so effect_count is 0 throughout — this rule
        proves the FENCE, not effect dedup. Terminality is decided from the MODEL.
        """
        guarantee = Guarantee.VERIFIABLE
        key = self._key_for(payload)
        km = self.model.get(key)
        if km is not None and km.guarantee is not guarantee:
            return  # keep one guarantee per key; skip if the model has another
        if km is not None and km.model_terminal:
            return
        if km is None:
            km = _KeyModel(self.action_type, guarantee, payload)
            self.model[key] = km

        # Stage an owner stranded 'executing' at epoch N (no effect, no finalize).
        claim = self.store.claim(key, self.action_type, guarantee, dict(km.payload), None)
        if not claim.won:
            return
        owner_epoch = claim.record.attempts
        if not self.store.mark_executing(key, owner_epoch):
            return

        # Advance past staleness and run a reconciler whose probe answers UNKNOWN,
        # so it bumps the epoch (fencing the owner) but ESCALATES — the row stays
        # 'executing' at the bumped epoch. This is what makes the epoch guard the
        # sole fence (the state guard still matches).
        self._fake_now = self._fake_now + timedelta(seconds=BIG_ADVANCE)
        reconcile(
            self.store,
            older_than=OLDER_THAN,
            on_absent=OnAbsent.ABORT,
            execute_timeout=None,
            now_fn=self._now,
            registry=self._unknown_probe_registry(),
        )

        # THE FENCE, asserted directly: the original owner at epoch N can no
        # longer finalize, re-mark, or record. Each guarded write must match 0
        # rows (return False). A dropped epoch guard (or a bump_epoch that does
        # not increment) turns one of these True — a broken fence.
        assert not self.store.finalize(
            key, owner_epoch, LedgerState.COMMITTED, {"owner": "late"}, None
        ), f"FENCE BROKEN: owner epoch {owner_epoch} finalized {key!r} after takeover"
        assert not self.store.mark_executing(key, owner_epoch), (
            f"FENCE BROKEN: owner epoch {owner_epoch} re-marked {key!r} after takeover"
        )
        assert not self.store.record_error(key, owner_epoch, {"owner": "late"}), (
            f"FENCE BROKEN: owner epoch {owner_epoch} recorded on {key!r} after takeover"
        )
        count = self.effects.count(key)
        assert count <= 1, f"FENCE effect leak: key {key!r} has effect_count={count} (> 1)"

    def _unknown_probe_registry(self) -> Registry:
        """A registry whose probe always answers UNKNOWN -> the reconciler
        escalates and LEAVES the row executing at the bumped epoch (never
        finalizes it), which is what the fence rule needs."""
        action_type = self.action_type

        def probe(**_: Any) -> tuple[Verification, dict[str, Any]]:
            return Verification.UNKNOWN, {"why": "fence-rule: forced escalation"}

        def execute(downstream_key: str | None, **_: Any) -> JsonValue:  # never called
            raise AssertionError("fence rule reconcile must not re-execute (probe is unknown)")

        reg = Registry()
        reg.register(action_type, Effect(verify=probe), execute)
        return reg

    def _registry_for_all(self) -> Registry:
        """One registry whose execute/probe dispatch on the row's own payload."""
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
        """Discard in-memory owner state, keep the DB (a process restart)."""
        self.store.close()
        self.store = PostgresStore(DATABASE_URL, now_fn=self._now)

    # --- the durable-pause rules (P2.3): gate / approve / reject / dup webhook --

    def _gate_registry(self) -> Registry:
        """A registry for the gated action, execute logs the ground-truth effect."""
        effects = self.effects

        def execute(downstream_key: str | None, *, invoice: str, **_: Any) -> JsonValue:
            effects.log(invoice)  # invoice == the gate's ledger key
            return {"refund_id": f"re_{invoice}"}

        reg = Registry()
        reg.register(self.gate_action, Effect(key_param="idempotency_key"), execute)
        return reg

    @rule()
    def propose_gate(self) -> None:
        """Persist a fresh proposed pause (a gated action awaiting a human).

        Keys are minted from the MODEL's size (deterministic, collision-free), so
        no draw depends on DB state. serialized_state carries the canonical
        arg_map the approve rule rehydrates the call from (scenario 6 shape).
        """
        n = len(self.gate_model)
        key = f"{self.prefix}gate:{n}"
        ref = str(uuid.uuid4())
        run_id = f"grun_{uuid.uuid4().hex}"
        state = build_serialized_state(
            {"invoice": key},
            reversibility=Reversibility.IRREVERSIBLE,
            cost=None,
            blast_radius=None,
            precondition_snapshot=None,
        )
        self.store.save_paused(
            run_id=run_id,
            idempotency_key=key,
            approval_ref=ref,
            action_type=self.gate_action,
            serialized_state=state,
        )
        self.gate_model[ref] = {
            "run_id": run_id,
            "key": key,
            "status": "proposed",
            "decision": None,
        }

    @rule()
    @precondition(lambda self: any(g["status"] == "proposed" for g in self.gate_model.values()))
    def approve(self) -> None:
        """Approve the first proposed gate → apply_decision drives it committed."""
        ref = self._first_gate("proposed")
        apply_decision(
            self.store,
            ref,
            ApprovalDecision(decision=HumanDecision.APPROVED, decided_by="usr_prop"),
            registry=self._gate_registry(),
            now_fn=self._now,
        )
        self.gate_model[ref]["status"] = "committed"
        self.gate_model[ref]["decision"] = "approved"

    @rule()
    @precondition(lambda self: any(g["status"] == "proposed" for g in self.gate_model.values()))
    def reject(self) -> None:
        """Reject the first proposed gate → apply_decision drives it aborted."""
        ref = self._first_gate("proposed")
        apply_decision(
            self.store,
            ref,
            ApprovalDecision(decision=HumanDecision.REJECTED, decided_by="usr_prop"),
            registry=self._gate_registry(),
            now_fn=self._now,
        )
        self.gate_model[ref]["status"] = "aborted"
        self.gate_model[ref]["decision"] = "rejected"

    @rule()
    @precondition(
        lambda self: any(g["status"] in ("committed", "aborted") for g in self.gate_model.values())
    )
    def duplicate_webhook(self) -> None:
        """Re-deliver the SAME decision to a resolved gate — must be a no-op.

        The double-delivered approval (SPEC scenario 5) at the pause layer: the
        commit ledger + the terminal pause status make it idempotent — no second
        effect, no second action_event (I7 asserts exactly one).
        """
        ref = next(r for r, g in self.gate_model.items() if g["status"] in ("committed", "aborted"))
        gm = self.gate_model[ref]
        decision = (
            HumanDecision.APPROVED if gm["decision"] == "approved" else HumanDecision.REJECTED
        )
        apply_decision(
            self.store,
            ref,
            ApprovalDecision(decision=decision, decided_by="usr_prop"),
            registry=self._gate_registry(),
            now_fn=self._now,
        )
        # The model is UNCHANGED — a duplicate delivery resolves nothing new.

    def _first_gate(self, status: str) -> str:
        return next(r for r, g in self.gate_model.items() if g["status"] == status)

    def _gate_rows(self) -> dict[str, str]:
        with self._raw.connect() as conn:
            rows = (
                conn.execute(
                    text(
                        "SELECT approval_ref::text AS ref, status FROM paused_runs"
                        " WHERE action_type = :a"
                    ),
                    {"a": self.gate_action},
                )
                .mappings()
                .all()
            )
        return {row["ref"]: row["status"] for row in rows}

    # --- helpers ---------------------------------------------------------------

    def _some_key(self) -> str:
        # Deterministic pick (first modelled key) — Hypothesis controls sequencing
        # via rule ordering; we do not need extra randomness here.
        return next(iter(self.model))

    def _real_rows(self) -> dict[str, Any]:
        """Read THIS machine's rows only (scoped to its prefix) from a fresh conn.

        The ``action_type LIKE :like`` scope means the invariants can never see
        another test's rows — the machine is structurally isolated (PLAN.md 10).
        """
        with self._raw.connect() as conn:
            rows = (
                conn.execute(
                    text(
                        "SELECT idempotency_key, state, guarantee, result_json, error_json,"
                        " committed_at, attempts FROM commit_records"
                        " WHERE action_type LIKE :like"
                    ),
                    {"like": f"{self.prefix}%"},
                )
                .mappings()
                .all()
            )
        return {row["idempotency_key"]: row for row in rows}

    # --- invariants (I1-I5), asserted after EVERY step -------------------------

    @invariant()
    def i1_effect_count_at_most_one(self) -> None:
        """I1: for every key, the real effects_log effect_count is <= 1."""
        for key in self.model:
            count = self.effects.count(key)
            assert count <= 1, f"I1 VIOLATED: key {key!r} has effect_count={count} (> 1)"

    @invariant()
    def i2_committed_implies_one_effect(self) -> None:
        """I2: a committed row has exactly one real effect (from effects_log)."""
        rows = self._real_rows()
        for key, row in rows.items():
            if row["state"] == LedgerState.COMMITTED.value:
                count = self.effects.count(key)
                assert count == 1, (
                    f"I2 VIOLATED: key {key!r} is committed but effect_count={count} (!= 1)"
                )

    @invariant()
    def i3_none_crashed_executing_lands_unknown(self) -> None:
        """I3 (scenario 7): a none row crashed while executing, once terminal,
        lands 'unknown' — never committed, never retried — and its effect_count
        never exceeds 1.

        This is the real scenario-7 property (PLAN.md 4.2 / SPEC scenario 7), not
        the old tautology: a guarantee=none row that was crashed mid-execute and
        then reconciled MUST be finalized ``unknown`` (the reconciler NEVER
        re-executes a none row), so it is never ``committed`` and the reconcile
        pass adds no effect. We assert on the rows the model flagged as
        none-crashed-executing.
        """
        rows = self._real_rows()
        for key, km in self.model.items():
            if km.guarantee is not Guarantee.NONE or not km.none_crashed_executing:
                continue
            row = rows.get(key)
            if row is None:
                continue
            state = row["state"]
            # A none row that crashed executing is NEVER committed by recovery.
            assert state != LedgerState.COMMITTED.value, (
                f"I3 VIOLATED: none key {key!r} crashed executing then reached "
                "'committed' — the reconciler re-executed a none row (scenario 7 breach)"
            )
            count = self.effects.count(key)
            assert count <= 1, (
                f"I3 VIOLATED: none key {key!r} has effect_count={count} (> 1) — "
                "a none row was retried by recovery"
            )
            # Once terminal, the only truthful state for a crashed-executing none
            # row is 'unknown' (never failed/aborted, which would claim proof it
            # cannot have).
            if state in {s.value for s in TERMINAL_LEDGER_STATES}:
                assert state == LedgerState.UNKNOWN.value, (
                    f"I3 VIOLATED: none key {key!r} crashed executing but terminal "
                    f"state is {state!r}, expected 'unknown' (scenario 7)"
                )

    @invariant()
    def i4_audit_chain_verifies_end_to_end(self) -> None:
        """I4 (THE REAL INVARIANT, PLAN.md 7): after every step, the FULL
        audit chain verifies end-to-end.

        The chain is example-scoped (fresh genesis per machine, see __init__),
        so a full verify_chain pass here recomputes every row hash, checks
        every prev_hash link, the gapless seq order, the genesis constant and
        the head match — after EVERY rule the machine executes. Any finalize
        that wrote a terminal state without its chained event landing
        atomically, any crash that half-applied a finalize+append, any
        rollback that leaked an audit row, breaks this immediately.

        The P1.4 evidence-consistency assertions are kept below (they cover a
        different, ledger-internal property).
        """
        try:
            verify_chain(self.store)
        except AuditChainError as exc:
            raise AssertionError(
                f"I4 VIOLATED: audit chain broken at seq {exc.seq}: {exc}"
            ) from exc

    @invariant()
    def i4b_evidence_and_terminal_states_consistent(self) -> None:
        """I4 supplement (the P1.4 property, retained): no committed row
        without a result, and no non-committed row that claims success."""
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
        row terminal; every subsequent step must find the SAME state and SAME
        effect_count. A terminal row that flipped state, or whose effect_count
        moved, is a monotonicity break — the class of bug a double-commit, a
        resurrected row, or a BROKEN EPOCH FENCE (a fenced owner finalizing over
        the reconciler's terminal row) would show.
        """
        rows = self._real_rows()
        for key, row in rows.items():
            state = LedgerState(row["state"])
            km = self.model.get(key)
            if km is None:
                continue
            count = self.effects.count(key)
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

    @invariant()
    def i6_paused_status_follows_the_adr4_dag(self) -> None:
        """I6 (P2.3): every paused_runs.status transition observed in the DB is a
        legal ADR-4 edge, and the DB agrees with the model.

        This reads the ACTUAL DB status of each gated run after every step and,
        whenever it changes from the previously-observed one, asserts the edge is
        one of the five ADR-4 transitions (proposed → approved|rejected →
        committed|aborted). A store that landed any other status — a resurrected
        run, an approved→rejected flip, a terminal row re-opened — reddens here.
        It also pins the DB against the model's expected status, so a divergence
        (the store advancing a run the model never drove) is caught too.
        """
        rows = self._gate_rows()
        valid = {s.value for s in PauseStatus}
        for ref, status in rows.items():
            assert status in valid, f"I6 VIOLATED: unknown pause status {status!r}"
            prev = self._gate_last_status.get(ref)
            if prev is not None and prev != status:
                # Reachability, not a single edge: one apply_decision call legally
                # walks proposed→approved→committed between two snapshots.
                assert status in _PAUSE_REACHABLE[prev], (
                    f"I6 VIOLATED: unreachable pause transition {prev!r} -> {status!r} for {ref}"
                )
            self._gate_last_status[ref] = status
            gm = self.gate_model.get(ref)
            if gm is not None:
                assert status == gm["status"], (
                    f"I6 VIOLATED: DB status {status!r} != model {gm['status']!r} for {ref}"
                )

    @invariant()
    def i7_every_terminal_call_emits_exactly_one_schema_valid_event(self) -> None:
        """I7 (P2.3, REAL): every action_event this machine produced validates
        against /contracts/events/action_event.v1.json, and every terminally-
        decided gate produced EXACTLY ONE action_event matching its decision.

        (a) Global validity: each ``action_event`` row (AUTO commits and gate
        resolutions alike) parses as :class:`ActionEvent` AND validates against
        the frozen JSON Schema — a malformed or forked event reddens here.

        (b) Exactly-one per gate: a committed/aborted gated run has one and only
        one action_event keyed by its run_id, with policy_decision=gate, the
        human_decision the model recorded, and the matching outcome; the effect
        count matches (1 committed, 0 aborted). A double delivery
        (duplicate_webhook) that emitted a second event, or a resolution that
        emitted none, reddens here.
        """
        with self._raw.connect() as conn:
            payloads = (
                conn.execute(
                    text(
                        "SELECT payload_json FROM audit_events"
                        " WHERE event_type = 'action_event' AND action_type LIKE :like"
                    ),
                    {"like": f"{self.prefix}%"},
                )
                .scalars()
                .all()
            )
        for payload in payloads:
            _ACTION_EVENT_VALIDATOR.validate(payload)  # schema
            ActionEvent.model_validate(payload)  # and the pydantic model

        for ref, gm in self.gate_model.items():
            if gm["status"] not in ("committed", "aborted"):
                continue
            with self._raw.connect() as conn:
                events = (
                    conn.execute(
                        text(
                            "SELECT payload_json FROM audit_events"
                            " WHERE event_type = 'action_event' AND run_id = :r"
                        ),
                        {"r": gm["run_id"]},
                    )
                    .scalars()
                    .all()
                )
            assert len(events) == 1, (
                f"I7 VIOLATED: gate {ref} ({gm['status']}) has {len(events)} action_events "
                "(expected exactly one per terminal gate resolution)"
            )
            event = events[0]
            assert event["policy_decision"] == "gate"
            expected_human = "approved" if gm["decision"] == "approved" else "rejected"
            assert event["human_decision"] == expected_human, (
                f"I7 VIOLATED: gate {ref} action_event human_decision "
                f"{event['human_decision']!r} != {expected_human!r}"
            )
            expected_outcome = "committed" if gm["status"] == "committed" else "aborted"
            assert event["outcome"] == expected_outcome
            count = self.effects.count(gm["key"])
            assert count == (1 if gm["status"] == "committed" else 0), (
                f"I7 VIOLATED: gate {ref} ({gm['status']}) has effect_count={count}"
            )


# The Hypothesis test the machine compiles to. Settings (max_examples, deadline,
# derandomize, the suppressed DB-backed health checks) come from the active
# profile — "ci" is derandomized with a fixed budget and no deadline (see
# tests/conftest.py). No per-test override: the profile is the single knob.
TestCommitMachine = CommitMachine.TestCase


# ---------------------------------------------------------------------------
# I6 / I7 — LANDED (P2.3). The gate/approve/reject/duplicate_webhook rules drive
# the durable pause through apply_decision; I6 watches every paused_runs.status
# transition against the ADR-4 DAG, and I7 schema-validates every action_event
# and pins exactly one per terminal gate resolution (a double-delivered approval
# via duplicate_webhook must not emit a second). See the invariant methods above.
# ---------------------------------------------------------------------------
