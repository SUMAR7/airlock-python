"""The mechanical no-``time.sleep`` guard (PLAN.md 7 / P1.4 deliverable 3).

SPEC 9 / PLAN 7 are categorical: "a conftest guard fails any test calling
``time.sleep``". Sleeping to synchronize is how a concurrency test becomes
flaky — it trades a real barrier for a wall-clock guess, and a slow CI box
turns the guess into an intermittent failure that hides a live race. This guard
makes that mistake impossible to commit: an autouse fixture replaces
``time.sleep`` with a function that RAISES, so any test whose call stack reaches
``time.sleep`` fails loudly and immediately. All synchronization must instead be
barriers, events, fake clocks, or DB-state polling against a hard deadline.

**The one sanctioned exception, narrowly scoped.** ``commit_once``'s loser wait
(:func:`airlock.commit._await_terminal`) polls the ledger for the winner's
terminal outcome, sleeping ``poll_interval`` between reads, bounded by a hard
``wait_timeout``. That IS "DB-state polling with a hard deadline" — the pattern
PLAN 7 explicitly permits — and it is PRODUCTION code, not test synchronization.
So the guard allows ``time.sleep`` only when the immediate caller is that exact
function in ``airlock/commit.py``; every other caller (a test body, a fixture,
any other library code) is refused. The allowlist is keyed on the calling
frame's module file AND function name, so it cannot be widened by accident.

Because the allowlist is a single production poll loop that is itself covered by
a hard deadline and by the loser/timeout tests, the guarantee PLAN 7 wants —
"this proves nothing currently sleeps" — holds: running the whole suite under
this guard green is a proof that no test synchronizes by sleeping.
"""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Iterator

import pytest

__all__ = ["no_time_sleep"]

#: (module file suffix, function name) pairs allowed to call ``time.sleep``.
#: Exactly ONE entry: ``commit_once``'s bounded ledger poll (DB-state polling
#: with a hard deadline — the sanctioned pattern). Keep this list empty-by-
#: default in spirit; every addition must be a production poll bounded by a
#: deadline, never a test.
_ALLOWED_SLEEP_CALLERS: frozenset[tuple[str, str]] = frozenset(
    {
        ("airlock/commit.py", "_await_terminal"),
    }
)


class SleepInTestError(AssertionError):
    """Raised when a test's call stack reaches ``time.sleep`` (PLAN.md 7).

    An ``AssertionError`` so it reads as a test failure, not an error, and so a
    blanket ``except Exception`` in code under test cannot swallow it silently
    (it would still fail the test on the re-raise, but the intent is that this
    is a HARNESS verdict, not a runtime condition to handle).
    """


def _caller_is_allowed() -> bool:
    """True iff the frame that called ``time.sleep`` is on the allowlist.

    Inspects the immediate caller (the frame one level up from the patched
    ``sleep``): its code object's filename must END WITH an allowed module path
    AND its function name must match. Matching on the immediate caller (not
    anywhere in the stack) means a test cannot launder a sleep through the
    allowlisted function — only the poll loop's own ``time.sleep`` call site is
    permitted.
    """
    frame = sys._getframe(2)  # 0: this fn, 1: the patched sleep, 2: the caller
    filename = frame.f_code.co_filename.replace("\\", "/")
    func_name = frame.f_code.co_name
    return any(
        filename.endswith(module_suffix) and func_name == fn_name
        for module_suffix, fn_name in _ALLOWED_SLEEP_CALLERS
    )


@pytest.fixture(autouse=True)
def no_time_sleep(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Autouse: forbid ``time.sleep`` in every test (PLAN.md 7).

    Replaces ``time.sleep`` with a guard that delegates to the real sleep only
    for the single allowlisted production poll loop and raises
    :class:`SleepInTestError` for anyone else. Patched via ``monkeypatch`` so it
    is torn down automatically after each test.

    The patch is applied to ``time.sleep`` (the attribute the whole process
    resolves, including ``airlock.commit``'s ``import time; time.sleep(...)``),
    so it is in force for in-process code under test. Spawn SUBPROCESSES
    re-import a clean ``time`` and are therefore unaffected — which is correct:
    their synchronization is asserted by their own barriers/events, and a child
    process is not "a test calling time.sleep" in the sense PLAN 7 forbids.
    """
    real_sleep = time.sleep
    main_thread = threading.main_thread()

    def guarded_sleep(seconds: float) -> None:
        # Only police the MAIN thread — that is where the test body (and any
        # fixture) runs, so a main-thread sleep IS "a test calling time.sleep"
        # (PLAN.md 7). A background/library thread is not the test; policing it
        # would let an unrelated leaked daemon (e.g. a prior test's abandoned
        # execute thread) raise here and muddy the verdict, and would wrongly
        # forbid a future production poll that legitimately sleeps off-thread.
        if threading.current_thread() is not main_thread or _caller_is_allowed():
            real_sleep(seconds)
            return
        raise SleepInTestError(
            "time.sleep() is forbidden in tests (PLAN.md 7 / SPEC.md 9): a sleeping "
            "test synchronizes by guessing wall-clock time, which turns a live race "
            "into an intermittent CI failure. Use a barrier, event, FakeClock, or "
            "DB-state polling with a hard deadline instead. (The only sanctioned "
            "sleep is commit_once's bounded ledger poll.)"
        )

    monkeypatch.setattr(time, "sleep", guarded_sleep)
    yield
