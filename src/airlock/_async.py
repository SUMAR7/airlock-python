"""The coroutine bridge (ASYNC-DESIGN.md §4.2) — how an `async def` effect runs
under the ONE synchronous, already-proven commit core.

Airlock's exactly-once core (`commit_once`: claim → mark_executing → execute →
post-verify → finalize+audit in one transaction) is synchronous and adversarially
tested. Async support deliberately does NOT fork it — a second implementation of
exactly-once would mean a second place for an exactly-once bug, and the whole
proof battery (8-process concurrency, crash-injection, the property machine)
would need an async twin.

Instead: **only the user's effect needs awaiting.** The sync core runs on a
worker thread; the coroutine is bridged back to a real event loop. Everything
else — the ledger writes, the hash-chained audit append — is Airlock's own sync
DB work, untouched.

The effect is invoked at THREE sites, and two of them have no event loop:

    live AUTO          -> the caller's loop (bridged back to it)
    resume             -> a SYNC webhook receiver / backstop poll, often a
                          fresh process after a restart
    reconcile          -> a SYNC cron (`python -m airlock reconcile`), no loop

`run_coro_blocking` handles all three, which is what makes the durable-pause and
crash-recovery promises hold for async effects as literally as they do for sync
ones (ASYNC-DESIGN.md §1, P2/P3). Async that only worked on the AUTO path would
mean "exactly-once, except when a human approves it or after a crash" — which is
not a promise worth making.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

__all__ = ["bridge_loop", "is_awaitable", "run_coro_blocking"]

#: The loop a bridged worker thread should send coroutines back to. Set by the
#: async `@guard` wrapper (via :func:`bridge_loop`) for the duration of the
#: worker's run. Thread-local because each worker thread serves exactly one
#: `commit_once` call, and threads are reused across calls by the executor.
_state = threading.local()


def is_awaitable(value: Any) -> bool:
    """True if ``value`` is a coroutine/awaitable the bridge must resolve.

    Checked on the RESULT rather than the function so both call funnels
    (``_call_tool_live`` and ``_call_tool_from_map``) need one identical line —
    and so a plain sync tool that happens to return an awaitable is still
    handled rather than silently committed as a coroutine object.
    """
    return asyncio.iscoroutine(value) or isinstance(value, asyncio.Future)


class bridge_loop:  # noqa: N801 - a context manager used like a lowercase verb
    """Bind this worker thread to ``loop`` for the duration of the block.

    Entered by the async guard wrapper on the worker thread it dispatches the
    sync core to, so any coroutine the core produces is executed on the caller's
    own loop instead of a private one.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._previous: asyncio.AbstractEventLoop | None = None

    def __enter__(self) -> bridge_loop:
        self._previous = getattr(_state, "loop", None)
        _state.loop = self._loop
        return self

    def __exit__(self, *exc: object) -> None:
        _state.loop = self._previous


def _bound_loop() -> asyncio.AbstractEventLoop | None:
    return getattr(_state, "loop", None)


def run_coro_blocking(coro: Any, *, timeout: float | None = None) -> Any:
    """Drive ``coro`` to completion from SYNCHRONOUS code, and return its result.

    Three situations, one helper (ASYNC-DESIGN.md §4.2):

    1. **We are a bridged worker** — the async wrapper bound a loop to this
       thread. Submit the coroutine to that loop and block this worker (never
       the loop) until it finishes. The loop is free precisely because the sync
       core is off it, which is why this cannot deadlock.
    2. **No loop is running in this thread** — a sync reconciler, a webhook
       receiver, a fresh process after a restart. Own a loop for the duration:
       ``asyncio.run``. This is what makes resume and crash-recovery work for
       async effects.
    3. **A loop IS already running in this thread** — we must not block it, and
       we cannot await from sync code. Refuse loudly, naming the fix.

    Cancellation/timeout note (ASYNC-DESIGN.md §4.3): on timeout the future is
    cancelled — better than the sync path, which can only abandon a thread. But
    cancellation is NOT proof the effect did not land (the ``await`` may already
    have sent the request), so callers must still treat the row as ``executing``
    and let the verify-first reconciler decide. Async gets a better mechanism,
    not a stronger promise.
    """
    loop = _bound_loop()
    if loop is not None:
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            return future.result(timeout)
        except TimeoutError:
            future.cancel()
            raise

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # No loop in this thread: own one for the duration (situation 2).
        return asyncio.run(coro)

    # Situation 3: a running loop we must not block.
    coro.close()
    raise RuntimeError(
        "Airlock cannot drive an async effect from inside a running event loop "
        "on this thread. This happens when a SYNC entry point (Airlock.resume, "
        "the reconciler, or a webhook receiver) is called from async code while "
        "the guarded tool is 'async def'. Call the async entry point instead, or "
        "run the sync one in a worker thread (e.g. await asyncio.to_thread(...))."
    )
