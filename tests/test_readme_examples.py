"""Execute the README + docs code blocks so a drifted example FAILS CI (P4.3).

The README and ``docs/`` are the OSS front door: a stranger copies a code block
and expects it to run against the *shipped* API. A block that silently drifts
from the real surface is worse than no docs. So every load-bearing snippet is
marked runnable and executed here, verbatim, in isolation — if the API changes
under it, this test reddens.

How a block is marked
---------------------
An HTML comment immediately before a fenced ``python`` block::

    <!-- airlock:test id=quickstart -->
    ```python
    ... runnable, self-verifying code (contains its own asserts) ...
    ```

Each marked block is extracted and ``exec``'d in a fresh namespace, in a scratch
working directory (so the zero-config SQLite store lands in ``tmp``, never the
repo), with the process-wide ``@guard`` registry, the ambient runtime, and the
one-shot warning latches reset around it (the same isolation the ``@guard``
suite uses). The blocks carry their OWN assertions — the exactly-once result,
the gate that commits once, the at-most-once warning — so executing without an
exception IS the verification. Deterministic, base-install + SQLite, no network,
no ``time.sleep`` (the autouse conftest guard forbids it).
"""

from __future__ import annotations

import contextlib
import os
import re
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

_REPO_ROOT = Path(__file__).resolve().parents[1]

#: The files whose marked ```python blocks must run against the shipped API.
_DOC_FILES = (
    _REPO_ROOT / "README.md",
    _REPO_ROOT / "docs" / "api.md",
    _REPO_ROOT / "docs" / "architecture.md",
    _REPO_ROOT / "docs" / "event-schema.md",
)

#: `<!-- airlock:test id=NAME -->` then the next ```python fenced block.
_BLOCK_RE = re.compile(
    r"<!--\s*airlock:test\s+id=([\w-]+)\s*-->\s*\n```python\n(.*?)\n```",
    re.DOTALL,
)


class _Block(NamedTuple):
    """One extracted, runnable doc block."""

    doc: str
    block_id: str
    code: str


def _collect_blocks() -> list[_Block]:
    blocks: list[_Block] = []
    for path in _DOC_FILES:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for match in _BLOCK_RE.finditer(text):
            blocks.append(_Block(doc=path.name, block_id=match.group(1), code=match.group(2)))
    return blocks


_BLOCKS = _collect_blocks()


@contextmanager
def _isolated_runtime(workdir: Path) -> Iterator[None]:
    """Run a doc block in a scratch cwd with all process-wide state reset.

    Resets the same globals the ``guard_isolation`` conftest fixture does — the
    ambient runtime contextvar and the shared registry — plus the one-shot
    warning latches (dev-store note, at-most-once) so a block that asserts on a
    warning sees it fire. Closes whatever store the block wired, then restores
    everything, so blocks never leak into each other or the rest of the suite.
    """
    import airlock._guard as guard_mod
    import airlock.commit as commit_mod
    from airlock.registry import registry

    original_cwd = Path.cwd()
    os.chdir(workdir)
    token = guard_mod._runtime_var.set(None)
    saved_registrations = dict(registry._registrations)
    registry._registrations.clear()
    guard_mod._dev_store_warned = False
    saved_at_most_once = set(commit_mod._at_most_once_warned)
    commit_mod._at_most_once_warned.clear()
    try:
        yield
    finally:
        runtime = guard_mod._runtime_var.get()
        if runtime is not None:
            with contextlib.suppress(Exception):  # best-effort cleanup
                runtime.store.close()
        registry._registrations.clear()
        registry._registrations.update(saved_registrations)
        guard_mod._runtime_var.reset(token)
        commit_mod._at_most_once_warned.clear()
        commit_mod._at_most_once_warned.update(saved_at_most_once)
        os.chdir(original_cwd)


def test_docs_have_runnable_blocks() -> None:
    """Guard against the extractor silently matching nothing (a green no-op)."""
    ids = {block.block_id for block in _BLOCKS}
    # The four surfaces + the two honesty/audit stories must all be present and run.
    assert {"quickstart", "policy", "store", "gate", "at_most_once"} <= ids


@pytest.mark.parametrize(
    "block",
    _BLOCKS,
    ids=[f"{block.doc}:{block.block_id}" for block in _BLOCKS],
)
def test_doc_block_runs(block: _Block, tmp_path: Path) -> None:
    """Execute one marked doc block verbatim; its own asserts are the check."""
    namespace: dict[str, object] = {"__name__": "__airlock_docs__"}
    compiled = compile(block.code, f"<{block.doc}:{block.block_id}>", "exec")
    with _isolated_runtime(tmp_path):
        exec(compiled, namespace)  # running our own docs against the shipped API
