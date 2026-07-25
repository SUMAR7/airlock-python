"""Async guarded tools inside REAL agent frameworks (ASYNC-DESIGN.md §7 item 10).

The "actually usable" gate. Every other async test drives the bridge under a loop
*we* create; these run it under a framework's OWN event loop — LangGraph's Pregel
execution and an MCP server session — which is where a loop-ownership bug would
actually show up.

Opt-in, exactly like the cross-repo Rails E2E: marked ``e2e`` and skipped when the
framework is not installed, so CI does not carry heavy agent-framework deps. Run
them with::

    pip install langgraph mcp
    pytest -m e2e

SQLite-only (a temp file per test): these prove the framework integration, not the
storage matrix, which the rest of the async suite already covers on both backends.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from typing import Any

import pytest

from airlock import guard, init
from airlock.audit import verify_chain
from airlock.effects import Effect
from airlock.policy import Policy, Rule
from airlock.types import Decision

pytestmark = [pytest.mark.e2e, pytest.mark.usefixtures("guard_isolation")]


def _init() -> Any:
    return init(
        store=f"sqlite:///{os.path.join(tempfile.mkdtemp(), 'a.db')}",
        policy=Policy(rules=[Rule(match="fw.*", decision=Decision.AUTO)]),
    )


# --- LangGraph ---------------------------------------------------------------


async def test_langgraph_graph_runs_async_guarded_tool_exactly_once() -> None:
    """A real compiled StateGraph + ToolNode, driven by ``graph.ainvoke``.

    Case 3 is the one that matters most: the model emitting the SAME tool call
    twice IN PARALLEL in one AIMessage (langchain-ai/langchain#38708). Message-level
    dedup middleware would collapse those; Airlock collapses them at the LEDGER,
    which also covers the retry-across-turns case that middleware cannot see.
    """
    pytest.importorskip("langgraph", reason="pip install langgraph to run the framework E2E")
    from langchain_core.messages import AIMessage
    from langgraph.graph import END, START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode

    charged: list[str] = []
    pending: list[dict[str, Any]] = []

    @guard("fw.refund", effect=Effect(key_param="idempotency_key"))
    async def refund(charge_id: str, amount_cents: int, idempotency_key: str | None = None) -> str:
        """Refund a charge on the customer's card."""
        await asyncio.sleep(0)
        charged.append(charge_id)
        return f"refunded {charge_id} (effect #{len(charged)})"

    async def model_node(state: MessagesState) -> dict[str, Any]:
        # Stands in for the LLM: contributes exactly the tool_calls it would.
        return {"messages": [AIMessage(content="", tool_calls=list(pending))]}

    def call(cid: str, charge: str) -> dict[str, Any]:
        return {
            "name": "refund",
            "args": {"charge_id": charge, "amount_cents": 5000},
            "id": cid,
            "type": "tool_call",
        }

    def tool_texts(result: dict[str, Any]) -> list[str]:
        return [m.content for m in result["messages"] if m.__class__.__name__ == "ToolMessage"]

    app = _init()
    builder = StateGraph(MessagesState)
    builder.add_node("model", model_node)
    builder.add_node("tools", ToolNode([refund]))
    builder.add_edge(START, "model")
    builder.add_edge("model", "tools")
    builder.add_edge("tools", END)
    graph = builder.compile()

    # 1. the async guarded tool runs inside the graph
    pending[:] = [call("c1", "ch_A")]
    first = tool_texts(await graph.ainvoke({"messages": []}))[0]
    assert charged == ["ch_A"]

    # 2. the same logical call in a LATER graph run is deduped by the ledger
    pending[:] = [call("c2", "ch_A")]
    assert tool_texts(await graph.ainvoke({"messages": []}))[0] == first
    assert charged == ["ch_A"], f"a retry across graph runs re-fired the effect: {charged}"

    # 3. the model emits the SAME call twice in parallel (#38708)
    before = len(charged)
    pending[:] = [call("p1", "ch_B"), call("p2", "ch_B")]
    outs = tool_texts(await graph.ainvoke({"messages": []}))
    assert len(charged) - before == 1, "parallel duplicate tool calls double-fired the effect"
    assert len(outs) == 2 and outs[0] == outs[1], outs

    verify_chain(app.store)
    app.store.close()


# --- MCP ---------------------------------------------------------------------


async def test_mcp_session_runs_async_guarded_tool_exactly_once() -> None:
    """A real FastMCP server + client session over the real protocol.

    MCP is async to its core — the server owns the loop and dispatches tools as
    coroutines — so this is the sternest check that the bridge never needs a loop
    of its own and never blocks the caller's.
    """
    pytest.importorskip("mcp", reason="pip install mcp to run the framework E2E")
    from mcp.server.fastmcp import FastMCP
    from mcp.shared.memory import create_connected_server_and_client_session

    charged: list[str] = []
    server = FastMCP("airlock-e2e")

    # mcp ships no type stubs, so its decorator is untyped under strict mode.
    @server.tool()  # type: ignore[untyped-decorator]
    @guard("fw.mcp_refund", effect=Effect(key_param="idempotency_key"))
    async def refund(charge_id: str, amount_cents: int, idempotency_key: str | None = None) -> str:
        """Refund a charge on the customer's card."""
        await asyncio.sleep(0)
        charged.append(charge_id)
        return f"refunded {charge_id} (effect #{len(charged)})"

    def text(result: Any) -> str:
        return "".join(getattr(block, "text", "") for block in result.content)

    app = _init()
    async with create_connected_server_and_client_session(server._mcp_server) as session:
        assert "refund" in [t.name for t in (await session.list_tools()).tools]
        args = {"charge_id": "ch_MCP", "amount_cents": 5000}

        # 1. a real protocol round trip executes the async guarded tool
        first = text(await session.call_tool("refund", args))
        assert charged == ["ch_MCP"]

        # 2. an MCP client retry must not double-charge
        assert text(await session.call_tool("refund", args)) == first
        assert charged == ["ch_MCP"], f"an MCP retry re-fired the effect: {charged}"

        # 3. concurrent identical calls collapse to one effect
        before = len(charged)
        results = await asyncio.gather(
            *(
                session.call_tool("refund", {"charge_id": "ch_CONC", "amount_cents": 5000})
                for _ in range(5)
            )
        )
        assert len(charged) - before == 1, "concurrent MCP calls double-fired the effect"
        assert len({text(r) for r in results}) == 1, "concurrent MCP callers disagreed"

    verify_chain(app.store)
    app.store.close()
