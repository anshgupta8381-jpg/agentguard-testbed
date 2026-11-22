"""MCP server that exposes the six Acme tools.

The agent never calls the tool functions directly any more: it asks this server
which tools exist (their names, descriptions and argument schemas come from the
server) and calls them through the MCP client. That is how a real product wires
an agent to its tools, and it is what makes MCP attacks possible: whatever the
server says about its tools goes straight into the model's context (A10).

Two ways to run it:
  * in-process (used by the notebooks and the eval harness, fast):
        server = build_server(env)
        tools = MCPToolClient([server])
  * as a separate process over stdio (a real MCP server you can point any MCP client at):
        python -m agentguard.mcp_server --user riya --data data --db chroma_db --run-dir runs/demo
"""
from __future__ import annotations

import argparse
import asyncio
import threading
from typing import Annotated

from pydantic import Field

from mcp import Client
from mcp.server import MCPServer

from agentguard.tools import TOOL_SCHEMAS, AgentEnv, Toolbox

DESCRIPTIONS = {t["function"]["name"]: t["function"]["description"] for t in TOOL_SCHEMAS}


def build_server(env: AgentEnv, name: str = "acme-tools") -> MCPServer:
    """Create an MCP server whose tools act on `env` (one user's documents, inbox, outbox and memory).

    The server keeps a reference to `env`, so planting an email or page in `env`
    after the server is built is visible to the next tool call.
    """
    tb = Toolbox(env)
    server = MCPServer(name, instructions="Internal tools for the Acme Assistant.")

    @server.tool(description=DESCRIPTIONS["search_docs"])
    def search_docs(query: Annotated[str, Field(description="What to search for")]) -> str:
        return tb.search_docs(query)

    @server.tool(description=DESCRIPTIONS["read_file"])
    def read_file(path: Annotated[str, Field(description="File name or path of the document")]) -> str:
        return tb.read_file(path)

    @server.tool(description=DESCRIPTIONS["read_inbox"])
    def read_inbox(limit: Annotated[int, Field(description="How many emails to return (default 10)")] = 10) -> str:
        return tb.read_inbox(limit)

    @server.tool(description=DESCRIPTIONS["fetch_page"])
    def fetch_page(url: Annotated[str, Field(description="Page URL or file name")]) -> str:
        return tb.fetch_page(url)

    @server.tool(description=DESCRIPTIONS["send_email"])
    def send_email(to: Annotated[str, Field(description="Recipient address(es), comma separated")],
                   subject: Annotated[str, Field(description="Email subject")],
                   body: Annotated[str, Field(description="Email body")],
                   cc: Annotated[str, Field(description="Optional CC address(es), comma separated")] = "") -> str:
        return tb.send_email(to, subject, body, cc or None)

    @server.tool(description=DESCRIPTIONS["save_memory"])
    def save_memory(fact: Annotated[str, Field(description="The fact to remember")]) -> str:
        return tb.save_memory(fact)

    return server


def _to_ollama_schema(tool) -> dict:
    schema = dict(tool.input_schema or {"type": "object", "properties": {}})
    schema.pop("title", None)
    props = {k: {kk: vv for kk, vv in v.items() if kk != "title"} for k, v in schema.get("properties", {}).items()}
    schema["properties"] = props
    schema.setdefault("required", [])
    return {"type": "function", "function": {"name": tool.name, "description": tool.description or "",
                                             "parameters": schema}}


class MCPToolClient:
    """Synchronous wrapper around one or more MCP servers, for the (synchronous) agent loop.

    It runs its own event loop in a background thread, so it also works inside
    Jupyter/Kaggle, where the main thread already has a running loop.
    `servers` can be MCPServer objects (in-process) or StdioServerParameters (separate process).
    """

    def __init__(self, servers: list, timeout: float = 120.0):
        self.timeout = timeout
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()
        self._clients: list = []
        self._stop = None
        self._ready = threading.Event()
        self._error: BaseException | None = None
        self._runner = asyncio.run_coroutine_threadsafe(self._connect_all(servers), self._loop)
        if not self._ready.wait(timeout) or self._error:
            raise RuntimeError(f"Could not connect to MCP server(s): {self._error}")
        self.schemas: list[dict] = []
        self.routes: dict[str, int] = {}
        for i, client in enumerate(self._clients):
            for tool in self._run(client.list_tools()).tools:
                if tool.name not in self.routes:      # first server wins on a name clash
                    self.routes[tool.name] = i
                    self.schemas.append(_to_ollama_schema(tool))

    async def _connect_all(self, servers):
        from contextlib import AsyncExitStack
        self._stop = asyncio.Event()
        try:
            async with AsyncExitStack() as stack:
                for s in servers:
                    self._clients.append(await stack.enter_async_context(Client(s)))
                self._ready.set()
                await self._stop.wait()
        except BaseException as e:  # surface connection errors to __init__
            self._error = e
            self._ready.set()

    def _run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(self.timeout)

    @property
    def tool_names(self) -> list[str]:
        return [s["function"]["name"] for s in self.schemas]

    def call(self, name: str, args: dict) -> str:
        if name not in self.routes:
            return f"Error: unknown tool '{name}'. Available tools: {', '.join(self.tool_names)}"
        result = self._run(self._clients[self.routes[name]].call_tool(name, args or {}))
        text = "\n".join(getattr(c, "text", "") for c in result.content)
        return f"Error: {text}" if result.is_error and not text.startswith("Error") else text

    def close(self) -> None:
        if self._stop is not None:
            self._loop.call_soon_threadsafe(self._stop.set)
            try:
                self._runner.result(10)
            except Exception:
                pass
        self._loop.call_soon_threadsafe(self._loop.stop)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def main():  # stdio mode
    from agentguard.memory import MemoryStore
    from agentguard.rag import DocIndex
    p = argparse.ArgumentParser(description="Run the Acme tools as an MCP server over stdio.")
    p.add_argument("--user", default="riya")
    p.add_argument("--data", default="data")
    p.add_argument("--db", default="chroma_db", help="ChromaDB folder (build the index first)")
    p.add_argument("--run-dir", default="runs/mcp_stdio")
    a = p.parse_args()
    env = AgentEnv(data_dir=a.data, user=a.user, index=DocIndex(a.data, a.db),
                   memory=MemoryStore(f"{a.run_dir}/memory.db"), run_dir=a.run_dir)
    build_server(env).run("stdio")


if __name__ == "__main__":
    main()
