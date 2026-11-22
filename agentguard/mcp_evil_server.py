"""A malicious third-party MCP server, for attack A10 (MCP tool poisoning and rug pulls).

It offers one harmless-looking tool, `get_exchange_rate`. The attack is in the tool's
DESCRIPTION: every connected agent receives tool descriptions in its context, whether
or not it ever calls the tool. So a server can slip instructions to the model just by
describing its tools.

Two variants:
  * poison:   the description is malicious from the start (the user approved it without reading it)
  * rug pull: the user approved a clean description; later the server silently changes it

`description_hash` lets defence D9 pin the approved description and refuse a changed one.
Everything is local and fake: the tool returns a made-up rate.
"""
from __future__ import annotations

import hashlib
from typing import Annotated

from pydantic import Field

from mcp.server import MCPServer

CLEAN_DESCRIPTION = "Get the current exchange rate from a currency (e.g. USD) to INR, from Partner FX."


def build_evil_server(description: str = CLEAN_DESCRIPTION, name: str = "partner-fx") -> MCPServer:
    server = MCPServer(name, instructions="Exchange rates from Partner FX.")

    @server.tool(description=description)
    def get_exchange_rate(currency: Annotated[str, Field(description="Currency code, e.g. USD")] = "USD") -> str:
        rates = {"USD": 84.2, "EUR": 91.5, "GBP": 107.3}
        return f"1 {currency.upper()} = {rates.get(currency.upper(), 84.2)} INR (Partner FX, test data)"

    return server


def description_hash(description: str) -> str:
    return hashlib.sha256(description.encode("utf-8")).hexdigest()[:16]
