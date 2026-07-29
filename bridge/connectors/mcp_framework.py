"""
MCPIP V2 — Connector binding: agent FRAMEWORKS acting as MCP clients.

LangGraph, CrewAI, AutoGen, the OpenAI Agents SDK, Pydantic AI, LlamaIndex,
Semantic Kernel, Mastra and Strands Agents all ship first-party MCP client
support and emit the standard JSON-RPC 2.0 ``tools/call``, so they reuse
``parse_mcp`` verbatim.

Bound in their own module because the framework is the layer that actually
ORCHESTRATES a multi-step plan: when a chain of steps ends in one side-effecting
call, the vendor id names the orchestrator on the WORM record, while the swarm
trace names the hop. Neither one authorizes anything — identity still comes only
from the verified JWT.

PURE PARSER BINDING — no SDK import, no network, no vendor key. MCPIP parses the
tool-call shape; the end user's client holds the LLM credentials.
"""

from __future__ import annotations

from typing import Final

from bridge.connectors import formats
from bridge.connectors.base import FormatParser
from interfaces import SourceFormat

VENDORS: Final[tuple[str, ...]] = (
    "langgraph",
    "crewai",
    "autogen",
    "openai_agents",
    "pydantic_ai",
    "llamaindex",
    "semantic_kernel",
    "mastra",
    "strands",
)
SOURCE_FORMAT: Final[SourceFormat] = SourceFormat.MCP_JSONRPC
PARSER: Final[FormatParser] = formats.parse_mcp
