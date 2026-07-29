"""
MCPIP V2 — Connector binding: MCP-speaking assistant surfaces & automation platforms.

Covers the standard MCP wire shape (JSON-RPC 2.0 ``tools/call``) as emitted by
assistant products and workflow/automation platforms acting as MCP CLIENTS:
ChatGPT connectors, Microsoft Copilot Studio, LibreChat, Open WebUI, n8n, Dify,
Langflow and Flowise. Same parser as ``mcp_standard`` — bound in its own module
because these are PLATFORMS, not developer tools, and an operator reading the WORM
log needs "an n8n workflow proposed this" to be distinguishable from "a developer's
editor proposed this".

PURE PARSER BINDING — no SDK import, no network, no vendor key. MCPIP parses the
tool-call shape; the end user's client holds the LLM credentials.
"""

from __future__ import annotations

from typing import Final

from bridge.connectors import formats
from bridge.connectors.base import FormatParser
from interfaces import SourceFormat

VENDORS: Final[tuple[str, ...]] = (
    "chatgpt",
    "copilot_studio",
    "librechat",
    "openwebui",
    "n8n",
    "dify",
    "langflow",
    "flowise",
)
SOURCE_FORMAT: Final[SourceFormat] = SourceFormat.MCP_JSONRPC
PARSER: Final[FormatParser] = formats.parse_mcp
