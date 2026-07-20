"""
MCPIP V2 — Connector binding: MCP standard (JSON-RPC 2.0 tools/call).

Covers the standard MCP wire shape (JSON-RPC 2.0 ``tools/call``) emitted by MCP
hosts: Claude Code, Cursor, Windsurf, plus the coding-agent hosts Cline, opencode,
Goose, and OpenHands, and OpenClaw's MCP passthrough. (OpenClaw's *native* flat
tool-invoke envelope is a distinct wire shape and is NOT covered here.)

PURE PARSER BINDING — no SDK import, no network, no vendor key. MCPIP parses the
tool-call shape; the end user's client holds the LLM credentials.
"""

from __future__ import annotations

from typing import Final

from bridge.connectors import formats
from bridge.connectors.base import FormatParser
from interfaces import SourceFormat

VENDORS: Final[tuple[str, ...]] = (
    "mcp",
    "claude_code",
    "cursor",
    "windsurf",
    "cline",
    "opencode",
    "goose",
    "openhands",
    "openclaw",
)
SOURCE_FORMAT: Final[SourceFormat] = SourceFormat.MCP_JSONRPC
PARSER: Final[FormatParser] = formats.parse_mcp
