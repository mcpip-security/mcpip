"""
MCPIP V2 — Connector binding: MCP standard (JSON-RPC 2.0 tools/call).

Covers the standard MCP wire shape (JSON-RPC 2.0 ``tools/call``) emitted by MCP
hosts — editors, IDEs, terminals and coding agents: Claude Code, Cursor, Windsurf,
Zed, VS Code, JetBrains, Continue, Cline, Roo Code, Kilo Code, opencode, Codex CLI,
Gemini CLI, Goose, OpenHands, Amp, Crush, Warp, plus OpenClaw's MCP passthrough.
(OpenClaw's *native* flat tool-invoke envelope is a distinct wire shape and is NOT
covered here.)

Assistant/automation PLATFORMS speaking MCP live in ``mcp_platform``; agent
FRAMEWORKS acting as MCP clients live in ``mcp_framework``. Same parser, separate
modules, so the vendor id on a WORM record tells an operator what KIND of caller
proposed the action.

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
    "zed",
    "vscode",
    "jetbrains",
    "continue",
    "roo",
    "kilocode",
    "codex",
    "gemini_cli",
    "amp",
    "crush",
    "warp",
)
SOURCE_FORMAT: Final[SourceFormat] = SourceFormat.MCP_JSONRPC
PARSER: Final[FormatParser] = formats.parse_mcp
