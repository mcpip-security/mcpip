"""
MCPIP V2 — Connector binding: Claude, incl. Bedrock- and Vertex-hosted (tool_use).

``claude_bedrock`` and ``claude_vertex`` bind to the ANTHROPIC parser deliberately:
Claude served through Bedrock's or Vertex AI's Anthropic-native API emits the
identical ``tool_use`` block — the HOST changes, the wire shape does not. Raw
``bedrock`` (Converse ``toolUse``) binds to the bedrock parser instead, and raw
``vertex`` (Gemini ``functionCall``) binds to the gemini parser — all four
mappings deliberate and pinned in the registry.

PURE PARSER BINDING — no SDK import, no network, no vendor key. MCPIP parses the
tool-call shape; the end user's client holds the LLM credentials.
"""

from __future__ import annotations

from typing import Final

from bridge.connectors import formats
from bridge.connectors.base import FormatParser
from interfaces import SourceFormat

VENDORS: Final[tuple[str, ...]] = ("claude", "claude_bedrock", "claude_vertex")
SOURCE_FORMAT: Final[SourceFormat] = SourceFormat.ANTHROPIC_TOOL_USE
PARSER: Final[FormatParser] = formats.parse_anthropic
