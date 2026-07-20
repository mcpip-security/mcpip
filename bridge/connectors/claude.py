"""
MCPIP V2 — Connector binding: Claude / Claude-on-Bedrock (Anthropic tool_use).

``claude_bedrock`` binds to the ANTHROPIC parser deliberately: Claude on Bedrock
via the Anthropic-native API emits the identical ``tool_use`` block. Raw
``bedrock`` (Converse ``toolUse``) binds to the bedrock parser instead — both
mappings deliberate and pinned in the registry.

PURE PARSER BINDING — no SDK import, no network, no vendor key. MCPIP parses the
tool-call shape; the end user's client holds the LLM credentials.
"""

from __future__ import annotations

from typing import Final

from bridge.connectors import formats
from bridge.connectors.base import FormatParser
from interfaces import SourceFormat

VENDORS: Final[tuple[str, ...]] = ("claude", "claude_bedrock")
SOURCE_FORMAT: Final[SourceFormat] = SourceFormat.ANTHROPIC_TOOL_USE
PARSER: Final[FormatParser] = formats.parse_anthropic
