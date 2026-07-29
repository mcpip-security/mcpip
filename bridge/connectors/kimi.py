"""
MCPIP V2 — Connector binding: Kimi / Moonshot AI (OpenAI tool_call dialect).

Moonshot AI's Kimi models expose an OpenAI-compatible chat-completions surface and
emit the exact OpenAI tool-call shape, so this is a pure alias onto
``OPENAI_TOOL_CALL`` — no new wire shape. Both vendor ids are bound because both
are in live use: ``kimi`` (the product/agent surface) and ``moonshot`` (the
platform/API surface). Exact strings only — MCPIP never casefolds or aliases.

PURE PARSER BINDING — no SDK import, no network, no vendor key. MCPIP parses the
tool-call shape; the end user's client holds the LLM credentials.
"""

from __future__ import annotations

from typing import Final

from bridge.connectors import formats
from bridge.connectors.base import FormatParser
from interfaces import SourceFormat

VENDORS: Final[tuple[str, ...]] = ("kimi", "moonshot")
SOURCE_FORMAT: Final[SourceFormat] = SourceFormat.OPENAI_TOOL_CALL
PARSER: Final[FormatParser] = formats.parse_openai
