"""
MCPIP V2 — Connector binding: OpenAI-compatible model providers.

Mistral, Groq, Together, Fireworks, OpenRouter, and xAI all emit the exact OpenAI
tool-call shape (``{"id","type":"function","function":{"name","arguments":"<json>"}}``),
so they reuse ``parse_openai`` verbatim — a pure alias onto ``OPENAI_TOOL_CALL``,
no new wire shape. (OpenAI/Azure/Copilot/DeepSeek/Qwen/ERNIE have their own binding
modules; this groups the remaining OpenAI-compatible third parties.)

PURE PARSER BINDING — no SDK import, no network, no vendor key. MCPIP parses the
tool-call shape; the end user's client holds the LLM credentials.
"""

from __future__ import annotations

from typing import Final

from bridge.connectors import formats
from bridge.connectors.base import FormatParser
from interfaces import SourceFormat

VENDORS: Final[tuple[str, ...]] = (
    "mistral",
    "groq",
    "together",
    "fireworks",
    "openrouter",
    "xai",
)
SOURCE_FORMAT: Final[SourceFormat] = SourceFormat.OPENAI_TOOL_CALL
PARSER: Final[FormatParser] = formats.parse_openai
