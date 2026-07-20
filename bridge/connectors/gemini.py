"""
MCPIP V2 — Connector binding: Gemini / Vertex AI (functionCall part).

PURE PARSER BINDING — no SDK import, no network, no vendor key. MCPIP parses the
tool-call shape; the end user's client holds the LLM credentials.
"""

from __future__ import annotations

from typing import Final

from bridge.connectors import formats
from bridge.connectors.base import FormatParser
from interfaces import SourceFormat

VENDORS: Final[tuple[str, ...]] = ("gemini", "vertex")
SOURCE_FORMAT: Final[SourceFormat] = SourceFormat.GEMINI_FUNCTION_CALL
PARSER: Final[FormatParser] = formats.parse_gemini
