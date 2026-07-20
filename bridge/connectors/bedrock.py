"""
MCPIP V2 — Connector binding: AWS Bedrock Converse (native toolUse block).

# PARSE ONLY — MCPIP never calls AWS; no boto3, no credentials, ever.

PURE PARSER BINDING — no SDK import, no network, no vendor key. MCPIP parses the
tool-call shape; the end user's client holds the LLM credentials.
"""

from __future__ import annotations

from typing import Final

from bridge.connectors import formats
from bridge.connectors.base import FormatParser
from interfaces import SourceFormat

VENDORS: Final[tuple[str, ...]] = ("bedrock",)
SOURCE_FORMAT: Final[SourceFormat] = SourceFormat.BEDROCK_TOOL_USE
PARSER: Final[FormatParser] = formats.parse_bedrock
