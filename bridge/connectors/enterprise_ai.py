"""
MCPIP V2 — Connector binding: enterprise data-platform model endpoints.

Databricks Foundation Model APIs, IBM watsonx.ai and Snowflake Cortex all expose
an OpenAI-compatible chat surface whose tool calls arrive in the exact OpenAI
shape, so they reuse ``parse_openai`` verbatim — a pure alias onto
``OPENAI_TOOL_CALL``, no new wire shape.

Bound separately from the third-party inference clouds because these are the
platforms a REGULATED buyer already runs inside their own account: the vendor id
is what the WORM record will name, and "which platform proposed this action" is
exactly the question a compliance reviewer asks.

PURE PARSER BINDING — no SDK import, no network, no vendor key. MCPIP parses the
tool-call shape; the end user's client holds the LLM credentials.
"""

from __future__ import annotations

from typing import Final

from bridge.connectors import formats
from bridge.connectors.base import FormatParser
from interfaces import SourceFormat

VENDORS: Final[tuple[str, ...]] = ("databricks", "watsonx", "snowflake_cortex")
SOURCE_FORMAT: Final[SourceFormat] = SourceFormat.OPENAI_TOOL_CALL
PARSER: Final[FormatParser] = formats.parse_openai
