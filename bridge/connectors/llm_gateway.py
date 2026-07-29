"""
MCPIP V2 — Connector binding: LLM gateways / routers (OpenAI tool_call dialect).

LiteLLM, Portkey, Cloudflare Workers AI, the Vercel AI Gateway and GitHub Models
all normalize whatever upstream model they front INTO the OpenAI tool-call shape
before the caller sees it, so they reuse ``parse_openai`` verbatim.

A gateway in front of the model does NOT change MCPIP's posture: MCPIP is an
authorization plane, not an LLM proxy, so it authorizes the tool call the gateway
emitted with no knowledge of (and no credential for) whatever model produced it.
The vendor id records WHICH router proposed the action in the WORM log.
(``openrouter`` is a router too and is already bound in ``openai_compatible``;
it stays there to keep the pinned mapping stable — the binding is identical.)

PURE PARSER BINDING — no SDK import, no network, no vendor key. MCPIP parses the
tool-call shape; the end user's client holds the LLM credentials.
"""

from __future__ import annotations

from typing import Final

from bridge.connectors import formats
from bridge.connectors.base import FormatParser
from interfaces import SourceFormat

VENDORS: Final[tuple[str, ...]] = (
    "litellm",
    "portkey",
    "cloudflare_workers_ai",
    "vercel_ai_gateway",
    "github_models",
)
SOURCE_FORMAT: Final[SourceFormat] = SourceFormat.OPENAI_TOOL_CALL
PARSER: Final[FormatParser] = formats.parse_openai
