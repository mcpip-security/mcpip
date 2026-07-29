"""
MCPIP V2 — Connector binding: OpenAI-compatible third-party model providers.

Mistral, Groq, Together, Fireworks, OpenRouter, xAI, Z.ai/Zhipu (GLM), MiniMax,
Perplexity, Cerebras, SambaNova, NVIDIA NIM, DeepInfra and Nebius all emit the
exact OpenAI tool-call shape
(``{"id","type":"function","function":{"name","arguments":"<json>"}}``), so they
reuse ``parse_openai`` verbatim — a pure alias onto ``OPENAI_TOOL_CALL``, no new
wire shape.

``zhipu`` and ``glm`` are BOTH bound (platform name and model-family name are both
in live use) — as separate exact strings, never as an alias: MCPIP does not
casefold, alias, or sniff, so each id is its own pinned entry.

Frontier labs with their own binding module (OpenAI/Azure, Copilot, DeepSeek, Qwen,
ERNIE, Kimi/Moonshot), self-hosted runtimes (``local_runtime``), enterprise data
platforms (``enterprise_ai``) and routers (``llm_gateway``) live elsewhere; this
module groups the remaining third-party inference clouds.

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
    "zhipu",
    "glm",
    "minimax",
    "perplexity",
    "cerebras",
    "sambanova",
    "nvidia_nim",
    "deepinfra",
    "nebius",
)
SOURCE_FORMAT: Final[SourceFormat] = SourceFormat.OPENAI_TOOL_CALL
PARSER: Final[FormatParser] = formats.parse_openai
