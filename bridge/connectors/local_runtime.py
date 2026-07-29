"""
MCPIP V2 — Connector binding: self-hosted OpenAI-compatible inference runtimes.

Ollama, vLLM, SGLang, llama.cpp's server, LM Studio, HF text-generation-inference
and LocalAI all serve an OpenAI-compatible ``/v1/chat/completions`` and emit the
exact OpenAI tool-call shape, so they reuse ``parse_openai`` verbatim.

These matter to MCPIP's core deployment story: an AIR-GAPPED operator runs the
model locally and still gets the identical authorization boundary — the gateway
never dials the runtime, it only parses what the runtime's client hands it.

PURE PARSER BINDING — no SDK import, no network, no vendor key. MCPIP parses the
tool-call shape; the end user's client holds the LLM credentials.
"""

from __future__ import annotations

from typing import Final

from bridge.connectors import formats
from bridge.connectors.base import FormatParser
from interfaces import SourceFormat

VENDORS: Final[tuple[str, ...]] = (
    "ollama",
    "vllm",
    "sglang",
    "llama_cpp",
    "lmstudio",
    "tgi",
    "localai",
)
SOURCE_FORMAT: Final[SourceFormat] = SourceFormat.OPENAI_TOOL_CALL
PARSER: Final[FormatParser] = formats.parse_openai
