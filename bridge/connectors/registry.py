"""
MCPIP V2 — Connectors: the version-pinned vendor→format registry.

    ◐ "Format is DECLARED, never sniffed — same discipline as pinning the JWT alg."

A Python constant, HASH-PINNED at import, never hot-reloaded — this table decides
what gets authorized, so it changes only via code review + a deliberate
``REGISTRY_VERSION`` bump and re-pin. Every import-time self-check failure is a
``RuntimeError`` → fail-closed boot: a gateway with an inconsistent connector
table refuses to serve at all.

Lookups are fail-closed both ways:
  * an unknown vendor string  → ``UnknownVendor``  → DenyReason.UNKNOWN_VENDOR
  * an unmapped source format → ``UnknownFormat``  → DenyReason.UNKNOWN_FORMAT
"""

from __future__ import annotations

import sys
from enum import Enum
from typing import Final

from bridge.connectors import (
    a2a,
    bedrock,
    claude,
    copilot,
    deepseek,
    enterprise_ai,
    ernie,
    formats,
    gemini,
    kimi,
    llm_gateway,
    local_runtime,
    mcp_framework,
    mcp_platform,
    mcp_standard,
    openai,
    openai_compatible,
    qwen,
)
from bridge.connectors.base import FormatParser
from bridge.errors import UnknownFormat, UnknownVendor
from interfaces import SourceFormat, canonical_json, sha256_hex


class Vendor(str, Enum):
    """Every vendor id the registry may bind. Exact strings — no aliasing."""

    OPENAI = "openai"
    AZURE_OPENAI = "azure_openai"
    COPILOT = "copilot"
    DEEPSEEK = "deepseek"
    QWEN = "qwen"
    ERNIE = "ernie"
    KIMI = "kimi"
    MOONSHOT = "moonshot"
    # OpenAI-compatible third-party model providers (same tool-call shape).
    MISTRAL = "mistral"
    GROQ = "groq"
    TOGETHER = "together"
    FIREWORKS = "fireworks"
    OPENROUTER = "openrouter"
    XAI = "xai"
    ZHIPU = "zhipu"
    GLM = "glm"
    MINIMAX = "minimax"
    PERPLEXITY = "perplexity"
    CEREBRAS = "cerebras"
    SAMBANOVA = "sambanova"
    NVIDIA_NIM = "nvidia_nim"
    DEEPINFRA = "deepinfra"
    NEBIUS = "nebius"
    # Self-hosted OpenAI-compatible inference runtimes (the air-gapped path).
    OLLAMA = "ollama"
    VLLM = "vllm"
    SGLANG = "sglang"
    LLAMA_CPP = "llama_cpp"
    LMSTUDIO = "lmstudio"
    TGI = "tgi"
    LOCALAI = "localai"
    # Enterprise data-platform model endpoints (OpenAI-compatible chat surface).
    DATABRICKS = "databricks"
    WATSONX = "watsonx"
    SNOWFLAKE_CORTEX = "snowflake_cortex"
    # LLM gateways / routers that re-emit the OpenAI tool-call shape.
    LITELLM = "litellm"
    PORTKEY = "portkey"
    CLOUDFLARE_WORKERS_AI = "cloudflare_workers_ai"
    VERCEL_AI_GATEWAY = "vercel_ai_gateway"
    GITHUB_MODELS = "github_models"
    # Anthropic tool_use — the model, incl. its Bedrock- and Vertex-hosted forms.
    CLAUDE = "claude"
    CLAUDE_BEDROCK = "claude_bedrock"
    CLAUDE_VERTEX = "claude_vertex"
    BEDROCK = "bedrock"
    GEMINI = "gemini"
    VERTEX = "vertex"
    MCP = "mcp"
    CLAUDE_CODE = "claude_code"
    CURSOR = "cursor"
    WINDSURF = "windsurf"
    # Coding-agent MCP hosts + OpenClaw's MCP passthrough (standard JSON-RPC).
    CLINE = "cline"
    OPENCODE = "opencode"
    GOOSE = "goose"
    OPENHANDS = "openhands"
    OPENCLAW = "openclaw"
    # Editors / IDEs / terminals that ship a first-party MCP client.
    ZED = "zed"
    VSCODE = "vscode"
    JETBRAINS = "jetbrains"
    CONTINUE = "continue"
    ROO = "roo"
    KILOCODE = "kilocode"
    CODEX = "codex"
    GEMINI_CLI = "gemini_cli"
    AMP = "amp"
    CRUSH = "crush"
    WARP = "warp"
    # Assistant surfaces + automation platforms acting as MCP clients.
    CHATGPT = "chatgpt"
    COPILOT_STUDIO = "copilot_studio"
    LIBRECHAT = "librechat"
    OPENWEBUI = "openwebui"
    N8N = "n8n"
    DIFY = "dify"
    LANGFLOW = "langflow"
    FLOWISE = "flowise"
    # Agent frameworks acting as MCP clients.
    LANGGRAPH = "langgraph"
    CREWAI = "crewai"
    AUTOGEN = "autogen"
    OPENAI_AGENTS = "openai_agents"
    PYDANTIC_AI = "pydantic_ai"
    LLAMAINDEX = "llamaindex"
    SEMANTIC_KERNEL = "semantic_kernel"
    MASTRA = "mastra"
    STRANDS = "strands"
    # A2A (Agent-to-Agent) task envelope — the 7th SOURCE_FORMAT, added as a
    # DELIBERATE vendor-mapped connector wave (the conscious registry re-pin below).
    A2A = "a2a"


REGISTRY_VERSION: Final[str] = "4"

# Format → parser table. RAW_MCP is legacy and NOT vendor-mapped (frozen ingress).
_PARSER_FOR: Final[dict[SourceFormat, FormatParser]] = {
    SourceFormat.OPENAI_TOOL_CALL: formats.parse_openai,
    SourceFormat.ANTHROPIC_TOOL_USE: formats.parse_anthropic,
    SourceFormat.GEMINI_FUNCTION_CALL: formats.parse_gemini,
    SourceFormat.BEDROCK_TOOL_USE: formats.parse_bedrock,
    SourceFormat.MCP_JSONRPC: formats.parse_mcp,
    SourceFormat.RAW_MCP: formats.parse_raw_mcp,             # legacy, not vendor-mapped
    SourceFormat.A2A_TASK: formats.parse_a2a_task,
}

# The vendor bindings — each contributes (VENDORS, SOURCE_FORMAT, PARSER).
_BINDINGS: Final[tuple[tuple[tuple[str, ...], SourceFormat, FormatParser], ...]] = (
    (openai.VENDORS, openai.SOURCE_FORMAT, openai.PARSER),
    (openai_compatible.VENDORS, openai_compatible.SOURCE_FORMAT, openai_compatible.PARSER),
    (copilot.VENDORS, copilot.SOURCE_FORMAT, copilot.PARSER),
    (deepseek.VENDORS, deepseek.SOURCE_FORMAT, deepseek.PARSER),
    (qwen.VENDORS, qwen.SOURCE_FORMAT, qwen.PARSER),
    (ernie.VENDORS, ernie.SOURCE_FORMAT, ernie.PARSER),
    (kimi.VENDORS, kimi.SOURCE_FORMAT, kimi.PARSER),
    (local_runtime.VENDORS, local_runtime.SOURCE_FORMAT, local_runtime.PARSER),
    (enterprise_ai.VENDORS, enterprise_ai.SOURCE_FORMAT, enterprise_ai.PARSER),
    (llm_gateway.VENDORS, llm_gateway.SOURCE_FORMAT, llm_gateway.PARSER),
    (claude.VENDORS, claude.SOURCE_FORMAT, claude.PARSER),
    (bedrock.VENDORS, bedrock.SOURCE_FORMAT, bedrock.PARSER),
    (gemini.VENDORS, gemini.SOURCE_FORMAT, gemini.PARSER),
    (mcp_standard.VENDORS, mcp_standard.SOURCE_FORMAT, mcp_standard.PARSER),
    (mcp_platform.VENDORS, mcp_platform.SOURCE_FORMAT, mcp_platform.PARSER),
    (mcp_framework.VENDORS, mcp_framework.SOURCE_FORMAT, mcp_framework.PARSER),
    (a2a.VENDORS, a2a.SOURCE_FORMAT, a2a.PARSER),
)


def _assemble_vendor_format() -> dict[Vendor, SourceFormat]:
    """Build VENDOR_FORMAT from the vendor modules with fail-closed self-checks."""
    assembled: dict[Vendor, SourceFormat] = {}
    seen: set[str] = set()
    for vendors, source_format, parser in _BINDINGS:
        if parser is not _PARSER_FOR[source_format]:
            raise RuntimeError(
                f"connector registry: parser mismatch for {source_format.value}"
            )
        for vendor_string in vendors:
            if vendor_string in seen:
                raise RuntimeError(
                    f"connector registry: vendor '{vendor_string}' bound twice"
                )
            seen.add(vendor_string)
            assembled[Vendor(vendor_string)] = source_format
    if seen != {v.value for v in Vendor}:
        raise RuntimeError(
            "connector registry: vendor bindings do not cover the Vendor enum exactly"
        )
    return assembled


VENDOR_FORMAT: Final[dict[Vendor, SourceFormat]] = _assemble_vendor_format()

# --- Hash pin: any mapping edit without a deliberate pin + REGISTRY_VERSION bump ---
# refuses to boot. Computed over the canonical JSON of the value-string mapping,
# reusing the engine's canonical_json/sha256_hex so the pin is byte-exact stable.
#
# v3 → v4 (DELIBERATE re-pin, connector-coverage wave): 27 → 82 vendor ids.
# Added Kimi/Moonshot; the remaining popular OpenAI-compatible inference clouds;
# self-hosted runtimes (Ollama/vLLM/SGLang/llama.cpp/LM Studio/TGI/LocalAI);
# enterprise platforms (Databricks/watsonx/Snowflake Cortex); LLM gateways
# (LiteLLM/Portkey/Workers AI/Vercel/GitHub Models); `claude_vertex`; and the
# editors, assistant platforms and agent frameworks that ship an MCP client.
# EVERY addition is a pure alias onto an EXISTING parser — no new wire shape, no
# new parsing code, and no change to any pre-existing vendor→format binding.
_PINNED_REGISTRY_SHA256: Final[str] = (
    "c755c47019d17271f2b1a8ccd30ff2020dc0b27beaa0466e1f3a49fbcafb622a"
)
REGISTRY_SHA256: Final[str] = sha256_hex(
    canonical_json({v.value: f.value for v, f in VENDOR_FORMAT.items()})
)
if REGISTRY_SHA256 != _PINNED_REGISTRY_SHA256:
    raise RuntimeError(
        "connector registry: vendor→format mapping does not match the pinned "
        f"sha256 for REGISTRY_VERSION={REGISTRY_VERSION}; a mapping edit requires "
        "a deliberate re-pin + version bump"
    )

print(
    f"MCPIP connector registry v{REGISTRY_VERSION} sha256={REGISTRY_SHA256}",
    file=sys.stderr,
)


def resolve_vendor(vendor: str) -> SourceFormat:
    """Exact-match only — no casefolding, no aliasing, no sniffing."""
    try:
        return VENDOR_FORMAT[Vendor(vendor)]
    except ValueError as exc:
        raise UnknownVendor(f"no connector registered for vendor '{vendor}'") from exc


def parser_for(source_format: SourceFormat) -> FormatParser:
    """Fail-closed parser lookup for a DECLARED source format."""
    parser = _PARSER_FOR.get(source_format)
    if parser is None:
        raise UnknownFormat(f"unsupported source_format {source_format!r}")
    return parser


__all__ = [
    "Vendor",
    "REGISTRY_VERSION",
    "REGISTRY_SHA256",
    "VENDOR_FORMAT",
    "resolve_vendor",
    "parser_for",
]
