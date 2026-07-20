"""
MCPIP V2 — Bridge package.

    ◐ Bridge: "One ingress for every agent framework — OpenAI, Anthropic, raw MCP."

Re-exports the Bridge public API: the ``parse`` entrypoint, the shared
argument-safety walker, and the narrow exception types the gateway maps to
DenyReason.
"""

from __future__ import annotations

from bridge.intent_parser import (
    AnthropicToolUse,
    DepthExceeded,
    IdentityInjection,
    OpenAIToolCall,
    RawMCPCall,
    SizeExceeded,
    UnknownFormat,
    enforce_argument_safety,
    parse,
)

__all__ = [
    "parse",
    "enforce_argument_safety",
    "UnknownFormat",
    "IdentityInjection",
    "DepthExceeded",
    "SizeExceeded",
    "OpenAIToolCall",
    "AnthropicToolUse",
    "RawMCPCall",
]
