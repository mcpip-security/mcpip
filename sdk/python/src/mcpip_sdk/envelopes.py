"""
mcpip_sdk.envelopes — provider tool-call envelope builders.

The gateway's Bridge deep-validates each provider dialect with STRICT models
(``bridge/connectors/formats.py``): unknown keys, missing ids, or non-object
arguments are hard 422s. These builders encode each dialect's exact accepted
shape so callers never hand-roll envelopes. ``MCPIPClient.authorize`` uses
:func:`build` when given a bare ``(alias, arguments)`` pair.

The format is DECLARED, never sniffed — the ``source_format`` string sent with
the envelope must match one of :data:`SOURCE_FORMATS` (byte-identical to the
gateway's ``interfaces.SourceFormat`` values).
"""

from __future__ import annotations

import json
from typing import Any, Final, Mapping

OPENAI_TOOL_CALL: Final[str] = "openai_tool_call"
ANTHROPIC_TOOL_USE: Final[str] = "anthropic_tool_use"
GEMINI_FUNCTION_CALL: Final[str] = "gemini_function_call"
BEDROCK_TOOL_USE: Final[str] = "bedrock_tool_use"
MCP_JSONRPC: Final[str] = "mcp_jsonrpc"
RAW_MCP: Final[str] = "raw_mcp"
A2A_TASK: Final[str] = "a2a_task"

SOURCE_FORMATS: Final[tuple[str, ...]] = (
    OPENAI_TOOL_CALL,
    ANTHROPIC_TOOL_USE,
    GEMINI_FUNCTION_CALL,
    BEDROCK_TOOL_USE,
    MCP_JSONRPC,
    RAW_MCP,
    A2A_TASK,
)


def openai_tool_call(
    alias: str, arguments: Mapping[str, Any], *, call_id: str = "call_mcpip_sdk"
) -> dict[str, Any]:
    """OpenAI ``{"id","type":"function","function":{name,arguments}}`` — the
    arguments are a JSON *string* per the OpenAI wire format."""
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": alias, "arguments": json.dumps(dict(arguments))},
    }


def anthropic_tool_use(
    alias: str, arguments: Mapping[str, Any], *, call_id: str = "toolu_mcpip_sdk"
) -> dict[str, Any]:
    """Anthropic ``{"type":"tool_use","id","name","input"}``."""
    return {"type": "tool_use", "id": call_id, "name": alias, "input": dict(arguments)}


def gemini_function_call(alias: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Gemini — the bare ``{"functionCall": {name, args}}`` PART object (a
    ``parts`` array or full candidate response is rejected server-side)."""
    return {"functionCall": {"name": alias, "args": dict(arguments)}}


def bedrock_tool_use(
    alias: str, arguments: Mapping[str, Any], *, call_id: str = "mcpip-sdk-tooluse"
) -> dict[str, Any]:
    """Bedrock Converse ``{"toolUse": {toolUseId, name, input}}`` block."""
    return {"toolUse": {"toolUseId": call_id, "name": alias, "input": dict(arguments)}}


def mcp_tools_call(
    alias: str, arguments: Mapping[str, Any], *, request_id: int | str = 1
) -> dict[str, Any]:
    """JSON-RPC 2.0 ``tools/call`` — the MCP-native wire unit (also the shape
    to resubmit on ``/v1/authorize`` when completing a step-up that was staged
    via the ``/v1/mcp`` edge)."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": alias, "arguments": dict(arguments)},
    }


def raw_mcp(alias: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Canonical raw JSON-MCP ``{"tool","arguments"}`` — the gateway's own
    minimal frozen ingress; the SDK's default envelope."""
    return {"tool": alias, "arguments": dict(arguments)}


def a2a_task(
    alias: str,
    arguments: Mapping[str, Any],
    *,
    task_id: str = "mcpip-sdk-task",
    context_id: str = "mcpip-sdk-ctx",
    message_id: str = "mcpip-sdk-msg",
) -> dict[str, Any]:
    """A2A ``Task`` envelope carrying EXACTLY ONE ``DataPart`` skill invocation.

    MCPIP does not sit on the A2A message bus — it gates the single
    side-effecting call a governed identity proposes, so the accepted envelope
    is deliberately narrow: one message, one data part, ``{skill, arguments}``.
    A task carrying zero or several invocations is a hard 422, not a guess."""
    return {
        "kind": "task",
        "id": task_id,
        "contextId": context_id,
        "status": {"state": "submitted"},
        "message": {
            "kind": "message",
            "role": "agent",
            "messageId": message_id,
            "parts": [
                {"kind": "data", "data": {"skill": alias, "arguments": dict(arguments)}}
            ],
        },
    }


def build(source_format: str, alias: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Build the ``tool_call`` dict for ``source_format`` — ValueError on an
    unknown format (fail fast client-side; the gateway would 422)."""
    if source_format == OPENAI_TOOL_CALL:
        return openai_tool_call(alias, arguments)
    if source_format == ANTHROPIC_TOOL_USE:
        return anthropic_tool_use(alias, arguments)
    if source_format == GEMINI_FUNCTION_CALL:
        return gemini_function_call(alias, arguments)
    if source_format == BEDROCK_TOOL_USE:
        return bedrock_tool_use(alias, arguments)
    if source_format == MCP_JSONRPC:
        return mcp_tools_call(alias, arguments)
    if source_format == RAW_MCP:
        return raw_mcp(alias, arguments)
    if source_format == A2A_TASK:
        return a2a_task(alias, arguments)
    raise ValueError(
        f"unknown source_format {source_format!r} — expected one of {SOURCE_FORMATS}"
    )


__all__ = [
    "OPENAI_TOOL_CALL",
    "ANTHROPIC_TOOL_USE",
    "GEMINI_FUNCTION_CALL",
    "BEDROCK_TOOL_USE",
    "MCP_JSONRPC",
    "RAW_MCP",
    "A2A_TASK",
    "SOURCE_FORMATS",
    "openai_tool_call",
    "anthropic_tool_use",
    "gemini_function_call",
    "bedrock_tool_use",
    "mcp_tools_call",
    "raw_mcp",
    "a2a_task",
    "build",
]
