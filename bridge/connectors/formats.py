"""
MCPIP V2 — Connectors: the real format parsers (strict ingress models + extraction).

    ◐ "Five wire shapes, one strict boundary — parsers extract, NormalizedIntent decides."

Every parser here is a PURE PARSER of a tool-call shape. It MUST NOT hold any
LLM/vendor API key, MUST NOT call any LLM/vendor API, MUST NOT open any outbound
network connection (mechanically enforced by the conformance purity guard). Parsers
do extraction and shape-matching ONLY — they never walk, sanitize, NFC-normalize,
or size-check ``arguments``. The ONE validation authority is ``NormalizedIntent``
(whose validator runs ``enforce_argument_safety``): depth <= 8, node ceiling,
canonical 16 KiB cap, unicode scrubbing, and the identity-injection hard-deny all
run on the candidate this module produces, in a SINGLE place.

Import discipline (load-bearing): this module imports only from ``interfaces``,
``bridge.errors``, ``bridge.connectors.base``, ``json``, ``typing``, ``pydantic`` —
NEVER from ``bridge.intent_parser`` (that is the cycle the exception move breaks).
"""

from __future__ import annotations

import json
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator

from bridge.connectors.base import Candidate
from bridge.errors import SizeExceeded, UnknownFormat
from interfaces import (
    MAX_A2A_META_BYTES,
    MAX_A2A_PARTS,
    MAX_CANONICAL_BYTES,
    SourceFormat,
    canonical_json,
    reject_unsafe_string,
)

# ---------------------------------------------------------------------------
# §4.0  Raw-input byte ceiling — the pre-parse DoS gate.
# ---------------------------------------------------------------------------
#
# MAX_CANONICAL_BYTES bounds the *canonical* encoding, but that check only runs
# AFTER the full json.loads + recursive walk have already allocated and traversed
# the payload. A raw JSON string can be far larger than its canonical form (raw
# whitespace, redundant escaping, pretty-printing), so we cap the RAW arguments
# string BEFORE it is decoded. The 4× headroom over MAX_CANONICAL_BYTES tolerates
# legitimate escaping/whitespace expansion while still rejecting the multi-MB / GB
# inputs an attacker would use to force json.loads to exhaust CPU/memory.
MAX_RAW_ARGUMENTS_BYTES: int = MAX_CANONICAL_BYTES * 4


# ---------------------------------------------------------------------------
# §4.1–4.3  Per-provider strict ingress models (legacy trio, moved verbatim).
# ---------------------------------------------------------------------------


class _OpenAIFunction(BaseModel):
    """Inner ``function`` object of an OpenAI tool_call."""

    model_config = ConfigDict(extra="forbid", strict=True)

    name: str
    # A JSON *string* per the OpenAI wire format. The hard length cap is the
    # pre-parse DoS gate (§4.0): Pydantic rejects an oversize string during
    # model_validate, BEFORE json.loads / the recursive walk ever allocate it.
    arguments: str = Field(max_length=MAX_RAW_ARGUMENTS_BYTES)


class OpenAIToolCall(BaseModel):
    """OpenAI ``{"id","type":"function","function":{name,arguments}}`` (§4.1)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    id: str
    type: Literal["function"]
    function: _OpenAIFunction


class AnthropicToolUse(BaseModel):
    """Anthropic ``{"type":"tool_use","id","name","input"}`` (§4.2)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    type: Literal["tool_use"]
    id: str
    name: str
    input: dict[str, Any]


class RawMCPCall(BaseModel):
    """Canonical raw JSON-MCP ``{"tool","arguments"}`` (§4.3)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    tool: str
    arguments: dict[str, Any]


# ---------------------------------------------------------------------------
# Gemini — the bare {"functionCall": ...} part object (gemini / vertex).
# ---------------------------------------------------------------------------


class _GeminiFunctionCall(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str
    # Gemini omits args for zero-argument functions; None normalizes to {}.
    args: Optional[dict[str, Any]] = None
    # Newer Gemini API versions attach a call id for parallel calls; accepted
    # and DISCARDED (never enters arguments), mirroring OpenAI's ignored id.
    id: Optional[str] = None


class GeminiFunctionCall(BaseModel):
    """The accepted unit is the bare ``{"functionCall": ...}`` PART object.

    A ``parts`` array, a full ``candidates`` response, or any wrapper fails
    ``extra="forbid"`` → ValidationError → SCHEMA_VIOLATION (one call per request).
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    functionCall: _GeminiFunctionCall


# ---------------------------------------------------------------------------
# Bedrock — the Converse-API native toolUse block.
# PARSE ONLY — MCPIP never calls AWS; no boto3, no credentials, ever.
# ---------------------------------------------------------------------------


class _BedrockToolUse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    # Converse always emits toolUseId; required here and DISCARDED after parse.
    toolUseId: str
    name: str
    input: dict[str, Any]


class BedrockToolUse(BaseModel):
    """Bedrock Converse ``{"toolUse":{toolUseId,name,input}}`` block."""

    model_config = ConfigDict(extra="forbid", strict=True)

    toolUse: _BedrockToolUse


# ---------------------------------------------------------------------------
# MCP — JSON-RPC 2.0 tools/call (mcp / claude_code / cursor / windsurf).
# ---------------------------------------------------------------------------


class _MCPCallParams(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str
    # The MCP spec marks arguments optional; absent normalizes to {}.
    arguments: Optional[dict[str, Any]] = None
    # Protocol plumbing (progressToken etc.). Accepted and DISCARDED — it is
    # NOT tool arguments, never merged, never forwarded, never normalized.
    # Real MCP clients (Claude Code, Cursor) attach _meta.progressToken on
    # tools/call; rejecting it would break "works out of the box". Safe to
    # discard because it never enters ``arguments`` — identity keys inside
    # _meta are inert (the identity-injection hard-deny applies to arguments;
    # _meta is transport plumbing outside the authorized payload and outside
    # the payload-lock hash).
    field_meta: Optional[dict[str, Any]] = Field(default=None, alias="_meta")


class MCPToolsCall(BaseModel):
    """JSON-RPC 2.0 ``tools/call`` request — the MCP-native wire unit."""

    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=False)

    jsonrpc: Literal["2.0"]
    id: Union[str, int]          # tools/call is a request, never a notification.
    method: Literal["tools/call"]
    params: _MCPCallParams


# ---------------------------------------------------------------------------
# The parsers — one raw wire dict -> one Candidate. NOTHING else.
# ---------------------------------------------------------------------------


def parse_openai(raw: dict[str, Any]) -> Candidate:
    """OpenAI tool_call — reused by openai/azure_openai/copilot/deepseek/qwen/ernie.

    Stringified-args discipline: the string is length-capped by Pydantic BEFORE
    ``json.loads`` (pre-parse gate), decoded exactly once, then the decoded object
    is re-fed through the one strict validator by way of
    ``NormalizedIntent._validate_arguments`` → ``enforce_argument_safety``.
    Error strings are FROZEN (regression bar).
    """
    model = OpenAIToolCall.model_validate(raw)
    try:
        decoded = json.loads(model.function.arguments)
    except (json.JSONDecodeError, TypeError) as exc:
        raise UnknownFormat("openai arguments is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise UnknownFormat("openai arguments JSON must be an object")
    return Candidate(model.function.name, decoded, SourceFormat.OPENAI_TOOL_CALL)


def parse_anthropic(raw: dict[str, Any]) -> Candidate:
    """Anthropic tool_use — claude and claude_bedrock (Bedrock-hosted Claude emits
    the identical ``tool_use`` block)."""
    model = AnthropicToolUse.model_validate(raw)
    return Candidate(model.name, model.input, SourceFormat.ANTHROPIC_TOOL_USE)


def parse_gemini(raw: dict[str, Any]) -> Candidate:
    """Gemini functionCall part — gemini and vertex."""
    model = GeminiFunctionCall.model_validate(raw)
    return Candidate(
        model.functionCall.name,
        model.functionCall.args if model.functionCall.args is not None else {},
        SourceFormat.GEMINI_FUNCTION_CALL,
    )


def parse_bedrock(raw: dict[str, Any]) -> Candidate:
    """Bedrock Converse toolUse block.

    # PARSE ONLY — MCPIP never calls AWS; no boto3, no credentials, ever.
    """
    model = BedrockToolUse.model_validate(raw)
    return Candidate(model.toolUse.name, model.toolUse.input, SourceFormat.BEDROCK_TOOL_USE)


def parse_mcp(raw: dict[str, Any]) -> Candidate:
    """JSON-RPC 2.0 tools/call — mcp/claude_code/cursor/windsurf."""
    model = MCPToolsCall.model_validate(raw)
    return Candidate(
        model.params.name,
        model.params.arguments if model.params.arguments is not None else {},
        SourceFormat.MCP_JSONRPC,
    )


def parse_raw_mcp(raw: dict[str, Any]) -> Candidate:
    """Legacy canonical raw JSON-MCP — not vendor-mapped, kept for the frozen
    ``RAW_MCP`` ingress."""
    model = RawMCPCall.model_validate(raw)
    return Candidate(model.tool, model.arguments, SourceFormat.RAW_MCP)


# ---------------------------------------------------------------------------
# A2A — the Agent-to-Agent Task envelope (kind='task' → single DataPart invoke).
#
# MCPIP does NOT sit on the A2A message bus and does NOT dial A2A. It gates the
# ONE side-effecting alias call a governed identity proposes, normalizing a
# representative A2A Task envelope (grounded in the A2A v1.0.1 data model:
# Task / Message / Part, where a DataPart carries structured JSON) into the SAME
# NormalizedIntent every other dialect produces. PURE PARSER — no SDK, no network,
# no A2A client. One invocation per request: EXACTLY one DataPart carrying
# {skill:<alias>, arguments:{...}}; anything else fails the strict extra="forbid"
# ingress models → SCHEMA_VIOLATION.
# ---------------------------------------------------------------------------


class _A2ASkillInvocation(BaseModel):
    """The DataPart ``data`` payload — the side-effecting skill invocation.

    ``skill`` is the opaque MCPIP alias; ``arguments`` is the tool-call arguments
    object (absent → {} like MCP/Gemini). ``extra="forbid"`` means any OTHER key at
    this level (e.g. a smuggled ``actor``/``sub``) is a SCHEMA_VIOLATION — identity
    lives ONLY in the verified JWT, never in the invocation body. (An identity-shaped
    key *inside* ``arguments`` is caught one layer down by the unchanged
    ``enforce_argument_safety`` hard-deny → IDENTITY_INJECTION.)
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    skill: str
    arguments: Optional[dict[str, Any]] = None


class _A2ADataPart(BaseModel):
    """A single A2A ``DataPart`` — ``kind='data'`` carrying structured JSON.

    A non-data part (``kind='text'``/``'file'``) fails the ``Literal['data']`` →
    ValidationError → SCHEMA_VIOLATION: MCPIP gates a structured skill invocation,
    not free text.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    kind: Literal["data"]
    data: _A2ASkillInvocation


class _A2AStatus(BaseModel):
    """The Task ``status`` object — its ``state`` is recorded-not-authorizing."""

    model_config = ConfigDict(extra="forbid", strict=True)

    state: str


class _A2AMessage(BaseModel):
    """The A2A ``Message`` carried by the Task.

    ``parts`` is bounded to EXACTLY ``MAX_A2A_PARTS`` (=1) entries via the field
    length bounds, so 0 or >1 parts fail validation → SCHEMA_VIOLATION (one
    invocation per request). ``metadata`` is the DECLARED, UNVERIFIED actor/
    delegation channel — recorded-not-trusted, never merged into arguments.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    kind: Literal["message"]
    role: str
    messageId: str
    parts: list[_A2ADataPart] = Field(min_length=1, max_length=MAX_A2A_PARTS)
    metadata: Optional[dict[str, Any]] = None

    @field_validator("messageId")
    @classmethod
    def _scrub_message_id(cls, value: str) -> str:
        # Charset-scrub the recorded-not-trusted id before it can reach the signed WORM
        # record; a ValueError here → ValidationError → SCHEMA_VIOLATION (fail-closed).
        return reject_unsafe_string(value, "a2a_message_id")

    @field_validator("metadata")
    @classmethod
    def _scrub_metadata(
        cls, value: Optional[dict[str, Any]]
    ) -> Optional[dict[str, Any]]:
        # The metadata is recorded-not-trusted and may legitimately DECLARE an actor/
        # principal, so the identity hard-deny is NOT applied — but its BYTES must still be
        # charset-safe (control/bidi/ANSI) before they land in the signed audit log.
        if value is not None:
            # Bound the SERIALIZED size BEFORE the recursive charset walk (mirrors
            # RegistryServerJson._scrub_meta) so an oversized metadata object can never
            # drive an unbounded recursive traversal — over-cap → ValueError →
            # SCHEMA_VIOLATION (fail-closed). The authoritative MAX_A2A_META_BYTES gate in
            # parse_a2a_task still applies; this is the pre-recursion guard.
            if len(json.dumps(value, ensure_ascii=False).encode("utf-8")) > MAX_A2A_META_BYTES:
                raise ValueError("a2a metadata exceeds the size cap")
            _a2a_charset_scrub(value)
        return value


class A2ATaskEnvelope(BaseModel):
    """A top-level A2A ``Task`` envelope carrying one side-effecting invocation.

    The whole envelope is strict/``extra="forbid"``: any extra key at any level, a
    wrong ``kind``, a non-data part, or >1 part is a SCHEMA_VIOLATION. Extraction is
    ``message.parts[0].data.skill`` → alias and ``.data.arguments`` → arguments; the
    task/context/message IDs + declared ``metadata`` are packed into a separate,
    non-locked ``a2a_context`` channel (WORM correlation only).
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    kind: Literal["task"]
    id: str
    contextId: str
    status: _A2AStatus
    message: _A2AMessage

    @field_validator("id", "contextId")
    @classmethod
    def _scrub_ids(cls, value: str) -> str:
        # Charset-scrub the recorded-not-trusted task/context ids (→ SCHEMA_VIOLATION on an
        # unsafe byte) so they cannot smuggle a terminal-escape into the signed WORM record.
        return reject_unsafe_string(value, "a2a_id")


def _a2a_charset_scrub(node: Any) -> None:
    """Recursively charset-scrub every string key/value in the recorded-not-trusted A2A
    metadata (``reject_unsafe_string`` — Cc/Cf/Zl/Zp + bidi/format-mark reject), raising
    ``ValueError`` (→ SCHEMA_VIOLATION upstream) on any unsafe character. This is the CHARSET
    guard only; the identity hard-deny is deliberately NOT applied (metadata may legitimately
    declare an actor/principal — recorded, never trusted). The caller (``_scrub_metadata``)
    bounds the serialized size BEFORE invoking this walk, so recursion is bounded and safe."""
    if isinstance(node, str):
        reject_unsafe_string(node, "a2a_metadata")
    elif isinstance(node, dict):
        for key, sub in node.items():
            if isinstance(key, str):
                reject_unsafe_string(key, "a2a_metadata_key")
            _a2a_charset_scrub(sub)
    elif isinstance(node, (list, tuple)):
        for sub in node:
            _a2a_charset_scrub(sub)


def parse_a2a_task(raw: dict[str, Any]) -> Candidate:
    """A2A Task envelope → Candidate (7th dialect).

    PURE: extraction + shape-matching only. ``data.arguments`` flows through the
    UNCHANGED ``enforce_argument_safety`` / ``canonical_json`` / payload-lock exactly
    as every other dialect — the A2A shape only changes WHERE (alias, arguments) come
    from, so the same (alias, arguments) yields a byte-identical lock hash regardless
    of dialect. The task/context/message IDs + declared (unverified) metadata are
    packed into the non-locked ``a2a_context`` channel; the metadata envelope is
    size-bounded (``MAX_A2A_META_BYTES``) so an untrusted document cannot smuggle
    unbounded provenance into the audit log. Metadata is RECORDED-NOT-TRUSTED: it is
    NEVER merged into arguments (so an identity/actor claim there is inert), never
    authorizes, and never crosses the agent wire.
    """
    model = A2ATaskEnvelope.model_validate(raw)
    invocation = model.message.parts[0].data
    arguments = invocation.arguments if invocation.arguments is not None else {}

    # The task/context/message ids + declared metadata were charset-scrubbed at model
    # validation (``reject_unsafe_string`` field validators → SCHEMA_VIOLATION on any
    # control/bidi/ANSI byte), so they are safe to pack into the recorded-not-trusted
    # a2a_context here. The identity hard-deny is deliberately NOT applied to metadata (it
    # may legitimately declare an actor/principal — recorded, never trusted).
    a2a_context: dict[str, Any] = {
        "task_id": model.id,
        "context_id": model.contextId,
        "message_id": model.message.messageId,
    }
    metadata = model.message.metadata
    if metadata is not None:
        # Size-bound the recorded-not-trusted metadata envelope (canonical bytes) — a
        # PROVENANCE bound so an untrusted document cannot smuggle unbounded provenance into
        # the audit log.
        if len(canonical_json(metadata)) > MAX_A2A_META_BYTES:
            raise SizeExceeded(
                f"a2a message metadata exceeds MAX_A2A_META_BYTES={MAX_A2A_META_BYTES}"
            )
        a2a_context["metadata"] = metadata

    return Candidate(
        invocation.skill,
        arguments,
        SourceFormat.A2A_TASK,
        a2a_context,
    )


__all__ = [
    "MAX_RAW_ARGUMENTS_BYTES",
    "OpenAIToolCall",
    "AnthropicToolUse",
    "RawMCPCall",
    "GeminiFunctionCall",
    "BedrockToolUse",
    "MCPToolsCall",
    "A2ATaskEnvelope",
    "parse_openai",
    "parse_anthropic",
    "parse_gemini",
    "parse_bedrock",
    "parse_mcp",
    "parse_raw_mcp",
    "parse_a2a_task",
]
