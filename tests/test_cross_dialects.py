"""
MCPIP — CROSS-DIALECT normalization tests: six wire shapes, one verdict.

    ◐ "The dialect decides only WHERE (alias, arguments) come from — never WHAT
       gets authorized. Prove it byte-for-byte."

The Bridge normalizes any of the provider dialects into a single ``NormalizedIntent``.
This suite pins the load-bearing consequence: two *equivalent* tool calls expressed in
different dialects must be indistinguishable to every downstream stage — identical
alias, byte-identical canonical arguments, byte-identical payload-lock hash, the same
resolved target, and therefore the SAME authorize verdict. And every malformed /
injected / oversized envelope must fail CLOSED in EACH dialect, mapped to the exact
same ``DenyReason`` taxonomy — never a crash, never a partial parse, never a strip.

Design (per the cross-test brief):
  * ENGINE/BRIDGE level only — no HTTP, no lifespan, no Redis round trips, no network.
    ``bridge.parse`` + ``lock_payload_hash`` + an in-memory ``AliasRegistry`` are pure
    functions, so these tests are fast and deterministic.
  * Self-contained: every test that needs identifiers mints fresh ``uuid4`` tenants /
    agents / aliases and builds its own in-memory registry — no clean-db assumption,
    no reliance on the demo catalog's specific rows, no global-count asserts.
  * Each test's docstring names the guarantee it defends.

The six DECLARED provider dialects under test (``interfaces.SourceFormat``):
    openai_tool_call · anthropic_tool_use · gemini_function_call · bedrock_tool_use
    · mcp_jsonrpc · a2a_task
The legacy ``raw_mcp`` ingress is spot-checked for parity too.
"""

from __future__ import annotations

import itertools
import json
import os
import uuid
from typing import Any, Callable, Optional

import pytest

# --- Defensive env preamble (this file makes NO Redis connection, but keeping the
# --- sandbox namespace via setdefault means importing product modules is inert even
# --- if a future import reads settings). Fallback db per the cross-test brief.
os.environ.setdefault("MCPIP_REDIS_URL", "redis://localhost:63790/4")
os.environ.setdefault("MCPIP_SANDBOX_MODE", "true")

import bridge
from auth.pin_validator import lock_payload_hash
from bridge.connectors.registry import (
    REGISTRY_SHA256,
    VENDOR_FORMAT,
    _PINNED_REGISTRY_SHA256,
    parser_for,
    resolve_vendor,
)
from core.security import map_engine_exception
from interfaces import (
    Hop,
    RiskTier,
    SourceFormat,
    SwarmTrace,
    canonical_json,
    sha256_hex,
)
from obfuscator.alias_registry import AliasEntry, AliasRegistry


# ===========================================================================
# Dialect envelope builders — the SAME logical call, in each wire shape.
# ===========================================================================
#
# Each builder takes the opaque alias + the tool-call ``arguments`` object and returns
# the raw wire dict a real client of that dialect would emit. For OpenAI the arguments
# ride as a JSON *string* (its wire contract); every other dialect carries the object
# directly. Unique wire ids (call/tool_use/task/message) are minted with uuid4 so no
# two builds collide — none of these ids enters the payload lock, so they never perturb
# the cross-dialect hash.


def _openai(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "call_" + uuid.uuid4().hex,
        "type": "function",
        "function": {"name": alias, "arguments": json.dumps(arguments)},
    }


def _anthropic(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "tool_use",
        "id": "toolu_" + uuid.uuid4().hex,
        "name": alias,
        "input": arguments,
    }


def _gemini(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {"functionCall": {"name": alias, "args": arguments}}


def _bedrock(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "toolUse": {
            "toolUseId": "tu_" + uuid.uuid4().hex,
            "name": alias,
            "input": arguments,
        }
    }


def _mcp(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": uuid.uuid4().hex,
        "method": "tools/call",
        "params": {"name": alias, "arguments": arguments},
    }


def _a2a(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "task",
        "id": "task-" + uuid.uuid4().hex,
        "contextId": "ctx-" + uuid.uuid4().hex,
        "status": {"state": "submitted"},
        "message": {
            "kind": "message",
            "role": "agent",
            "messageId": "msg-" + uuid.uuid4().hex,
            "parts": [{"kind": "data", "data": {"skill": alias, "arguments": arguments}}],
        },
    }


def _raw_mcp(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {"tool": alias, "arguments": arguments}


Builder = Callable[[str, dict[str, Any]], dict[str, Any]]

# The six provider dialects (order fixed for stable parametrize ids).
DIALECTS: tuple[SourceFormat, ...] = (
    SourceFormat.OPENAI_TOOL_CALL,
    SourceFormat.ANTHROPIC_TOOL_USE,
    SourceFormat.GEMINI_FUNCTION_CALL,
    SourceFormat.BEDROCK_TOOL_USE,
    SourceFormat.MCP_JSONRPC,
    SourceFormat.A2A_TASK,
)

_BUILDERS: dict[SourceFormat, Builder] = {
    SourceFormat.OPENAI_TOOL_CALL: _openai,
    SourceFormat.ANTHROPIC_TOOL_USE: _anthropic,
    SourceFormat.GEMINI_FUNCTION_CALL: _gemini,
    SourceFormat.BEDROCK_TOOL_USE: _bedrock,
    SourceFormat.MCP_JSONRPC: _mcp,
    SourceFormat.A2A_TASK: _a2a,
}

_DIALECT_IDS = [fmt.value for fmt in DIALECTS]

# The reference dialect every cross-dialect equivalence check compares against.
_BASELINE = SourceFormat.MCP_JSONRPC


# ===========================================================================
# Small pure helpers.
# ===========================================================================


def _trace() -> SwarmTrace:
    """A fresh single-hop trace (trace_id must be a unique uuid4 per parse)."""
    return SwarmTrace(
        trace_id=str(uuid.uuid4()),
        hops=[
            Hop(
                hop_index=0,
                agent_id="cross-agent",
                parent_agent_id=None,
                purpose="cross-dialect",
            )
        ],
    )


def _sample_arguments() -> dict[str, Any]:
    """A representative arguments object exercising strings, floats, arrays, nesting
    and non-ASCII (NFC) text — the payload whose canonicalization must be dialect
    independent. Fresh per call (unique invoice id)."""
    return {
        "invoice_id": "INV-" + uuid.uuid4().hex[:8],
        "amount": 1250.5,
        "tags": ["q3", "eu"],
        "detail": {"note": "café ☕"},
    }


def _parse(fmt: SourceFormat, alias: str, arguments: dict[str, Any]) -> Any:
    """Build the dialect envelope and run the REAL bridge parser."""
    return bridge.parse(_BUILDERS[fmt](alias, arguments), fmt, _trace())


def _deny_reason(raw: Any, fmt: SourceFormat) -> str:
    """Parse and assert it FAILS CLOSED; return the mapped DenyReason value.

    Proves both halves of "fail closed, never a partial parse": ``bridge.parse`` must
    raise (never return a NormalizedIntent), and the single ``map_engine_exception``
    funnel must classify it to a concrete taxonomy string (never leak / crash)."""
    try:
        bridge.parse(raw, fmt, _trace())
    except Exception as exc:  # noqa: BLE001 — the funnel is exactly what's under test.
        return map_engine_exception(exc).reason.value
    raise AssertionError(f"{fmt.value}: expected a fail-closed deny, got an intent")


# A closed verdict tuple: ("allow"|"staged"|"deny", reason_or_none, lock_hash_or_none).
Verdict = tuple[str, Optional[str], Optional[str]]


def _engine_verdict(
    fmt: SourceFormat,
    alias: str,
    arguments: dict[str, Any],
    registry: AliasRegistry,
    tenant: str,
    agent: str,
) -> Verdict:
    """Reproduce the dialect-INDEPENDENT slice of the authorize pipeline for an
    un-compartmented alias: Bridge (parse) → Obfuscator (resolve) → Risk gate.

    Every input this consumes downstream of parse — (tenant, agent, alias, arguments) —
    is identity-or-payload, never dialect. So an identical NormalizedIntent yields an
    identical verdict BY CONSTRUCTION; the tests assert that byte-for-byte. Deny reasons
    come from the REAL ``map_engine_exception``; the risk mapping (AUTO→allow /
    PIN_REQUIRED→staged) mirrors pipeline step 9 for the un-compartmented rows used here.
    """
    try:
        intent = bridge.parse(_BUILDERS[fmt](alias, arguments), fmt, _trace())
    except Exception as exc:  # noqa: BLE001
        return ("deny", map_engine_exception(exc).reason.value, None)
    try:
        entry = registry.resolve(tenant, intent.alias)
    except Exception as exc:  # noqa: BLE001
        return ("deny", map_engine_exception(exc).reason.value, None)
    lock = lock_payload_hash(tenant, agent, intent.alias, intent.arguments)
    if entry.risk_tier is RiskTier.PIN_REQUIRED:
        return ("staged", "pin_required", lock)
    return ("allow", None, lock)


def _fresh_registry(
    tenant: str, alias: str, risk: RiskTier = RiskTier.AUTO
) -> AliasRegistry:
    """A one-row in-memory registry (no Redis, no demo seed) — deterministic."""
    reg = AliasRegistry()
    reg.register(
        tenant,
        AliasEntry(alias, "rest." + uuid.uuid4().hex, "cloud_rest", risk),
    )
    return reg


# ===========================================================================
# 1. Cross-dialect NormalizedIntent equivalence.
# ===========================================================================


@pytest.mark.parametrize("fmt", DIALECTS, ids=_DIALECT_IDS)
def test_dialect_normalizes_to_expected_alias_and_arguments(fmt: SourceFormat) -> None:
    """Each dialect extracts the SAME (alias, arguments) and tags its own source_format.

    The one field that legitimately differs by dialect is ``source_format``; alias and
    the (NFC-normalized) arguments are identical to what every other dialect produces."""
    alias = "skill_" + uuid.uuid4().hex
    args = _sample_arguments()
    intent = _parse(fmt, alias, args)
    assert intent.alias == alias
    assert intent.arguments == args
    assert intent.source_format is fmt


def test_all_six_dialects_produce_identical_canonical_arguments() -> None:
    """One logical call in all six dialects → a SINGLE canonical-bytes value.

    The payload-lock hashes exactly these bytes, so byte-identical canonicalization is
    the precondition for a dialect-independent lock."""
    alias = "skill_" + uuid.uuid4().hex
    args = _sample_arguments()
    canon = {canonical_json(_parse(fmt, alias, args).arguments) for fmt in DIALECTS}
    assert len(canon) == 1, f"dialects diverged on canonical arguments: {canon!r}"


def test_all_six_dialects_produce_identical_lock_hash() -> None:
    """register-in-dialect-X ≡ any-dialect: the four-field payload-lock hash
    (tenant, agent, alias, arguments) is byte-identical across every dialect, so a PIN
    lock registered from one dialect is answerable from any other."""
    tenant, agent = "tenant-" + uuid.uuid4().hex, "agent-" + uuid.uuid4().hex
    alias = "skill_" + uuid.uuid4().hex
    args = _sample_arguments()
    hashes = {
        lock_payload_hash(tenant, agent, i.alias, i.arguments)
        for i in (_parse(fmt, alias, args) for fmt in DIALECTS)
    }
    assert len(hashes) == 1, f"dialects diverged on lock hash: {hashes!r}"


def test_all_six_dialects_resolve_to_identical_alias_entry() -> None:
    """The Obfuscator stage is dialect-independent: the same call in every dialect
    resolves to the exact same AliasEntry (target/transport/risk), because resolution
    keys only on the (tenant, alias) that normalization produced identically."""
    tenant = "tenant-" + uuid.uuid4().hex
    alias = "skill_" + uuid.uuid4().hex
    reg = _fresh_registry(tenant, alias)
    args = _sample_arguments()
    entries = [reg.resolve(tenant, _parse(fmt, alias, args).alias) for fmt in DIALECTS]
    assert all(e == entries[0] for e in entries)


def test_raw_mcp_ingress_matches_the_six_dialect_baseline() -> None:
    """The legacy raw_mcp ingress produces the SAME canonical arguments + lock hash as
    the vendor-mapped dialects — the normalization contract spans all seven ingresses."""
    tenant, agent = "tenant-" + uuid.uuid4().hex, "agent-" + uuid.uuid4().hex
    alias = "skill_" + uuid.uuid4().hex
    args = _sample_arguments()
    base = _parse(_BASELINE, alias, args)
    raw = bridge.parse(_raw_mcp(alias, args), SourceFormat.RAW_MCP, _trace())
    assert canonical_json(raw.arguments) == canonical_json(base.arguments)
    assert lock_payload_hash(tenant, agent, raw.alias, raw.arguments) == lock_payload_hash(
        tenant, agent, base.alias, base.arguments
    )


@pytest.mark.parametrize("fmt", DIALECTS, ids=_DIALECT_IDS)
def test_a2a_context_channel_is_populated_only_for_a2a(fmt: SourceFormat) -> None:
    """The non-locked ``a2a_context`` correlation channel exists ONLY on the A2A
    dialect; the other five normalize it to None — so it can never perturb the lock
    tuple or the cross-dialect equivalence the other tests assert."""
    intent = _parse(fmt, "skill_" + uuid.uuid4().hex, _sample_arguments())
    if fmt is SourceFormat.A2A_TASK:
        assert intent.a2a_context is not None
        assert {"task_id", "context_id", "message_id"} <= set(intent.a2a_context)
    else:
        assert intent.a2a_context is None


# ===========================================================================
# 2. Cross-dialect SAME authorize verdict.
# ===========================================================================


@pytest.mark.parametrize("fmt", DIALECTS, ids=_DIALECT_IDS)
def test_verdict_auto_alias_is_identical_across_dialects(fmt: SourceFormat) -> None:
    """An AUTO-tier alias yields an identical ('allow', None, lock) verdict in every
    dialect — same decision AND same payload-lock hash as the mcp baseline."""
    tenant, agent = "tenant-" + uuid.uuid4().hex, "agent-" + uuid.uuid4().hex
    alias = "skill_" + uuid.uuid4().hex
    reg = _fresh_registry(tenant, alias, RiskTier.AUTO)
    args = _sample_arguments()
    baseline = _engine_verdict(_BASELINE, alias, args, reg, tenant, agent)
    assert baseline[0] == "allow"
    assert _engine_verdict(fmt, alias, args, reg, tenant, agent) == baseline


@pytest.mark.parametrize("fmt", DIALECTS, ids=_DIALECT_IDS)
def test_verdict_pin_alias_is_identical_across_dialects(fmt: SourceFormat) -> None:
    """A PIN_REQUIRED alias stages the SAME ('staged', 'pin_required', lock) verdict in
    every dialect — the step-up is bound to a dialect-independent lock hash."""
    tenant, agent = "tenant-" + uuid.uuid4().hex, "agent-" + uuid.uuid4().hex
    alias = "skill_" + uuid.uuid4().hex
    reg = _fresh_registry(tenant, alias, RiskTier.PIN_REQUIRED)
    args = _sample_arguments()
    baseline = _engine_verdict(_BASELINE, alias, args, reg, tenant, agent)
    assert baseline[0] == "staged" and baseline[1] == "pin_required"
    assert _engine_verdict(fmt, alias, args, reg, tenant, agent) == baseline


@pytest.mark.parametrize("fmt", DIALECTS, ids=_DIALECT_IDS)
def test_verdict_unknown_alias_denies_identically_across_dialects(
    fmt: SourceFormat,
) -> None:
    """An alias registered for NOBODY denies UNKNOWN_ALIAS in every dialect."""
    tenant, agent = "tenant-" + uuid.uuid4().hex, "agent-" + uuid.uuid4().hex
    alias = "skill_" + uuid.uuid4().hex  # never registered
    reg = _fresh_registry(tenant, "skill_" + uuid.uuid4().hex)  # a different alias
    args = _sample_arguments()
    verdict = _engine_verdict(fmt, alias, args, reg, tenant, agent)
    assert verdict == ("deny", "unknown_alias", None)


@pytest.mark.parametrize("fmt", DIALECTS, ids=_DIALECT_IDS)
def test_verdict_cross_tenant_denies_identically_across_dialects(
    fmt: SourceFormat,
) -> None:
    """An alias owned by ANOTHER tenant denies CROSS_TENANT in every dialect — the
    tenant boundary is enforced identically regardless of the ingress wire shape."""
    owner = "tenant-" + uuid.uuid4().hex
    caller = "tenant-" + uuid.uuid4().hex
    agent = "agent-" + uuid.uuid4().hex
    alias = "skill_" + uuid.uuid4().hex
    reg = _fresh_registry(owner, alias)  # alias exists — but for `owner`, not `caller`
    args = _sample_arguments()
    verdict = _engine_verdict(fmt, alias, args, reg, caller, agent)
    assert verdict == ("deny", "cross_tenant", None)


# ===========================================================================
# 3. Register-in-dialect-X, consume-via-dialect-Y — lock parity across every pair.
# ===========================================================================

# All ordered dialect pairs where the register and consume dialects differ.
_CROSS_PAIRS = [
    (a, b) for a, b in itertools.product(DIALECTS, DIALECTS) if a is not b
]


@pytest.mark.parametrize(
    ("reg_fmt", "con_fmt"),
    _CROSS_PAIRS,
    ids=[f"{a.value}->{b.value}" for a, b in _CROSS_PAIRS],
)
def test_lock_hash_matches_register_dialect_x_consume_dialect_y(
    reg_fmt: SourceFormat, con_fmt: SourceFormat
) -> None:
    """PIN lock parity: a lock registered from dialect X and answered from dialect Y
    hashes to the SAME payload — the exactly-once payload lock is format-independent, so
    an agent cannot dodge a step-up by re-issuing the completion in a different dialect."""
    tenant, agent = "tenant-" + uuid.uuid4().hex, "agent-" + uuid.uuid4().hex
    alias = "skill_" + uuid.uuid4().hex
    args = _sample_arguments()
    reg_intent = _parse(reg_fmt, alias, args)
    con_intent = _parse(con_fmt, alias, args)
    registered = lock_payload_hash(tenant, agent, reg_intent.alias, reg_intent.arguments)
    consumed = lock_payload_hash(tenant, agent, con_intent.alias, con_intent.arguments)
    assert registered == consumed


def test_lock_hash_differs_when_arguments_differ_by_one_byte() -> None:
    """Sanity dual: the cross-dialect equality above is NOT a hash collapse — one byte
    of argument drift changes the lock hash (so PAYLOAD_MISMATCH is real), regardless
    of dialect."""
    tenant, agent = "tenant-" + uuid.uuid4().hex, "agent-" + uuid.uuid4().hex
    alias = "skill_" + uuid.uuid4().hex
    a = _parse(SourceFormat.OPENAI_TOOL_CALL, alias, {"amount": "100"})
    b = _parse(SourceFormat.A2A_TASK, alias, {"amount": "101"})
    assert lock_payload_hash(tenant, agent, a.alias, a.arguments) != lock_payload_hash(
        tenant, agent, b.alias, b.arguments
    )


# ===========================================================================
# 4. Identity- / capability-shaped key injection → HARD deny in EVERY dialect.
# ===========================================================================

_IDENTITY_KEYS = ["role", "tenant_id", "agent_id", "sub", "capabilities", "entitlement"]


@pytest.mark.parametrize("fmt", DIALECTS, ids=_DIALECT_IDS)
@pytest.mark.parametrize("bad_key", _IDENTITY_KEYS)
def test_identity_shaped_key_in_arguments_is_hard_deny(
    fmt: SourceFormat, bad_key: str
) -> None:
    """An identity- or capability-shaped key smuggled into the tool-call arguments is a
    HARD deny (IDENTITY_INJECTION), never a silent strip — in EVERY dialect. Identity is
    sovereign (JWT-only); an in-band claim can never be trusted OR quietly dropped."""
    raw = _BUILDERS[fmt]("skill_" + uuid.uuid4().hex, {bad_key: "attacker-value"})
    assert _deny_reason(raw, fmt) == "identity_injection"


@pytest.mark.parametrize("fmt", DIALECTS, ids=_DIALECT_IDS)
def test_identity_key_nested_deep_in_arguments_is_hard_deny(fmt: SourceFormat) -> None:
    """The hard deny fires at ANY nesting level, in every dialect — an identity key
    hidden inside a nested object is caught by the recursive walker, not just at top
    level."""
    raw = _BUILDERS[fmt](
        "skill_" + uuid.uuid4().hex, {"outer": {"inner": {"role": "admin"}}}
    )
    assert _deny_reason(raw, fmt) == "identity_injection"


@pytest.mark.parametrize("fmt", DIALECTS, ids=_DIALECT_IDS)
def test_fullwidth_homoglyph_identity_key_is_hard_deny(fmt: SourceFormat) -> None:
    """A fullwidth-homoglyph identity key (ｒｏｌｅ → NFKC-folds to 'role') still trips the
    hard deny in every dialect — the fold defeats the confusable-key evasion."""
    raw = _BUILDERS[fmt]("skill_" + uuid.uuid4().hex, {"ｒｏｌｅ": "x"})
    assert _deny_reason(raw, fmt) == "identity_injection"


# ===========================================================================
# 5. Malformed / illegal / oversized / over-deep envelopes → deny in EVERY dialect.
# ===========================================================================


@pytest.mark.parametrize("fmt", DIALECTS, ids=_DIALECT_IDS)
def test_illegal_bidi_character_in_value_denies(fmt: SourceFormat) -> None:
    """A right-to-left-override smuggled into an argument VALUE denies
    ILLEGAL_CHARACTER in every dialect (never rendered, never stored raw)."""
    raw = _BUILDERS[fmt]("skill_" + uuid.uuid4().hex, {"note": "abc‮xyz"})
    assert _deny_reason(raw, fmt) == "illegal_character"


@pytest.mark.parametrize("fmt", DIALECTS, ids=_DIALECT_IDS)
def test_oversized_string_value_denies(fmt: SourceFormat) -> None:
    """An over-cap string argument denies SIZE_EXCEEDED in every dialect — the limit is
    enforced on the normalized payload, not the wire framing, so no dialect can smuggle
    an oversized value past it."""
    raw = _BUILDERS[fmt]("skill_" + uuid.uuid4().hex, {"blob": "A" * 20_000})
    assert _deny_reason(raw, fmt) == "size_exceeded"


@pytest.mark.parametrize("fmt", DIALECTS, ids=_DIALECT_IDS)
def test_too_many_keys_denies(fmt: SourceFormat) -> None:
    """An arguments object with more than MAX_ARG_KEYS entries denies SIZE_EXCEEDED in
    every dialect (the per-container key ceiling, distinct from the byte ceiling)."""
    raw = _BUILDERS[fmt](
        "skill_" + uuid.uuid4().hex, {f"k{i}": i for i in range(65)}
    )
    assert _deny_reason(raw, fmt) == "size_exceeded"


@pytest.mark.parametrize("fmt", DIALECTS, ids=_DIALECT_IDS)
def test_deeply_nested_arguments_denies(fmt: SourceFormat) -> None:
    """An over-deep nested arguments object denies DEPTH_EXCEEDED in every dialect —
    the recursive-walk depth cap is dialect-independent."""
    node: dict[str, Any] = {"leaf": 1}
    for _ in range(12):
        node = {"n": node}
    raw = _BUILDERS[fmt]("skill_" + uuid.uuid4().hex, node)
    assert _deny_reason(raw, fmt) == "depth_exceeded"


@pytest.mark.parametrize("fmt", DIALECTS, ids=_DIALECT_IDS)
def test_unknown_envelope_key_denies_schema_violation(fmt: SourceFormat) -> None:
    """An unexpected/duplicate structural key at the envelope level denies
    SCHEMA_VIOLATION in every dialect — the strict (extra='forbid') ingress models mean
    no dialect tolerates a smuggled extra field on the call frame."""
    raw = _BUILDERS[fmt]("skill_" + uuid.uuid4().hex, {"ok": 1})
    raw["unexpected_" + uuid.uuid4().hex[:6]] = "smuggled"
    assert _deny_reason(raw, fmt) == "schema_violation"


@pytest.mark.parametrize("fmt", DIALECTS, ids=_DIALECT_IDS)
def test_top_level_array_denies_unknown_format(fmt: SourceFormat) -> None:
    """A top-level array (a batch / tool_calls list) denies UNKNOWN_FORMAT in every
    dialect — one tool call per parse; a dialect never silently unbundles a batch."""
    raw = [_BUILDERS[fmt]("skill_" + uuid.uuid4().hex, {"ok": 1})]
    assert _deny_reason(raw, fmt) == "unknown_format"


# Concrete malformed shapes, one per dialect, with the reason the taxonomy assigns.
_MALFORMED_CASES: list[tuple[SourceFormat, dict[str, Any], str]] = [
    # OpenAI: the stringified arguments are not valid JSON → UNKNOWN_FORMAT.
    (
        SourceFormat.OPENAI_TOOL_CALL,
        {"id": "call_x", "type": "function",
         "function": {"name": "skill_x", "arguments": "{not json"}},
        "unknown_format",
    ),
    # OpenAI: arguments decode to a non-object → UNKNOWN_FORMAT.
    (
        SourceFormat.OPENAI_TOOL_CALL,
        {"id": "call_x", "type": "function",
         "function": {"name": "skill_x", "arguments": "[1,2,3]"}},
        "unknown_format",
    ),
    # Anthropic: missing the required `input` field → SCHEMA_VIOLATION.
    (
        SourceFormat.ANTHROPIC_TOOL_USE,
        {"type": "tool_use", "id": "toolu_x", "name": "skill_x"},
        "schema_violation",
    ),
    # Gemini: missing the required functionCall.name → SCHEMA_VIOLATION.
    (
        SourceFormat.GEMINI_FUNCTION_CALL,
        {"functionCall": {"args": {}}},
        "schema_violation",
    ),
    # Bedrock: missing the required toolUseId → SCHEMA_VIOLATION.
    (
        SourceFormat.BEDROCK_TOOL_USE,
        {"toolUse": {"name": "skill_x", "input": {}}},
        "schema_violation",
    ),
    # MCP: missing params.name → SCHEMA_VIOLATION.
    (
        SourceFormat.MCP_JSONRPC,
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"arguments": {}}},
        "schema_violation",
    ),
    # MCP: wrong method literal → SCHEMA_VIOLATION.
    (
        SourceFormat.MCP_JSONRPC,
        {"jsonrpc": "2.0", "id": 1, "method": "tools/teleport",
         "params": {"name": "skill_x", "arguments": {}}},
        "schema_violation",
    ),
    # A2A: zero parts (min_length=1 bound) → SCHEMA_VIOLATION.
    (
        SourceFormat.A2A_TASK,
        {"kind": "task", "id": "task-x", "contextId": "ctx-x",
         "status": {"state": "submitted"},
         "message": {"kind": "message", "role": "agent", "messageId": "msg-x", "parts": []}},
        "schema_violation",
    ),
    # A2A: a non-data part (kind='text') → SCHEMA_VIOLATION (structured invocation only).
    (
        SourceFormat.A2A_TASK,
        {"kind": "task", "id": "task-x", "contextId": "ctx-x",
         "status": {"state": "submitted"},
         "message": {"kind": "message", "role": "agent", "messageId": "msg-x",
                     "parts": [{"kind": "text", "text": "hi"}]}},
        "schema_violation",
    ),
]


@pytest.mark.parametrize(
    ("fmt", "payload", "expected"),
    _MALFORMED_CASES,
    ids=[f"{f.value}-{i}" for i, (f, _p, _r) in enumerate(_MALFORMED_CASES)],
)
def test_malformed_envelope_fails_closed_with_expected_reason(
    fmt: SourceFormat, payload: dict[str, Any], expected: str
) -> None:
    """Every malformed envelope shape, in each dialect, fails CLOSED to the exact
    taxonomy reason — never a crash, never a partial parse, never an authorized intent."""
    assert _deny_reason(payload, fmt) == expected


@pytest.mark.parametrize("fmt", DIALECTS, ids=_DIALECT_IDS)
def test_identity_key_beside_the_invocation_is_denied_not_merged(
    fmt: SourceFormat,
) -> None:
    """A `sub`/identity key placed at the ENVELOPE level (a sibling of the invocation,
    not inside arguments) is rejected in every dialect — either the strict model forbids
    the extra field (SCHEMA_VIOLATION) or, where it lands inside arguments, the hard
    identity deny fires. It is NEVER merged into the authorized payload."""
    raw = _BUILDERS[fmt]("skill_" + uuid.uuid4().hex, {"ok": 1})
    raw["sub"] = "attacker@evil"
    reason = _deny_reason(raw, fmt)
    assert reason in {"schema_violation", "identity_injection"}


# ===========================================================================
# 6. Vendor→dialect registry: exact match, unknowns denied, and hash-pinned.
# ===========================================================================

_PINNED_VENDOR_CASES = [
    ("openai", SourceFormat.OPENAI_TOOL_CALL),
    ("azure_openai", SourceFormat.OPENAI_TOOL_CALL),
    ("mistral", SourceFormat.OPENAI_TOOL_CALL),
    ("xai", SourceFormat.OPENAI_TOOL_CALL),
    # Kimi/Moonshot: both ids bound, neither aliased to the other.
    ("kimi", SourceFormat.OPENAI_TOOL_CALL),
    ("moonshot", SourceFormat.OPENAI_TOOL_CALL),
    # A self-hosted runtime resolves exactly like a hosted cloud — the air-gapped
    # operator gets the identical boundary, not a degraded one.
    ("ollama", SourceFormat.OPENAI_TOOL_CALL),
    ("vllm", SourceFormat.OPENAI_TOOL_CALL),
    # A router in front of the model does not change the declared dialect.
    ("litellm", SourceFormat.OPENAI_TOOL_CALL),
    ("databricks", SourceFormat.OPENAI_TOOL_CALL),
    ("claude", SourceFormat.ANTHROPIC_TOOL_USE),
    # Bedrock- and Vertex-hosted Claude: the HOST changes, the wire shape does not.
    ("claude_bedrock", SourceFormat.ANTHROPIC_TOOL_USE),
    ("claude_vertex", SourceFormat.ANTHROPIC_TOOL_USE),
    # …while RAW bedrock/vertex keep their own native dialects. Same product names,
    # deliberately different bindings — the exact drift a sniffing gateway gets wrong.
    ("bedrock", SourceFormat.BEDROCK_TOOL_USE),
    ("gemini", SourceFormat.GEMINI_FUNCTION_CALL),
    ("vertex", SourceFormat.GEMINI_FUNCTION_CALL),
    ("mcp", SourceFormat.MCP_JSONRPC),
    ("cursor", SourceFormat.MCP_JSONRPC),
    ("zed", SourceFormat.MCP_JSONRPC),
    ("codex", SourceFormat.MCP_JSONRPC),
    ("n8n", SourceFormat.MCP_JSONRPC),
    ("langgraph", SourceFormat.MCP_JSONRPC),
    ("a2a", SourceFormat.A2A_TASK),
]


@pytest.mark.parametrize(
    ("vendor", "fmt"), _PINNED_VENDOR_CASES, ids=[v for v, _ in _PINNED_VENDOR_CASES]
)
def test_pinned_vendor_resolves_to_its_dialect(vendor: str, fmt: SourceFormat) -> None:
    """Format is DECLARED, never sniffed: each pinned vendor string resolves — by exact
    match — to its one bound dialect."""
    assert resolve_vendor(vendor) is fmt


@pytest.mark.parametrize(
    "vendor",
    ["OpenAI", "OPENAI", "grok", "gpt-4", "", "  ", "a2a_task", "unknown-" + "x"],
)
def test_unknown_or_case_variant_vendor_is_denied(vendor: str) -> None:
    """An unknown, empty, or case-variant vendor string denies UNKNOWN_VENDOR
    fail-closed — no casefolding, no aliasing, no sniffing selects a parser."""
    try:
        resolve_vendor(vendor)
    except Exception as exc:  # noqa: BLE001
        assert map_engine_exception(exc).reason.value == "unknown_vendor"
    else:
        raise AssertionError(f"vendor {vendor!r} should have denied")


def test_registry_is_hash_pinned_and_consistent() -> None:
    """The connector registry booted only because its live vendor→dialect mapping hashes
    to the pinned sha256 — importing it at all is the fail-closed self-check, and the two
    hashes match here."""
    assert REGISTRY_SHA256 == _PINNED_REGISTRY_SHA256


def test_tampered_registry_mapping_would_break_the_pin() -> None:
    """A tampered registry entry is refused: re-pointing a single vendor to a different
    (real) dialect changes the recomputed sha256 away from the pin — the exact drift the
    import-time RuntimeError would reject. Proven WITHOUT mutating product state."""
    live = {v.value: f.value for v, f in VENDOR_FORMAT.items()}
    assert sha256_hex(canonical_json(live)) == _PINNED_REGISTRY_SHA256

    repointed = dict(live)
    repointed["openai"] = SourceFormat.MCP_JSONRPC.value  # silent repoint attempt
    assert sha256_hex(canonical_json(repointed)) != _PINNED_REGISTRY_SHA256

    added = dict(live)
    added["rogue_vendor"] = SourceFormat.OPENAI_TOOL_CALL.value  # smuggled new binding
    assert sha256_hex(canonical_json(added)) != _PINNED_REGISTRY_SHA256


def test_every_source_format_has_a_parser() -> None:
    """Every declared dialect (all six + the legacy raw_mcp) resolves to a parser — no
    SourceFormat is a dead ingress that would fail-closed on a legitimate call."""
    for fmt in list(DIALECTS) + [SourceFormat.RAW_MCP]:
        assert callable(parser_for(fmt))


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-q"]))
