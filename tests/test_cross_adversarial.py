"""
Cross-adversarial red-team regression suite (test_cross_adversarial).

White-box attacker probes against the REAL gateway internals — every test below was
first RUN as an exploit attempt against the live code; each one encodes the gateway's
verified FAIL-CLOSED / OPAQUE behaviour so a future regression that opens the hole goes
red. The angles here deliberately go where the existing cross_* / redteam_fixes suites
do NOT: number/JSON canonicalization edges (NaN/Infinity/overflow/negative-zero/
exponent), duplicate-key collapse through the payload lock, `_meta`/a2a_context
NON-lock inputs, novel identity-key encodings (bidi/fullwidth/uppercase/array-nested/
non-string value), cross-dialect consume parity, and WORM event mutation/partial-
deletion/reorder tamper detection.

Harness (copied from tests/test_redteam_fixes.py — engine/pure level, robust + fast):
  * ``asyncio.run(_body())`` bodies; direct component calls; no HTTP, no lifespan.
  * PIN-lock tests use the REAL ``PinValidator`` on Redis :63790 with UNIQUE uuid4
    tenants (tenant-scoped keys ⇒ no flush, no cross-test bleed).
  * WORM tests use a dedicated FLUSHED db (14) and a fresh ``WormLogger`` per test.
  * Every deny asserts the concrete internal reason (``map_engine_exception`` /
    Lua code / ``verify_chain``) AND, where relevant, the OPAQUE agent-facing shape.

FINDINGS: no exploitable hole was found — every probe below is a DEFENDED, fail-closed
behaviour captured as a regression. See the module-level summary the agent returns.
"""

from __future__ import annotations

import os

_TEST_REDIS_URL = "redis://localhost:63790/13"
os.environ.setdefault("MCPIP_REDIS_URL", _TEST_REDIS_URL)
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_cross_adversarial_worm.jsonl"),
)

import asyncio
import json
import unicodedata
import uuid
from typing import Any

import pytest
import redis.asyncio as aioredis
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit.worm_logger import (
    WormLogger,
    _EVENTS_STREAM,
    _is_secret_key,
    _redact,
)
from auth import lock_payload_hash
from bridge.errors import DepthExceeded, IdentityInjection, SizeExceeded, UnknownFormat
from bridge.intent_parser import ValidationError, enforce_argument_safety, parse
from core.security import map_engine_exception
from interfaces import (
    AGENT_FACING_DENY_MESSAGE,
    CAP_COMPARTMENT_GRANT,
    CAP_DIRECTORY_ADMIN,
    CAP_FORENSIC_READ,
    DenyReason,
    Hop,
    MCPIPDenied,
    SourceFormat,
    SwarmTrace,
    canonical_json,
    constant_time_equals,
    grant_capability_for,
)
from auth.pin_validator import PinValidator

_LOCK_DB_URL = "redis://localhost:63790/13"
_WORM_DB_URL = "redis://localhost:63790/14"


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _trace() -> SwarmTrace:
    return SwarmTrace(
        trace_id=str(uuid.uuid4()),
        hops=[Hop(hop_index=0, agent_id="agent-x", parent_agent_id=None, purpose="p")],
    )


# --- dialect envelope builders (one tool call per envelope). ----------------------
def _openai(alias: str, args_json: str) -> dict[str, Any]:
    return {
        "id": "call_1",
        "type": "function",
        "function": {"name": alias, "arguments": args_json},
    }


def _raw_mcp(alias: str, args: dict[str, Any]) -> dict[str, Any]:
    return {"tool": alias, "arguments": args}


def _mcp(alias: str, args: dict[str, Any] | None, meta: dict[str, Any] | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {"name": alias}
    if args is not None:
        params["arguments"] = args
    if meta is not None:
        params["_meta"] = meta
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}


def _gemini(alias: str, args: dict[str, Any] | None) -> dict[str, Any]:
    fc: dict[str, Any] = {"name": alias}
    if args is not None:
        fc["args"] = args
    return {"functionCall": fc}


def _anthropic(alias: str, args: dict[str, Any]) -> dict[str, Any]:
    return {"type": "tool_use", "id": "tu_1", "name": alias, "input": args}


def _a2a(alias: str, args: dict[str, Any] | None, metadata: dict[str, Any] | None = None,
         parts: int = 1) -> dict[str, Any]:
    data: dict[str, Any] = {"skill": alias}
    if args is not None:
        data["arguments"] = args
    part = {"kind": "data", "data": data}
    msg: dict[str, Any] = {
        "kind": "message",
        "role": "user",
        "messageId": str(uuid.uuid4()),
        "parts": [part] * parts,
    }
    if metadata is not None:
        msg["metadata"] = metadata
    return {
        "kind": "task",
        "id": str(uuid.uuid4()),
        "contextId": str(uuid.uuid4()),
        "status": {"state": "submitted"},
        "message": msg,
    }


def _args_of(raw: dict[str, Any], fmt: SourceFormat) -> dict[str, Any]:
    """Parse a dialect envelope and return its normalized ``arguments`` (post-walk)."""
    return parse(raw, fmt, _trace()).arguments


def _reason(exc: Exception) -> str:
    return map_engine_exception(exc).reason.value


# ---------------------------------------------------------------------------
# Group A — canonicalization / byte-identity edges (register↔consume hash inputs).
# Numbers, whitespace, structure, null/empty, non-lock channels.
# ---------------------------------------------------------------------------
def test_a01_exponent_float_distinct_from_integer_in_canonical_bytes() -> None:
    """A raw-JSON exponent (``1e3`` → float ``1000.0``) canonicalizes DISTINCTLY from
    the integer ``1000`` — so an attacker cannot use ``1e3`` at consume to slip a
    different-typed value under a lock registered with an int (it would PAYLOAD_MISMATCH)."""
    assert canonical_json({"x": 1e3}) == b'{"x":1000.0}'
    assert canonical_json({"x": 1000}) == b'{"x":1000}'
    assert canonical_json({"x": 1e3}) != canonical_json({"x": 1000})


def test_a02_negative_zero_distinct_from_positive_zero() -> None:
    """``-0.0`` and ``0.0`` are IEEE-equal but produce DIFFERENT canonical bytes, so the
    payload lock treats them as distinct — no sign-flip smuggling under a bound hash."""
    assert canonical_json({"x": -0.0}) == b'{"x":-0.0}'
    assert canonical_json({"x": 0.0}) == b'{"x":0.0}'
    assert canonical_json({"x": -0.0}) != canonical_json({"x": 0.0})


def test_a03_nan_token_in_raw_json_is_schema_violation() -> None:
    """Python's ``json.loads`` accepts the bare ``NaN`` token; the gateway must NOT.
    A NaN reaching arguments is a fail-closed SCHEMA_VIOLATION at the one validation
    authority (``enforce_argument_safety`` NaN/Inf reject), never a live float leaf."""
    with pytest.raises(ValidationError) as exc:
        parse(_openai("skill_x", '{"amt": NaN}'), SourceFormat.OPENAI_TOOL_CALL, _trace())
    assert _reason(exc.value) == DenyReason.SCHEMA_VIOLATION.value


def test_a04_infinity_token_in_raw_json_is_schema_violation() -> None:
    """``Infinity`` / ``-Infinity`` raw-JSON tokens are rejected fail-closed the same way
    (both are non-finite floats ``json.loads`` would otherwise accept)."""
    for tok in ("Infinity", "-Infinity"):
        with pytest.raises(ValidationError) as exc:
            parse(_openai("skill_x", '{"amt": %s}' % tok), SourceFormat.OPENAI_TOOL_CALL, _trace())
        assert _reason(exc.value) == DenyReason.SCHEMA_VIOLATION.value


def test_a05_overflow_number_collapsing_to_inf_is_schema_violation() -> None:
    """A finite-LOOKING but overflowing literal (``1e400``) that ``json.loads`` collapses
    to ``inf`` must still be rejected — the NaN/Inf guard sees the decoded float, not the
    literal, so the overflow oracle is closed fail-closed."""
    for tok in ("1e400", "1e309", "-1e400"):
        with pytest.raises(ValidationError) as exc:
            parse(_openai("skill_x", '{"amt": %s}' % tok), SourceFormat.OPENAI_TOOL_CALL, _trace())
        assert _reason(exc.value) == DenyReason.SCHEMA_VIOLATION.value


def test_a06_openai_whitespace_is_canonically_irrelevant() -> None:
    """A pretty-printed OpenAI arguments STRING and its compact twin normalize to the
    SAME arguments, so the payload-lock hash is identical — whitespace cannot desync a
    register/consume pair across the stringified-args dialect."""
    pretty = '{\n  "a": 1,\n  "b": [ 2 , 3 ]\n}'
    compact = '{"a":1,"b":[2,3]}'
    ap = _args_of(_openai("skill_x", pretty), SourceFormat.OPENAI_TOOL_CALL)
    ac = _args_of(_openai("skill_x", compact), SourceFormat.OPENAI_TOOL_CALL)
    assert lock_payload_hash("t", "a", "skill_x", ap) == lock_payload_hash("t", "a", "skill_x", ac)


def test_a07_deep_nested_key_order_is_lock_invariant() -> None:
    """Key order is irrelevant to the lock hash at EVERY nesting level (canonical sort is
    recursive), so a re-serialized deep object still consumes its own lock."""
    a = {"z": {"m": {"b": 1, "a": 2}, "k": 3}, "top": [1, {"y": 9, "x": 8}]}
    b = {"top": [1, {"x": 8, "y": 9}], "z": {"k": 3, "m": {"a": 2, "b": 1}}}
    assert lock_payload_hash("t", "ag", "s", a) == lock_payload_hash("t", "ag", "s", b)


def test_a08_array_element_order_changes_the_lock_hash() -> None:
    """Array ORDER is semantic — ``[1,2]`` and ``[2,1]`` hash differently, so a reordered
    list at consume is a PAYLOAD_MISMATCH, never a silent match."""
    assert lock_payload_hash("t", "ag", "s", {"v": [1, 2]}) != lock_payload_hash(
        "t", "ag", "s", {"v": [2, 1]}
    )


def test_a09_empty_string_value_distinct_from_absent_key() -> None:
    """An empty-string value is NOT the same as an absent key — the two hash differently,
    so dropping a key to ""-equivalent is caught by the lock."""
    assert lock_payload_hash("t", "ag", "s", {"note": ""}) != lock_payload_hash(
        "t", "ag", "s", {}
    )


def test_a10_null_value_distinct_from_absent_key() -> None:
    """A JSON ``null`` value is distinct from an absent key at the lock — null-vs-missing
    cannot be smuggled past a bound payload."""
    assert lock_payload_hash("t", "ag", "s", {"opt": None}) != lock_payload_hash(
        "t", "ag", "s", {}
    )


def test_a11_bool_int_string_one_are_three_distinct_canonical_values() -> None:
    """``true`` / ``1`` / ``"1"`` are three distinct JSON values with three distinct
    canonical encodings — no type-juggling collapse the lock could conflate."""
    hb = canonical_json({"x": True})
    hi = canonical_json({"x": 1})
    hs = canonical_json({"x": "1"})
    assert hb == b'{"x":true}' and hi == b'{"x":1}' and hs == b'{"x":"1"}'
    assert len({hb, hi, hs}) == 3


def test_a12_duplicate_json_keys_collapse_to_last_value_deterministically() -> None:
    """A stringified-args object with duplicate keys collapses to the LAST value
    (``json.loads`` semantics), deterministically — so the same duplicate-key text always
    yields the same lock hash, and it equals the explicit last-value object."""
    dup = _args_of(_openai("skill_x", '{"amount":1,"amount":999}'), SourceFormat.OPENAI_TOOL_CALL)
    assert dup == {"amount": 999}
    assert lock_payload_hash("t", "a", "skill_x", dup) == lock_payload_hash(
        "t", "a", "skill_x", {"amount": 999}
    )


def test_a13_source_format_trace_and_a2a_context_are_not_lock_inputs() -> None:
    """The payload lock hashes ONLY {tenant,agent,alias,arguments}: the same (alias,args)
    delivered as an A2A Task envelope (which carries task/context/message ids + declared
    metadata) hashes IDENTICALLY to the MCP dialect — provenance is recorded-not-locked."""
    args = {"a": 1, "b": "x"}
    a2a = parse(_a2a("skill_x", args, metadata={"actor": "someone"}), SourceFormat.A2A_TASK, _trace())
    mcp = parse(_mcp("skill_x", args), SourceFormat.MCP_JSONRPC, _trace())
    assert a2a.a2a_context is not None and mcp.a2a_context is None
    assert lock_payload_hash("t", "a", "skill_x", a2a.arguments) == lock_payload_hash(
        "t", "a", "skill_x", mcp.arguments
    )


def test_a14_nfc_normalization_is_idempotent_across_forms() -> None:
    """A value in NFD form and the same value in NFC form normalize to ONE representation,
    so a lock registered in one Unicode form consumes with the other (idempotent hash)."""
    nfd = unicodedata.normalize("NFD", "café")   # e + combining acute
    nfc = unicodedata.normalize("NFC", "café")   # precomposed é
    assert nfd != nfc  # different code point sequences on the wire
    assert lock_payload_hash("t", "a", "s", {"name": nfd}) == lock_payload_hash(
        "t", "a", "s", {"name": nfc}
    )


# ---------------------------------------------------------------------------
# Group B — identity / capability smuggling (novel encodings & scoping).
# ---------------------------------------------------------------------------
def test_b01_prototype_pollution_keys_are_inert_not_special() -> None:
    """``__proto__`` / ``constructor`` / ``__class__`` are NOT identity-shaped and are
    treated as ordinary opaque argument keys — no JS-style prototype special-casing, and
    they simply ride into the (bound) arguments like any other data key."""
    out = enforce_argument_safety({"__proto__": {"a": 1}, "constructor": 2, "__class__": "x"})
    assert out == {"__proto__": {"a": 1}, "constructor": 2, "__class__": "x"}


def test_b02_substring_of_identity_key_is_not_over_blocked() -> None:
    """The identity hard-deny is a WHOLE-KEY fold-match, not a substring scan: business
    keys that merely CONTAIN an identity token (``user_role``, ``role_name``,
    ``subtotal``, ``tenant_region``) are legitimately accepted, so opacity never costs
    false denials."""
    ok = {"user_role": "x", "role_name": "y", "subtotal": 3, "tenant_region": "eu"}
    assert enforce_argument_safety(ok) == ok


def test_b03_uppercase_and_mixedcase_identity_keys_hard_deny() -> None:
    """Case is folded before the membership test, so ``ROLE`` / ``Tenant_Id`` /
    ``AGENT_ID`` are hard-denied exactly like their lowercase forms (IDENTITY_INJECTION)."""
    for key in ("ROLE", "Tenant_Id", "AGENT_ID", "Actor", "PRINCIPAL"):
        with pytest.raises(IdentityInjection):
            enforce_argument_safety({key: "x"})


def test_b04_bidi_marked_identity_key_is_identity_injection() -> None:
    """A directional-mark variant of an identity key (``role`` + U+200F) folds back to the
    forbidden set (Cf stripped in the identity fold), so it hard-denies as
    IDENTITY_INJECTION — the identity filter is self-sufficient regardless of the charset
    guard's ordering."""
    with pytest.raises(IdentityInjection) as exc:
        enforce_argument_safety({"role‏": "admin"})
    assert map_engine_exception(exc.value).reason is DenyReason.IDENTITY_INJECTION


def test_b05_fullwidth_homoglyph_identity_key_hard_denies() -> None:
    """A fullwidth-homoglyph identity key (``ｓｕｂ`` → NFKC ``sub``) cannot slip past the
    ASCII forbidden set — the fold collapses the confusable to ``sub`` → IDENTITY_INJECTION."""
    fullwidth_sub = "".join(chr(ord(c) - ord("a") + 0xFF41) for c in "sub")
    assert unicodedata.normalize("NFKC", fullwidth_sub) == "sub"
    with pytest.raises(IdentityInjection):
        enforce_argument_safety({fullwidth_sub: "x"})


def test_b06_every_identity_and_capability_shaped_key_hard_denies() -> None:
    """The full forbidden set — identity AND authorization-shaped keys — hard-denies in
    arguments: an agent can never smuggle its own tenant/actor/entitlements in-band."""
    for key in (
        "tenant_id", "agent_id", "role", "tenant", "actor", "principal", "identity",
        "sub", "capabilities", "capability", "entitlement", "entitlements", "grants",
    ):
        with pytest.raises(IdentityInjection):
            enforce_argument_safety({key: "x"})


def test_b07_identity_key_nested_inside_a_list_element_hard_denies() -> None:
    """The walker is recursive: an identity-shaped key inside a dict that is itself an
    ARRAY element (arguments → list → dict → 'tenant_id') still trips the hard deny."""
    with pytest.raises(IdentityInjection):
        enforce_argument_safety({"items": [{"ok": 1}, {"tenant_id": "victim"}]})


def test_b08_identity_key_denies_regardless_of_value_type() -> None:
    """The hard deny is KEY-shaped, not value-shaped: ``tenant_id`` mapped to an int, a
    list, or null is denied just as a string value is — value type is irrelevant."""
    for val in (12345, ["a"], None, {"nested": 1}, True):
        with pytest.raises(IdentityInjection):
            enforce_argument_safety({"tenant_id": val})


def test_b09_capability_match_is_case_sensitive_and_fails_closed() -> None:
    """Capability authorization is an EXACT constant-time UUID compare: an upper-cased
    variant of a real capability UUID does NOT match the canonical lowercase constant, so
    a case-juggled capability confers nothing (fail-closed, never a widened match)."""
    assert not constant_time_equals(CAP_DIRECTORY_ADMIN.upper(), CAP_DIRECTORY_ADMIN)
    assert not constant_time_equals(CAP_FORENSIC_READ.upper(), CAP_FORENSIC_READ)
    # ...and the three well-known caps are mutually distinct (no capability confusion).
    assert len({CAP_DIRECTORY_ADMIN, CAP_FORENSIC_READ, CAP_COMPARTMENT_GRANT}) == 3


def test_b10_cross_compartment_grant_capability_is_scoped_and_non_transferable() -> None:
    """``grant_capability_for(X)`` is a per-compartment uuid5 that never equals
    ``grant_capability_for(Y)`` (Y≠X) nor the coarse ``CAP_COMPARTMENT_GRANT`` — so
    holding the scoped grant-issue authority for one compartment can never authorize
    issuing a grant for another (closes the cross-compartment delegation escape)."""
    x, y = str(uuid.uuid4()), str(uuid.uuid4())
    sx, sy = grant_capability_for(x), grant_capability_for(y)
    assert sx != sy
    assert sx != CAP_COMPARTMENT_GRANT and sy != CAP_COMPARTMENT_GRANT
    assert grant_capability_for(x) == sx  # deterministic (stable across processes)


# ---------------------------------------------------------------------------
# Group C — dialect confusion / parser smuggling.
# ---------------------------------------------------------------------------
def test_c01_wrong_declared_dialect_fails_closed() -> None:
    """Declaring one dialect while sending another's shape fails closed: an Anthropic
    ``tool_use`` body parsed as OpenAI is UNKNOWN_FORMAT / SCHEMA_VIOLATION, never a
    lenient best-effort extraction."""
    anthropic_body = _anthropic("skill_x", {"a": 1})
    with pytest.raises((UnknownFormat, ValidationError)) as exc:
        parse(anthropic_body, SourceFormat.OPENAI_TOOL_CALL, _trace())
    assert _reason(exc.value) in {
        DenyReason.UNKNOWN_FORMAT.value,
        DenyReason.SCHEMA_VIOLATION.value,
    }


def test_c02_jsonrpc_batch_array_is_unknown_format() -> None:
    """A JSON-RPC BATCH (a top-level array of calls) is not one tool call — it fails the
    dict guard as UNKNOWN_FORMAT. Clients must unbundle to one /authorize per element."""
    batch = [_mcp("skill_a", {}), _mcp("skill_b", {})]
    with pytest.raises(UnknownFormat) as exc:
        parse(batch, SourceFormat.MCP_JSONRPC, _trace())  # type: ignore[arg-type]
    assert _reason(exc.value) == DenyReason.UNKNOWN_FORMAT.value


def test_c03_absent_args_normalizes_identically_across_dialects() -> None:
    """A zero-argument call — Gemini with no ``args``, MCP with no ``arguments`` — both
    normalize to ``{}``, so their lock hashes match: absence is one canonical shape."""
    g = _args_of(_gemini("skill_x", None), SourceFormat.GEMINI_FUNCTION_CALL)
    m = _args_of(_mcp("skill_x", None), SourceFormat.MCP_JSONRPC)
    assert g == {} and m == {}
    assert lock_payload_hash("t", "a", "skill_x", g) == lock_payload_hash("t", "a", "skill_x", m)


def test_c04_mcp_meta_is_discarded_and_never_locked_or_denied() -> None:
    """MCP protocol plumbing ``_meta`` (progressToken etc.) is DISCARDED: an identity-
    shaped key inside ``_meta`` neither trips the identity hard-deny (it is outside
    ``arguments``) nor merges into arguments — the lock hash is identical to the same
    call with no ``_meta`` at all."""
    with_meta = _args_of(
        _mcp("skill_x", {"a": 1}, meta={"role": "admin", "tenant_id": "victim", "progressToken": "t"}),
        SourceFormat.MCP_JSONRPC,
    )
    without = _args_of(_mcp("skill_x", {"a": 1}), SourceFormat.MCP_JSONRPC)
    assert with_meta == {"a": 1} == without
    assert lock_payload_hash("t", "a", "skill_x", with_meta) == lock_payload_hash(
        "t", "a", "skill_x", without
    )


def test_c05_a2a_more_than_one_part_is_schema_violation() -> None:
    """An A2A Task carrying >1 part violates the one-invocation-per-request bound
    (MAX_A2A_PARTS=1) → SCHEMA_VIOLATION, so a multi-part envelope cannot smuggle a
    second call under one authorization."""
    with pytest.raises(ValidationError) as exc:
        parse(_a2a("skill_x", {"a": 1}, parts=2), SourceFormat.A2A_TASK, _trace())
    assert _reason(exc.value) == DenyReason.SCHEMA_VIOLATION.value


def test_c06_a2a_identity_key_inside_arguments_still_hard_denies() -> None:
    """A2A metadata may DECLARE an actor (recorded-not-trusted), but an identity-shaped key
    inside the invocation's ``data.arguments`` hits the UNCHANGED hard-deny →
    IDENTITY_INJECTION (the a2a exemption applies only to the separate metadata channel)."""
    env = _a2a("skill_x", {"tenant_id": "victim"}, metadata={"actor": "legit-human"})
    with pytest.raises(IdentityInjection) as exc:
        parse(env, SourceFormat.A2A_TASK, _trace())
    assert map_engine_exception(exc.value).reason is DenyReason.IDENTITY_INJECTION


def test_c07_a2a_non_data_part_is_schema_violation() -> None:
    """MCPIP gates a STRUCTURED skill invocation: an A2A text part (``kind='text'``) fails
    the ``Literal['data']`` → SCHEMA_VIOLATION, so free text cannot ride the task dialect."""
    env = _a2a("skill_x", {"a": 1})
    env["message"]["parts"] = [{"kind": "text", "text": "hi"}]
    with pytest.raises(ValidationError) as exc:
        parse(env, SourceFormat.A2A_TASK, _trace())
    assert _reason(exc.value) == DenyReason.SCHEMA_VIOLATION.value


def test_c08_oversize_argument_depth_and_nodes_fail_closed() -> None:
    """Structural DoS bounds hold on an ALREADY-DECODED dialect (raw-MCP has no pre-parse
    string cap): an over-deep object is DEPTH_EXCEEDED and a huge flat object is
    SIZE_EXCEEDED — both fail closed at the one walker authority."""
    deep: dict[str, Any] = {}
    node = deep
    for _ in range(12):  # MAX_ARG_DEPTH is 8
        node["n"] = {}
        node = node["n"]
    with pytest.raises(DepthExceeded):
        enforce_argument_safety(deep)
    wide = {f"k{i}": i for i in range(65)}  # MAX_ARG_KEYS is 64
    with pytest.raises(SizeExceeded):
        enforce_argument_safety(wide)


# ---------------------------------------------------------------------------
# Group D — payload-lock TOCTOU / exactly-once, driven through the REAL PinValidator.
# Unique uuid4 tenants ⇒ tenant-scoped keys never collide (no flush needed).
# ---------------------------------------------------------------------------
_OK, _NOT_FOUND, _PIN_MISMATCH, _PAYLOAD_MISMATCH = 1, -1, -2, -3


async def _pin() -> PinValidator:
    client: Any = aioredis.from_url(_LOCK_DB_URL, decode_responses=True)  # type: ignore[no-untyped-call]
    return PinValidator(client)


def test_d01_cross_dialect_canonical_args_consume_the_same_lock() -> None:
    """A lock registered from one dialect's normalized args consumes correctly when the
    completion presents a DIFFERENT dialect's byte-different-but-canonically-identical
    args — the lock binds the canonical payload, not the wire text."""

    async def _body() -> None:
        pv = await _pin()
        tenant, agent, alias = str(uuid.uuid4()), "agent-1", "skill_x"
        reg_args = _args_of(_raw_mcp(alias, {"b": 2, "a": 1}), SourceFormat.RAW_MCP)
        con_args = _args_of(_openai(alias, '{\n "a": 1,\n "b": 2\n}'), SourceFormat.OPENAI_TOOL_CALL)
        lock = await pv.register(tenant, agent, alias, reg_args, "123456")
        assert await pv.consume(tenant, lock, agent, alias, con_args, "123456") == _OK

    _run(_body())


def test_d02_negative_zero_drift_is_payload_mismatch_lock_survives() -> None:
    """Registering ``{"x":0.0}`` and completing with ``{"x":-0.0}`` is a PAYLOAD_MISMATCH
    (distinct canonical bytes) that does NOT spend an attempt — the correct payload still
    consumes afterward, proving the sign-flip never matched."""

    async def _body() -> None:
        pv = await _pin()
        tenant, agent, alias = str(uuid.uuid4()), "agent-1", "skill_x"
        lock = await pv.register(tenant, agent, alias, {"x": 0.0}, "123456")
        assert await pv.consume(tenant, lock, agent, alias, {"x": -0.0}, "123456") == _PAYLOAD_MISMATCH
        assert await pv.consume(tenant, lock, agent, alias, {"x": 0.0}, "123456") == _OK

    _run(_body())


def test_d03_exponent_vs_integer_drift_is_payload_mismatch() -> None:
    """A lock on the integer ``{"x":1000}`` rejects a completion presenting the float
    ``{"x":1000.0}`` (an exponent literal decoded to float) — PAYLOAD_MISMATCH, no attempt
    spent, correct still consumes."""

    async def _body() -> None:
        pv = await _pin()
        tenant, agent, alias = str(uuid.uuid4()), "agent-1", "skill_x"
        lock = await pv.register(tenant, agent, alias, {"x": 1000}, "123456")
        float_args = _args_of(_openai(alias, '{"x": 1e3}'), SourceFormat.OPENAI_TOOL_CALL)
        assert await pv.consume(tenant, lock, agent, alias, float_args, "123456") == _PAYLOAD_MISMATCH
        assert await pv.consume(tenant, lock, agent, alias, {"x": 1000}, "123456") == _OK

    _run(_body())


def test_d04_nfc_form_drift_still_consumes_the_lock() -> None:
    """Register with an NFC value, complete with the SAME value in NFD form: both
    normalize to one canonical payload, so the lock consumes — Unicode form cannot desync
    a legitimate register/consume pair."""

    async def _body() -> None:
        pv = await _pin()
        tenant, agent, alias = str(uuid.uuid4()), "agent-1", "skill_x"
        nfc = unicodedata.normalize("NFC", "café")
        nfd = unicodedata.normalize("NFD", "café")
        lock = await pv.register(tenant, agent, alias, {"name": nfc}, "123456")
        assert await pv.consume(tenant, lock, agent, alias, {"name": nfd}, "123456") == _OK

    _run(_body())


def test_d05_duplicate_key_collapse_survives_the_lock() -> None:
    """Register from a duplicate-key OpenAI body (collapses to last value) and complete
    with the explicit last-value object across another dialect → OK. Duplicate-key text
    resolves to one canonical payload, so it neither desyncs nor double-binds the lock."""

    async def _body() -> None:
        pv = await _pin()
        tenant, agent, alias = str(uuid.uuid4()), "agent-1", "skill_x"
        reg = _args_of(_openai(alias, '{"amount":1,"amount":999}'), SourceFormat.OPENAI_TOOL_CALL)
        con = _args_of(_raw_mcp(alias, {"amount": 999}), SourceFormat.RAW_MCP)
        lock = await pv.register(tenant, agent, alias, reg, "123456")
        assert await pv.consume(tenant, lock, agent, alias, con, "123456") == _OK

    _run(_body())


def test_d06_mcp_meta_is_not_a_lock_input() -> None:
    """A lock registered from an MCP call that ALSO carried ``_meta`` consumes correctly
    when completed WITHOUT ``_meta`` — confirming ``_meta`` never entered the payload hash
    (protocol plumbing is outside the authorized, bound payload)."""

    async def _body() -> None:
        pv = await _pin()
        tenant, agent, alias = str(uuid.uuid4()), "agent-1", "skill_x"
        reg = _args_of(_mcp(alias, {"a": 1}, meta={"progressToken": "x"}), SourceFormat.MCP_JSONRPC)
        con = _args_of(_mcp(alias, {"a": 1}), SourceFormat.MCP_JSONRPC)
        lock = await pv.register(tenant, agent, alias, reg, "123456")
        assert await pv.consume(tenant, lock, agent, alias, con, "123456") == _OK

    _run(_body())


def test_d07_a2a_and_mcp_cross_dialect_lock_parity_consumes() -> None:
    """A lock staged from an A2A Task envelope consumes when completed via MCP with the
    same (alias, args) — the a2a_context/provenance is excluded from the lock, so the
    dialect boundary is invisible to exactly-once completion."""

    async def _body() -> None:
        pv = await _pin()
        tenant, agent, alias = str(uuid.uuid4()), "agent-1", "skill_x"
        reg = _args_of(_a2a(alias, {"amt": 5}, metadata={"actor": "h"}), SourceFormat.A2A_TASK)
        con = _args_of(_mcp(alias, {"amt": 5}), SourceFormat.MCP_JSONRPC)
        lock = await pv.register(tenant, agent, alias, reg, "123456")
        assert await pv.consume(tenant, lock, agent, alias, con, "123456") == _OK

    _run(_body())


def test_d08_bool_vs_int_drift_is_payload_mismatch() -> None:
    """``{"flag": true}`` and ``{"flag": 1}`` are distinct canonical payloads: a lock on
    the boolean rejects the integer completion (PAYLOAD_MISMATCH) — no bool/int juggling."""

    async def _body() -> None:
        pv = await _pin()
        tenant, agent, alias = str(uuid.uuid4()), "agent-1", "skill_x"
        lock = await pv.register(tenant, agent, alias, {"flag": True}, "123456")
        assert await pv.consume(tenant, lock, agent, alias, {"flag": 1}, "123456") == _PAYLOAD_MISMATCH
        assert await pv.consume(tenant, lock, agent, alias, {"flag": True}, "123456") == _OK

    _run(_body())


def test_d09_stolen_challenge_with_different_alias_is_payload_mismatch() -> None:
    """A completion that reuses a valid challenge_id but names a DIFFERENT alias (same
    args) is PAYLOAD_MISMATCH — the alias is one of the four bound fields, so a stolen
    challenge cannot be retargeted onto another skill."""

    async def _body() -> None:
        pv = await _pin()
        tenant, agent = str(uuid.uuid4()), "agent-1"
        lock = await pv.register(tenant, agent, "skill_real", {"a": 1}, "123456")
        assert await pv.consume(tenant, lock, agent, "skill_other", {"a": 1}, "123456") == _PAYLOAD_MISMATCH
        # Correct alias still consumes — the mismatch spent no attempt.
        assert await pv.consume(tenant, lock, agent, "skill_real", {"a": 1}, "123456") == _OK

    _run(_body())


def test_d10_cross_tenant_challenge_reuse_is_not_found() -> None:
    """A challenge_id minted for tenant A is unreachable to tenant B: the lock key is
    tenant-scoped, so B's completion (even with the identical id/pin/payload) returns
    NOT_FOUND — no cross-tenant lock sharing."""

    async def _body() -> None:
        pv = await _pin()
        tenant_a, tenant_b, agent, alias = str(uuid.uuid4()), str(uuid.uuid4()), "ag", "skill_x"
        lock = await pv.register(tenant_a, agent, alias, {"a": 1}, "123456")
        assert await pv.consume(tenant_b, lock, agent, alias, {"a": 1}, "123456") == _NOT_FOUND
        # A remains spendable by its rightful owner.
        assert await pv.consume(tenant_a, lock, agent, alias, {"a": 1}, "123456") == _OK

    _run(_body())


def test_d11_wrong_payload_never_spends_an_attempt_budget() -> None:
    """Payload is compared BEFORE the PIN in the atomic Lua: a flood of wrong-PAYLOAD
    completions (each -3) spends NO attempt, so after many the correct payload+PIN still
    consumes on the first try — a payload probe cannot exhaust the 5-attempt lockout."""

    async def _body() -> None:
        pv = await _pin()
        tenant, agent, alias = str(uuid.uuid4()), "ag", "skill_x"
        lock = await pv.register(tenant, agent, alias, {"a": 1}, "123456")
        for i in range(10):
            assert await pv.consume(tenant, lock, agent, alias, {"a": i + 2}, "000000") == _PAYLOAD_MISMATCH
        assert await pv.consume(tenant, lock, agent, alias, {"a": 1}, "123456") == _OK

    _run(_body())


def test_d12_pin_shape_is_strictly_six_digits() -> None:
    """The PIN must be EXACTLY six decimal digits at register: a short/long/non-digit PIN
    is a hard ValueError before any lock exists — no alternate-shape codes are mintable."""

    async def _body() -> None:
        pv = await _pin()
        tenant, agent, alias = str(uuid.uuid4()), "ag", "skill_x"
        for bad in ("12345", "1234567", "12a456", "abcdef", "  1234"):
            with pytest.raises(ValueError):
                await pv.register(tenant, agent, alias, {"a": 1}, bad)

    _run(_body())


# ---------------------------------------------------------------------------
# Group E — WORM tamper detection & redaction (fresh flushed logger per test).
# ---------------------------------------------------------------------------
async def _fresh_worm() -> tuple[Any, WormLogger]:
    client: Any = aioredis.from_url(_WORM_DB_URL, decode_responses=True)  # type: ignore[no-untyped-call]
    await client.flushdb()
    logger = WormLogger(
        client, Ed25519PrivateKey.generate(),
        path="/tmp/_cross_adv_worm.jsonl", mode="epoch", anchor=None,
    )
    return client, logger


async def _seal_n(logger: WormLogger, n: int) -> None:
    for i in range(n):
        await logger.emit({"decision": "allow", "alias": f"skill_{i}", "probe": i})
    header = await logger.close_epoch()
    assert header is not None and header.epoch == 0
    intact, first_bad = await logger.verify_chain()
    assert intact and first_bad is None


def test_e01_single_event_mutation_via_duplicate_seq_is_tamper() -> None:
    """Mutating one sealed event's record (re-XADD its seq with altered content — the
    dict keyed by seq takes the later value) changes that Merkle leaf, so ``verify_chain``
    reports tamper at epoch 0. A signed root cannot be reconciled with a doctored event."""

    async def _body() -> None:
        client, logger = await _fresh_worm()
        try:
            await _seal_n(logger, 4)
            entries: Any = await client.xrange(_EVENTS_STREAM, min="-", max="+")
            target = next(dict(f) for _sid, f in entries if int(f["seq"]) == 2)
            rec = json.loads(target["record"])
            rec["alias"] = "TAMPERED"
            target["record"] = json.dumps(rec, separators=(",", ":"))
            await client.xadd(_EVENTS_STREAM, target)  # duplicate seq=2, later wins
            intact, first_bad = await logger.verify_chain()
            assert not intact and first_bad == 0
        finally:
            await client.aclose()

    _run(_body())


def test_e02_partial_event_deletion_in_hot_epoch_is_tamper() -> None:
    """Deleting ONE of a sealed hot epoch's events (partial presence: 3 of 4) is tamper —
    ``verify_header_fields`` requires FULL presence above the retention watermark, so a
    surgical single-event trim reads as deletion, not legitimate retention trimming."""

    async def _body() -> None:
        client, logger = await _fresh_worm()
        try:
            await _seal_n(logger, 4)
            entries: Any = await client.xrange(_EVENTS_STREAM, min="-", max="+")
            sid_seq2 = next(sid for sid, f in entries if int(f["seq"]) == 2)
            await client.xdel(_EVENTS_STREAM, sid_seq2)
            intact, first_bad = await logger.verify_chain()
            assert not intact and first_bad == 0
        finally:
            await client.aclose()

    _run(_body())


def test_e03_event_reorder_within_epoch_is_tamper() -> None:
    """Swapping two sealed events' record contents (Merkle leaves are POSITION-sensitive)
    is tamper — reordering an epoch's decisions cannot preserve its signed root."""

    async def _body() -> None:
        client, logger = await _fresh_worm()
        try:
            await _seal_n(logger, 4)
            entries: Any = await client.xrange(_EVENTS_STREAM, min="-", max="+")
            f2 = next(dict(f) for _sid, f in entries if int(f["seq"]) == 2)
            f3 = next(dict(f) for _sid, f in entries if int(f["seq"]) == 3)
            rec2, rec3 = f2["record"], f3["record"]
            f2["record"], f3["record"] = rec3, rec2  # swap the two leaves
            await client.xadd(_EVENTS_STREAM, f2)
            await client.xadd(_EVENTS_STREAM, f3)
            intact, first_bad = await logger.verify_chain()
            assert not intact and first_bad == 0
        finally:
            await client.aclose()

    _run(_body())


def test_e04_emit_is_durable_before_any_close() -> None:
    """Write-before-execute: ``emit`` durably buffers the event (assigned seq, retrievable
    record) BEFORE any epoch close — the record is present in the buffer the instant emit
    returns, so an ALLOW is never acted on ahead of its durable audit row."""

    async def _body() -> None:
        client, logger = await _fresh_worm()
        try:
            receipt = await logger.emit({"decision": "allow", "alias": "skill_probe"})
            entries: Any = await client.xrange(_EVENTS_STREAM, min="-", max="+")
            seqs = {int(f["seq"]) for _sid, f in entries}
            assert receipt.seq in seqs
            recorded = next(f for _sid, f in entries if int(f["seq"]) == receipt.seq)
            # The buffered record wraps the (redacted) event under "event"; the seq is a
            # stream-side coverage datum, not part of the hashed record.
            assert json.loads(recorded["record"])["event"]["alias"] == "skill_probe"
        finally:
            await client.aclose()

    _run(_body())


def test_e05_redaction_scrubs_nested_secrets_but_keeps_non_secret_ids() -> None:
    """Redaction is recursive through lists and dicts: vendor-prefixed and bare secret
    keys are scrubbed even inside list elements, while a non-secret operator identifier
    (``secret_id``) is KEPT — precise suffix matching, no over/under-redaction."""
    red = _redact(
        {
            "items": [
                {"aws_secret_access_key": "AKIA...", "region": "us-east-1"},
                {"password": "hunter2", "note": "keep"},
            ],
            "secret_id": "vault-ref-123",
            "gcp_private_key": "-----BEGIN...",
        }
    )
    assert red["items"][0]["aws_secret_access_key"] == "[REDACTED]"
    assert red["items"][0]["region"] == "us-east-1"
    assert red["items"][1]["password"] == "[REDACTED]"
    assert red["items"][1]["note"] == "keep"
    assert red["gcp_private_key"] == "[REDACTED]"
    assert red["secret_id"] == "vault-ref-123"  # non-secret id survives


def test_e06_is_secret_key_matches_suffix_not_arbitrary_substring() -> None:
    """``_is_secret_key`` redacts a token as the WHOLE key or a ``_``/``-`` delimited
    SUFFIX (``x-api-key``, ``aws_secret_access_key``) but NOT a mere substring
    (``secret_id`` is kept; ``api_key_label`` is kept) — the redaction rule is precise."""
    for redacted in ("secret", "client_secret", "x-api-key", "aws_secret_access_key",
                     "gcp_private_key", "session_token", "_credential"):
        assert _is_secret_key(redacted), redacted
    for kept in ("secret_id", "api_key_label", "tokenizer", "password_hint_shown",
                 "material_type", "region"):
        assert not _is_secret_key(kept), kept


# ---------------------------------------------------------------------------
# Group F — opacity of the agent-facing boundary.
# ---------------------------------------------------------------------------
def test_f01_mcpip_denied_carries_only_the_correlation_id() -> None:
    """The single agent-facing exception exposes ONLY the generic message + correlation
    id: no alias, tenant, target, or deny reason leaks in the message or attributes."""
    corr = uuid.uuid4().hex
    exc = MCPIPDenied(corr)
    assert exc.correlation_id == corr
    assert str(exc) == f"{AGENT_FACING_DENY_MESSAGE} correlation_id={corr}"
    # None of the sensitive topology/taxonomy strings appear in the wire message.
    blob = str(exc).casefold()
    for leaked in ("tenant", "alias", "compartment", "target", "unknown", "cross",
                   "reason", "mainframe", "rest.", "skill_"):
        assert leaked not in blob


def test_f02_distinct_deny_families_share_one_opaque_shape_but_split_in_worm() -> None:
    """Four different internal deny families (unknown alias / cross-tenant / identity-
    injection / schema) map to FOUR distinct WORM reasons, yet each would surface to the
    agent as the SAME opaque ``MCPIPDenied`` — the reason lives only in the audit domain,
    so the caller cannot distinguish 'absent' from 'exists-but-forbidden'."""
    from obfuscator import CrossTenant, UnknownAlias

    reasons = {
        map_engine_exception(UnknownAlias("a")).reason,
        map_engine_exception(CrossTenant("a")).reason,
        map_engine_exception(IdentityInjection("k")).reason,
        _mk_schema_reason(),
    }
    assert reasons == {
        DenyReason.UNKNOWN_ALIAS,
        DenyReason.CROSS_TENANT,
        DenyReason.IDENTITY_INJECTION,
        DenyReason.SCHEMA_VIOLATION,
    }
    # The agent-facing envelope is byte-identical across all four (only corr differs).
    a, b = MCPIPDenied("c1"), MCPIPDenied("c2")
    assert str(a).replace("c1", "X") == str(b).replace("c2", "X")


def _mk_schema_reason() -> DenyReason:
    try:
        parse(_openai("skill_x", '{"amt": NaN}'), SourceFormat.OPENAI_TOOL_CALL, _trace())
    except Exception as exc:  # noqa: BLE001
        return map_engine_exception(exc).reason
    raise AssertionError("expected a schema violation")
