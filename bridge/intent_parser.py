"""
MCPIP V2 — Bridge: provider-agnostic ingress → NormalizedIntent.

    ◐ Bridge: "One ingress for every agent framework — OpenAI, Anthropic, Gemini,
       Bedrock, MCP JSON-RPC, raw MCP."

Provider dialects are accepted behind strict Pydantic v2 models
(``extra="forbid", strict=True``) that now live in ``bridge.connectors.formats``;
``parse`` selects the pure format parser by the DECLARED source_format through the
pinned ``bridge.connectors.registry``. Anything else is a fail-closed deny mapped
to UNKNOWN_FORMAT / SCHEMA_VIOLATION upstream.

This module still owns ``enforce_argument_safety`` — the recursive walker that every
NormalizedIntent runs over its ``arguments`` (imported lazily by interfaces.py to
avoid a circular import). It enforces depth, key/array counts, scalar-leaf typing,
string safety, NaN/Inf rejection, the canonical-byte ceiling, and — critically — the
identity-injection hard-deny at every nesting level. The walker MUST stay here: the
Rust shim (``bridge/fastwalk.py``) imports ``_enforce_argument_safety_py`` from this
module, and the compiled extension resolves the bridge exception classes via
``PyModule::import(py, "bridge.intent_parser")`` — so this module re-exports the
exception types (now defined in ``bridge.errors``) as the SAME class objects.
"""

from __future__ import annotations

import unicodedata
from typing import Any

from pydantic import ValidationError

from bridge.connectors.formats import (
    MAX_RAW_ARGUMENTS_BYTES,
    AnthropicToolUse,
    OpenAIToolCall,
    RawMCPCall,
)
from bridge.errors import DepthExceeded, IdentityInjection, SizeExceeded, UnknownFormat
from interfaces import (
    MAX_ARG_ARRAY,
    MAX_ARG_DEPTH,
    MAX_ARG_KEYS,
    MAX_CANONICAL_BYTES,
    NormalizedIntent,
    SourceFormat,
    SwarmTrace,
    canonical_json,
    reject_unsafe_string,
)

# Aggregate node ceiling applied INSIDE the walk, so it bounds the already-decoded
# Anthropic ``input`` object and the raw-MCP ``arguments`` object too — paths that
# (unlike OpenAI's raw JSON string) have no pre-parse byte cap. The per-container
# limits (MAX_ARG_KEYS / MAX_ARG_ARRAY / MAX_ARG_DEPTH) bound each level but NOT the
# total node count of a wide-and-deep structure, so a running counter is the true
# work bound. It is set to MAX_CANONICAL_BYTES because any structure with more nodes
# than that cannot possibly encode under the canonical byte ceiling, so this never
# rejects a payload the post-walk size check would have accepted — it only stops the
# walk early on an oversized one, before the full canonical encoding is built.
MAX_ARG_NODES: int = MAX_CANONICAL_BYTES


class _NodeCounter:
    """Mutable running count of nodes visited by ``_walk`` (aggregate work bound)."""

    __slots__ = ("count",)

    def __init__(self) -> None:
        self.count = 0

    def bump(self) -> None:
        self.count += 1
        if self.count > MAX_ARG_NODES:
            raise SizeExceeded(
                f"argument node count exceeds MAX_ARG_NODES={MAX_ARG_NODES}"
            )


# ---------------------------------------------------------------------------
# §4.5  Identity-injection forbidden key set (case-insensitive, every level).
# ---------------------------------------------------------------------------

_FORBIDDEN_IDENTITY_KEYS: frozenset[str] = frozenset(
    {
        "tenant_id",
        "agent_id",
        "role",
        "tenant",
        "actor",
        "principal",
        "identity",
        "sub",
        # Authorization-shaped claim names: an agent must never smuggle its own
        # capabilities/entitlements in-band — authorization is derived EXCLUSIVELY from
        # the verified JWT (capabilities claim) / Redis grants, never from the tool-call
        # payload. Hard-deny these instead of silently ignoring them (defense-in-depth
        # against a future reader that trusts them). Note: ``compartment`` is NOT here —
        # it is a legitimate business argument (the TARGET compartment of a grant
        # mandate), and it is provably inert for identity since the caller's own
        # compartment comes only from the JWT.
        "capabilities",
        "capability",
        "entitlement",
        "entitlements",
        "grants",
    }
)


def _identity_fold(key: str) -> str:
    """
    Fold a key for the identity-injection membership test.

    NFKC (compatibility) normalization collapses fullwidth / compatibility
    homoglyphs — e.g. fullwidth ``ｔｅｎａｎｔ＿ｉｄ`` (U+FF54…) folds to ``tenant_id`` —
    so an attacker cannot slip an identity-shaped key past the ASCII-only set with a
    confusable variant. casefold() then makes the match case-insensitive.

    Defense in depth: FORMAT characters (category ``Cf`` — bidi marks LRM/RLM/ALM and the
    like) survive NFKC, so ``"role‎"`` would otherwise fold to something the
    membership test misses. We strip every ``Cf`` codepoint before comparing so a
    directional-mark variant of an identity key still trips the hard deny. (Ingress
    strings are independently rejected for these by ``reject_unsafe_string``; this keeps
    the identity filter self-sufficient regardless of check order.)
    """
    folded = unicodedata.normalize("NFKC", key).casefold()
    return "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")


# ---------------------------------------------------------------------------
# §4.4  enforce_argument_safety — the recursive ingress-argument walker.
# ---------------------------------------------------------------------------


def _walk(node: Any, depth: int, counter: _NodeCounter) -> Any:
    """
    Recursively validate AND normalize one argument node; return the safe form.

    Invariants enforced on the way down:
      * every visited node counts against MAX_ARG_NODES (aggregate work bound).
      * depth <= MAX_ARG_DEPTH (root object counts as depth 1).
      * dict keys are str, <= MAX_ARG_KEYS, none identity-shaped, each char-safe.
      * arrays <= MAX_ARG_ARRAY elements.
      * scalar leaves are exactly one of {str, int, float, bool, None}.
      * NaN/Inf floats are rejected fail-closed.
      * every str (keys and values) passes reject_unsafe_string.

    Returns a structurally identical node with every string (keys AND values)
    replaced by its ``reject_unsafe_string`` NFC-normalized form, so no non-NFC
    text survives downstream. Containers are rebuilt from the normalized parts.

    Raises DepthExceeded / SizeExceeded / IdentityInjection / ValueError.
    """
    counter.bump()

    if depth > MAX_ARG_DEPTH:
        raise DepthExceeded(f"argument depth exceeds MAX_ARG_DEPTH={MAX_ARG_DEPTH}")

    if isinstance(node, dict):
        if len(node) > MAX_ARG_KEYS:
            raise SizeExceeded(
                f"object has {len(node)} keys > MAX_ARG_KEYS={MAX_ARG_KEYS}"
            )
        rebuilt: dict[str, Any] = {}
        for key, value in node.items():
            if not isinstance(key, str):
                # Non-string keys cannot exist in JSON objects; fail-closed.
                raise ValueError("object key must be a string")
            # Identity-injection guard runs BEFORE the size check (§4.5), on the
            # NFKC-casefolded key so compatibility/fullwidth homoglyphs cannot
            # evade the ASCII forbidden set.
            if _identity_fold(key) in _FORBIDDEN_IDENTITY_KEYS:
                raise IdentityInjection(
                    f"identity-shaped key '{key}' is forbidden in arguments"
                )
            # Keys are strings too — scrub for control/bidi/zero-width smuggling
            # and store the NFC-normalized key in the rebuilt object.
            safe_key = reject_unsafe_string(key, "argument-key")
            rebuilt[safe_key] = _walk(value, depth + 1, counter)
        return rebuilt

    if isinstance(node, list):
        if len(node) > MAX_ARG_ARRAY:
            raise SizeExceeded(
                f"array has {len(node)} elements > MAX_ARG_ARRAY={MAX_ARG_ARRAY}"
            )
        return [_walk(element, depth + 1, counter) for element in node]

    # Scalar leaves. bool must be tested before int (bool ⊂ int).
    if node is None or isinstance(node, bool):
        return node
    if isinstance(node, int):
        return node
    if isinstance(node, float):
        # NaN != NaN; Inf comparisons are the cheap portable test for non-finite.
        if node != node or node in (float("inf"), float("-inf")):
            raise ValueError("NaN/Inf not permitted in arguments")
        return node
    if isinstance(node, str):
        return reject_unsafe_string(node, "argument-value")

    # Anything else (tuple, set, bytes, custom object) is not JSON-native.
    raise ValueError(f"unsupported argument leaf type {type(node).__name__}")


def enforce_argument_safety(arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Validate a tool-call ``arguments`` object end-to-end (§4.4 + §4.5).

    The top-level ``arguments`` is an object counted as depth 1. The walk both
    validates and rebuilds the object with every string NFC-normalized in place,
    and enforces the aggregate node ceiling so an already-decoded (Anthropic /
    raw-MCP) payload cannot force unbounded walk work before the byte check. After
    the walk we bound the canonical-encoded size — the exact bytes the payload lock
    will hash, so size accounting and lock hashing agree perfectly.

    Returns the sanitized object (NFC-normalized keys and values).

    Dispatch: when the opt-in Rust fast-walker is enabled (``MCPIP_FAST_WALKER=1``)
    this delegates to the byte-identical / decision-identical Rust walk via
    ``bridge.fastwalk``; the Rust path raises the SAME bridge exception types so
    ``map_engine_exception`` yields the identical ``DenyReason``. Pure-Python
    (``_enforce_argument_safety_py``) is the default and the deferral fallback.
    """
    from bridge import fastwalk

    if fastwalk.FAST_ENABLED:
        return fastwalk.enforce_argument_safety(arguments)
    return _enforce_argument_safety_py(arguments)


def _enforce_argument_safety_py(arguments: dict[str, Any]) -> dict[str, Any]:
    """Pure-Python argument safety walk — the source-of-truth implementation.

    This is the default path and the fallback the Rust shim defers to; it must never
    call back through the ``enforce_argument_safety`` dispatcher (that would recurse).
    """
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be an object")

    sanitized = _walk(arguments, depth=1, counter=_NodeCounter())
    # arguments is a dict, so _walk returns a dict; assert to satisfy the checker.
    assert isinstance(sanitized, dict)

    # Byte ceiling on the canonical encoding — the exact bytes the payload lock
    # will hash, so size accounting and lock hashing agree perfectly.
    encoded = canonical_json(sanitized)
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise SizeExceeded(
            f"canonical arguments {len(encoded)} bytes > MAX_CANONICAL_BYTES="
            f"{MAX_CANONICAL_BYTES}"
        )
    return sanitized


# ---------------------------------------------------------------------------
# parse() — parser selected by the DECLARED source_format via the pinned registry.
# ---------------------------------------------------------------------------


def parse(
    raw: dict[str, Any],
    source_format: SourceFormat,
    trace: SwarmTrace,
) -> NormalizedIntent:
    """
    Normalize a provider tool-call into a NormalizedIntent (§4).

    The heavy lifting — schema rigidity, char/size/depth gates, identity-injection —
    happens when we construct the NormalizedIntent, whose validators run the shared
    ``enforce_argument_safety`` walker. Provider-shape mismatches raise UnknownFormat;
    a Pydantic ValidationError here means the strict per-format model rejected
    something. ONE tool call per parse — a top-level array (an OpenAI ``tool_calls``
    list, a Gemini ``parts`` list, a JSON-RPC batch) fails the dict guard below
    (UNKNOWN_FORMAT); a dict wrapper carrying a call array fails the per-format
    strict model's ``extra="forbid"`` (SCHEMA_VIOLATION). Clients unbundle: one
    /v1/authorize request per element.
    """
    if not isinstance(raw, dict):
        raise UnknownFormat("raw call must be an object")
    from bridge.connectors.registry import parser_for   # local import: registry imports formats only.
    candidate = parser_for(source_format)(raw)
    return NormalizedIntent(
        alias=candidate.alias,
        arguments=candidate.arguments,
        trace=trace,
        source_format=candidate.source_format,
        # Non-locked, recorded-not-trusted A2A correlation provenance. None for the six
        # existing dialects (Candidate default), so this is additive/backward-compatible;
        # it never enters the payload lock (which hashes {tenant,agent,alias,arguments})
        # nor the agent wire — it rides to the WORM audit ctx only.
        a2a_context=candidate.a2a_context,
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
    "MAX_RAW_ARGUMENTS_BYTES",
    "ValidationError",
]
