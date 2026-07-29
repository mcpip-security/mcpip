"""
MCPIP V2 — Connector conformance corpus: the durable defense against vendor drift.

    ◐ "Five wire shapes, one strict boundary — proven by fixtures, not by trust."

Three suites over ``tests/fixtures/connectors/``:

  * **Format vectors** — every wire-shape fixture is fed through the REAL ingress
    (``bridge.parse``) and must either produce the exact expected NormalizedIntent
    (alias, source_format, post-NFC arguments, canonical-bytes lock parity) or be
    denied with the exact expected ``DenyReason``. Deny vectors pin the *reason
    taxonomy* via ``map_engine_exception``, not exception classes, so they survive
    refactors.
  * **Registry vectors** — every pinned vendor string resolves to its pinned
    format; unknown/case-variant/empty vendors raise ``UnknownVendor`` fail-closed.
  * **Parity** — ONE logical call expressed in all five wire shapes yields
    byte-identical ``(alias, canonical_json(arguments))``, proving the payload-lock
    hash is format-independent.

Plus the **purity guard**: an AST scan proving no module under ``bridge/connectors/``
imports an LLM/vendor SDK or any network machinery, or reads ``os.environ`` — a
connector that does any of that is a defect, mechanically enforced forever.
"""

from __future__ import annotations

import ast
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

import bridge
from bridge.connectors.registry import VENDOR_FORMAT, resolve_vendor
from bridge.errors import UnknownVendor
from core.security import map_engine_exception
from interfaces import Hop, SourceFormat, SwarmTrace, canonical_json

_FIXTURES = Path(__file__).parent / "fixtures" / "connectors"
_FORMAT_FILES = (
    "openai.json",
    "anthropic.json",
    "gemini.json",
    "bedrock.json",
    "mcp.json",
    "raw_mcp.json",
    "a2a.json",
)


def _fixture_trace() -> SwarmTrace:
    """Fresh single-hop conformance trace (trace ids must be unique per parse)."""
    return SwarmTrace(
        trace_id=str(uuid.uuid4()),
        hops=[
            Hop(
                hop_index=0,
                agent_id="conformance-agent",
                parent_agent_id=None,
                purpose="conformance",
            )
        ],
    )


def _load(name: str) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads((_FIXTURES / name).read_text(encoding="utf-8"))
    return doc


def _collect_format_vectors() -> list[tuple[str, str, dict[str, Any]]]:
    collected: list[tuple[str, str, dict[str, Any]]] = []
    for filename in _FORMAT_FILES:
        doc = _load(filename)
        for vector in doc["vectors"]:
            collected.append((doc["format"], str(vector["name"]), vector))
    return collected


_FORMAT_VECTORS = _collect_format_vectors()


@pytest.mark.parametrize(
    ("format_value", "vector"),
    [(fmt, vec) for fmt, _, vec in _FORMAT_VECTORS],
    ids=[f"{fmt}-{name}" for fmt, name, _ in _FORMAT_VECTORS],
)
def test_format_vector(format_value: str, vector: dict[str, Any]) -> None:
    source_format = SourceFormat(format_value)
    payload: dict[str, Any] = vector["payload"]

    if vector["expect"] == "intent":
        intent = bridge.parse(payload, source_format, _fixture_trace())
        assert intent.alias == vector["alias"]
        assert intent.source_format is source_format
        assert intent.arguments == vector["arguments"]
        # Lock-hash parity: the canonical bytes the payload lock would hash must
        # match those of the fixture's expected (post-NFC) arguments exactly.
        assert canonical_json(intent.arguments) == canonical_json(vector["arguments"])
        return

    assert vector["expect"] == "deny"
    with pytest.raises(Exception) as excinfo:
        bridge.parse(payload, source_format, _fixture_trace())
    reason = map_engine_exception(excinfo.value).reason.value
    assert reason == vector["deny_reason"], (
        f"expected deny_reason={vector['deny_reason']!r}, got {reason!r} "
        f"({type(excinfo.value).__name__})"
    )


_REGISTRY_VECTORS: list[dict[str, Any]] = list(_load("registry.json")["vectors"])


@pytest.mark.parametrize(
    "vector",
    _REGISTRY_VECTORS,
    ids=[str(v["name"]) for v in _REGISTRY_VECTORS],
)
def test_registry_vector(vector: dict[str, Any]) -> None:
    if vector["expect"] == "format":
        assert resolve_vendor(vector["vendor"]) is SourceFormat(vector["format"])
        return
    assert vector["expect"] == "deny"
    with pytest.raises(UnknownVendor) as excinfo:
        resolve_vendor(vector["vendor"])
    assert map_engine_exception(excinfo.value).reason.value == vector["deny_reason"]


def test_every_registered_vendor_has_a_conformance_vector() -> None:
    """Coverage is MECHANICAL, not remembered: a vendor added to the registry without
    a pinned fixture vector fails here. Adding a binding is already a deliberate act
    (re-pin + ``REGISTRY_VERSION`` bump); this makes "and pin what it resolves to"
    part of that same act, so the corpus can never silently lag the registry."""
    pinned = {
        str(v["vendor"]) for v in _REGISTRY_VECTORS if v["expect"] == "format"
    }
    registered = {v.value for v in VENDOR_FORMAT}
    assert registered - pinned == set(), (
        "registered vendors with no conformance vector: "
        f"{sorted(registered - pinned)} — add them to fixtures/connectors/registry.json"
    )
    assert pinned - registered == set(), (
        f"fixture pins a vendor the registry no longer binds: {sorted(pinned - registered)}"
    )


def test_vendor_ids_are_exact_lowercase_tokens() -> None:
    """Every vendor id is a lowercase ``[a-z0-9_]`` token. Lookups are exact-match with
    no casefolding, so a mixed-case or punctuated id would be a string NO caller could
    ever hit — an unreachable binding is a fail-closed footgun, not a feature."""
    for vendor in VENDOR_FORMAT:
        assert re.fullmatch(r"[a-z0-9_]+", vendor.value), (
            f"vendor id {vendor.value!r} is not an exact lowercase token"
        )


def test_cross_format_parity() -> None:
    """ONE logical call in all 6 wire shapes → identical (alias, canonical bytes).

    Extending the proof to the A2A task envelope shows the payload-lock hash is
    format-INDEPENDENT for A2A too: the same (alias, arguments) expressed as an A2A
    Task yields byte-identical canonical arguments as MCP/OpenAI/etc., because the A2A
    parser only changes WHERE (alias, arguments) come from — canonical_json /
    enforce_argument_safety / the lock are untouched.
    """
    vectors: list[dict[str, Any]] = list(_load("parity.json")["vectors"])
    assert len(vectors) == 6
    assert {v["format"] for v in vectors} == {
        "openai_tool_call",
        "anthropic_tool_use",
        "gemini_function_call",
        "bedrock_tool_use",
        "mcp_jsonrpc",
        "a2a_task",
    }
    outcomes: set[tuple[str, bytes]] = set()
    for vector in vectors:
        intent = bridge.parse(
            vector["payload"], SourceFormat(vector["format"]), _fixture_trace()
        )
        outcomes.add((intent.alias, canonical_json(intent.arguments)))
    assert len(outcomes) == 1, f"formats diverged: {outcomes!r}"
    alias, canonical = outcomes.pop()
    assert alias == "skill_reconcile_invoices"
    assert json.loads(canonical) == {
        "invoice_id": "INV-7",
        "amount": 1250.5,
        "tags": ["q3", "eu"],
        "detail": {"note": "café ☕"},
    }


# ---------------------------------------------------------------------------
# Purity guard — "a connector that imports an LLM SDK is a defect", enforced.
# ---------------------------------------------------------------------------

_FORBIDDEN_TOP_LEVEL_IMPORTS = frozenset(
    {
        # LLM / vendor SDKs.
        "openai",
        "anthropic",
        "boto3",
        "botocore",
        "google",
        "vertexai",
        "dashscope",
        "qianfan",
        # HTTP / network machinery.
        "httpx",
        "requests",
        "aiohttp",
        "urllib",
        "http",
        "socket",
        "ssl",
        "asyncio",
    }
)


def test_connector_purity_no_sdk_no_network_no_env() -> None:
    connectors_dir = Path(bridge.__file__).resolve().parent / "connectors"
    sources = sorted(connectors_dir.glob("*.py"))
    assert sources, f"no connector sources found under {connectors_dir}"

    for source_path in sources:
        tree = ast.parse(
            source_path.read_text(encoding="utf-8"), filename=str(source_path)
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    assert top not in _FORBIDDEN_TOP_LEVEL_IMPORTS, (
                        f"{source_path.name}: forbidden import '{alias.name}' "
                        "— connectors are PURE parsers (no SDK, no network)"
                    )
            elif isinstance(node, ast.ImportFrom):
                top = (node.module or "").split(".")[0]
                assert top not in _FORBIDDEN_TOP_LEVEL_IMPORTS, (
                    f"{source_path.name}: forbidden import 'from {node.module}' "
                    "— connectors are PURE parsers (no SDK, no network)"
                )
            elif isinstance(node, ast.Attribute):
                if (
                    node.attr == "environ"
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "os"
                ):
                    raise AssertionError(
                        f"{source_path.name}: os.environ access — connectors "
                        "never read the environment"
                    )


# ---------------------------------------------------------------------------
# SDK parity — the published reference lists must not lag the registry.
# ---------------------------------------------------------------------------

_TS_TYPES = (
    Path(__file__).resolve().parents[1] / "sdk" / "typescript" / "src" / "types.ts"
)


def _ts_union(name: str) -> set[str]:
    """Extract a TS string-literal union's members by source scan (no node needed)."""
    source = _TS_TYPES.read_text(encoding="utf-8")
    start = source.index(f"export type {name} =")
    body = source[start : source.index(";", start)]
    return set(re.findall(r"'([a-z0-9_]+)'", body))


def test_typescript_sdk_vendor_union_matches_the_registry() -> None:
    """The TS SDK's ``Vendor`` union is documentation, not enforcement — the wire field
    is a free string and an unknown vendor is a WORM-audited opaque deny, never a 422.
    But documentation that lags the registry misleads integrators into thinking a bound
    vendor is unsupported, so parity is asserted rather than remembered."""
    assert _ts_union("Vendor") == {v.value for v in VENDOR_FORMAT}


def test_typescript_sdk_source_format_union_matches_the_engine() -> None:
    """Same contract for the dialect union: every ``SourceFormat`` the engine parses is
    listed, including the legacy ``raw_mcp`` ingress the SDK can still address."""
    assert _ts_union("SourceFormat") == {f.value for f in SourceFormat}


def test_python_sdk_envelope_builders_cover_every_dialect() -> None:
    """Every dialect the engine parses has an SDK builder, and each builder's output
    survives the REAL strict ingress producing the SAME (alias, canonical bytes).

    This is the SDK's half of the format-independence contract: a builder that drifts
    from its dialect's strict model would hand integrators a guaranteed 422, and a
    dialect with no builder is one the SDK silently cannot address."""
    sdk_root = Path(__file__).resolve().parents[1] / "sdk" / "python" / "src"
    if str(sdk_root) not in sys.path:
        sys.path.insert(0, str(sdk_root))
    from mcpip_sdk import envelopes  # noqa: PLC0415  (path-dependent import)

    assert set(envelopes.SOURCE_FORMATS) == {f.value for f in SourceFormat}

    alias = "skill_reconcile_invoices"
    arguments = {"invoice_id": "INV-7", "amount": 1250.5}
    outcomes: set[tuple[str, bytes]] = set()
    for source_format in SourceFormat:
        payload = envelopes.build(source_format.value, alias, arguments)
        intent = bridge.parse(payload, source_format, _fixture_trace())
        outcomes.add((intent.alias, canonical_json(intent.arguments)))
    assert len(outcomes) == 1, f"SDK builders diverged across dialects: {outcomes!r}"
    assert outcomes.pop() == (alias, canonical_json(arguments))
