"""
MCPIP — real-world connector simulation + tamper QA (MCP & Anthropic Claude).

    ◐ "Parse, isolate, evaluate — exact third-party connector traffic, fail-closed."

Fires AUTHENTIC third-party wire structures at the two production edges and asserts
the gateway parses, isolates, and evaluates them correctly, and fails CLOSED on
every malformed / injected / forged variant:

  * MCP (JSON-RPC 2.0) end-to-end through ``POST /v1/mcp`` — initialize, tools/list,
    tools/call (allow / step-up / deny), batch + parse-error + unknown-method framing.
  * Anthropic Claude (``tool_use`` blocks) end-to-end through ``POST /v1/authorize``
    with ``source_format="anthropic_tool_use"``.
  * Security & tamper: prompt-injection disguised as a tool-call (identity-shaped
    keys, bidi-override), oversized / deep payloads, invalid signatures (forged +
    ``alg=none``) — each denied opaque, concrete reason to WORM only.
  * Integration: the WORM ledger records the concrete reason for simulated traffic
    while the agent sees only opacity; a canary decoy fired over MCP trips + freezes
    the caller; the signed Merkle-epoch chain verifies intact after mixed traffic.

Self-contained: mirrors ``test_authorize_api``'s namespaced-sandbox env so importing
the composition root is safe, and drives the real FastAPI app via ``TestClient`` so
the lifespan (Redis rebind + epoch daemon) runs exactly as production would.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# MUST be set before importing app.main (settings are lru_cached at import). Uses the
# SAME namespaced sandbox db as the adversarial API suite, so import order is immaterial.
_TEST_REDIS_URL = "redis://localhost:63790/5"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_worm.jsonl"),
)

import json
from typing import Any, Iterator, Optional

import pytest
import redis as redis_sync
from fastapi.testclient import TestClient
from httpx import Response

from core.security import AGENT_FACING_DENY_MESSAGE

from app.main import _components, app
from main import _DemoIdP, _forge_none_token, _tamper_signature

_EVENTS_STREAM = "mcpip:worm:events"

# Real aliases from the tenant-acme demo catalog.
_AUTO_ALIAS = "skill_spend_summary"
_PIN_ALIAS = "skill_payroll_run"
_CANARY_ALIAS = "skill_export_all_credentials"


# ---------------------------------------------------------------------------
# Fixtures (namespaced sandbox — mirrors the adversarial API suite).
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def idp() -> _DemoIdP:
    demo = _components.demo_idp
    assert demo is not None, "sandbox IdP must be present in sandbox mode"
    return demo


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    # Hermetic start: this module shares the namespaced sandbox db + WORM path with the
    # adversarial API suite, so reset BOTH the Redis epoch state AND the on-disk WORM
    # log + regenerable anchor — otherwise a stale on-disk anchor left by another module
    # would disagree with the freshly-flushed Redis chain and the audit-verify would
    # (correctly) report not-intact. Reset before the lifespan re-inits the WORM logger.
    reset: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    reset.flushdb()
    reset.close()
    worm_path = _components.settings.worm_path
    for artifact in (worm_path, worm_path + ".anchor"):
        try:
            os.remove(artifact)
        except FileNotFoundError:
            pass
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Authentic wire-shape builders.
# ---------------------------------------------------------------------------


def _mcp(method: str, *, params: Optional[dict[str, Any]] = None, req_id: Any = 1) -> dict[str, Any]:
    """A JSON-RPC 2.0 request object, exactly as an MCP client emits it."""
    body: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        body["params"] = params
    return body


def _mcp_call(alias: str, arguments: dict[str, Any], *, req_id: Any = 1) -> dict[str, Any]:
    return _mcp("tools/call", params={"name": alias, "arguments": arguments}, req_id=req_id)


def _claude_tool_use(alias: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    """An Anthropic Claude ``tool_use`` content block, exactly as the API emits it."""
    return {"type": "tool_use", "id": "toolu_01AbCdEf", "name": alias, "input": tool_input}


def _post_mcp(client: TestClient, body: Any, *, token: Optional[str]) -> Response:
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    resp: Response = client.post("/v1/mcp", json=body, headers=headers)
    return resp


def _post_claude(
    client: TestClient, *, alias: str, tool_input: dict[str, Any], token: str
) -> Response:
    resp: Response = client.post(
        "/v1/authorize",
        json={
            "source_format": "anthropic_tool_use",
            "tool_call": _claude_tool_use(alias, tool_input),
            "jwt": token,
        },
    )
    return resp


def _json(resp: Response) -> dict[str, Any]:
    data: Any = resp.json()
    assert isinstance(data, dict), data
    return data


def _last_deny_reason() -> Optional[str]:
    """The concrete ``deny_reason`` on the most-recent WORM event (agent never sees it)."""
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=1)
    finally:
        reader.close()
    if not entries:
        return None
    _sid, fields = entries[0]
    record: Any = json.loads(fields["record"])
    reason = record["event"].get("deny_reason")
    return reason if isinstance(reason, str) else None


def _assert_opaque_403(resp: Response) -> None:
    assert resp.status_code == 403, resp.text
    data = _json(resp)
    assert set(data.keys()) == {"error", "correlation_id"}, data
    assert data["error"] == AGENT_FACING_DENY_MESSAGE


def _assert_jsonrpc_deny(resp: Response) -> None:
    """An MCP deny is HTTP 200 + a JSON-RPC error carrying only the generic message."""
    assert resp.status_code == 200, resp.text
    data = _json(resp)
    assert "result" not in data
    assert data["error"]["code"] == -32000
    assert data["error"]["message"] == AGENT_FACING_DENY_MESSAGE
    assert "correlation_id" in data["error"]["data"]


# ===========================================================================
# 1. MCP (JSON-RPC 2.0) end-to-end simulation — POST /v1/mcp.
# ===========================================================================


def test_mcp_initialize_server_card(client: TestClient) -> None:
    """initialize needs no auth and returns a static server card — never tenant data."""
    resp = _post_mcp(client, _mcp("initialize", req_id=0), token=None)
    assert resp.status_code == 200, resp.text
    result = _json(resp)["result"]
    assert result["serverInfo"]["name"] == "mcpip"
    assert "capabilities" in result and "protocolVersion" in result


def test_mcp_tools_list_is_visibility_scoped(client: TestClient, idp: _DemoIdP) -> None:
    """tools/list enumerates only what THIS identity may see — opaque aliases, no targets."""
    resp = _post_mcp(client, _mcp("tools/list"), token=idp.mint())
    assert resp.status_code == 200, resp.text
    tools = _json(resp)["result"]["tools"]
    names = {t["name"] for t in tools}
    assert _AUTO_ALIAS in names
    # No target topology leaks into the listing.
    blob = json.dumps(tools)
    assert "mainframe" not in blob and "." not in "".join(names)


def test_mcp_tools_call_happy_allow(client: TestClient, idp: _DemoIdP) -> None:
    """A real MCP tools/call for an AUTO alias → executed; result carries a receipt."""
    resp = _post_mcp(client, _mcp_call(_AUTO_ALIAS, {"period": "2026-Q2"}), token=idp.mint())
    assert resp.status_code == 200, resp.text
    result = _json(resp)["result"]
    assert result["isError"] is False
    receipt = json.loads(result["content"][0]["text"])
    assert receipt["decision"] == "allow" and receipt["status"] == "committed"


def test_mcp_tools_call_pin_required_staged(client: TestClient, idp: _DemoIdP) -> None:
    """A high-risk alias over MCP → step-up staged (isError, challenge_id; no OTP)."""
    resp = _post_mcp(client, _mcp_call(_PIN_ALIAS, {"run_id": "PR-MCP-1"}), token=idp.mint())
    assert resp.status_code == 200, resp.text
    result = _json(resp)["result"]
    assert result["isError"] is True
    staged = json.loads(result["content"][0]["text"])
    assert "challenge_id" in staged and "otp" not in staged
    assert _last_deny_reason() == "pin_required"


def test_mcp_batch_array_rejected(client: TestClient, idp: _DemoIdP) -> None:
    """One call per request: a JSON-RPC batch (top-level array) → -32600."""
    resp = _post_mcp(client, [_mcp_call(_AUTO_ALIAS, {})], token=idp.mint())
    assert resp.status_code == 200, resp.text
    assert _json(resp)["error"]["code"] == -32600


def test_mcp_parse_error(client: TestClient, idp: _DemoIdP) -> None:
    """A non-JSON body → -32700 parse error."""
    resp = client.post(
        "/v1/mcp",
        content=b"{ not json",
        headers={"Authorization": f"Bearer {idp.mint()}", "content-type": "application/json"},
    )
    assert resp.status_code == 200, resp.text
    assert _json(resp)["error"]["code"] == -32700


def test_mcp_unknown_method(client: TestClient, idp: _DemoIdP) -> None:
    resp = _post_mcp(client, _mcp("tools/teleport"), token=idp.mint())
    assert _json(resp)["error"]["code"] == -32601


def test_mcp_tools_call_no_auth_denied(client: TestClient) -> None:
    """tools/call with no bearer → opaque JSON-RPC deny (never an auth-shaped hint)."""
    resp = _post_mcp(client, _mcp_call(_AUTO_ALIAS, {}), token=None)
    _assert_jsonrpc_deny(resp)


# ===========================================================================
# 2. Anthropic Claude (tool_use) end-to-end simulation — POST /v1/authorize.
# ===========================================================================


def test_claude_tool_use_happy_allow(client: TestClient, idp: _DemoIdP) -> None:
    """An authentic Claude tool_use block for an AUTO alias → 200 executed."""
    resp = _post_claude(client, alias=_AUTO_ALIAS, tool_input={"period": "2026-Q3"}, token=idp.mint())
    assert resp.status_code == 200, resp.text
    assert _json(resp)["decision"] == "allow"


def test_claude_tool_use_pin_required_staged(client: TestClient, idp: _DemoIdP) -> None:
    resp = _post_claude(client, alias=_PIN_ALIAS, tool_input={"run_id": "PR-CL-1"}, token=idp.mint())
    assert resp.status_code == 202, resp.text
    assert "challenge_id" in _json(resp) and "otp" not in _json(resp)


# ===========================================================================
# 3. Security & tamper QA — injection / malformed / invalid-signature → fail-closed.
# ===========================================================================


def test_claude_prompt_injection_identity_key_denied(client: TestClient, idp: _DemoIdP) -> None:
    """A Claude tool-call smuggling a capability-shaped key in `input` → hard deny,
    NOT a strip. Concrete reason to WORM; agent sees opacity."""
    resp = _post_claude(
        client,
        alias=_AUTO_ALIAS,
        tool_input={"capabilities": ["9c2b6f14-7a3d-4e8b-b1c0-2f5a9d3e4c71"]},
        token=idp.mint(),
    )
    _assert_opaque_403(resp)
    assert _last_deny_reason() == "identity_injection"


def test_claude_bidi_override_injection_denied(client: TestClient, idp: _DemoIdP) -> None:
    """A right-to-left override smuggled in an argument value → illegal_character."""
    resp = _post_claude(
        client, alias=_AUTO_ALIAS, tool_input={"note": "abc‮xyz"}, token=idp.mint()
    )
    _assert_opaque_403(resp)
    assert _last_deny_reason() == "illegal_character"


def test_mcp_oversized_arguments_denied(client: TestClient, idp: _DemoIdP) -> None:
    """A payload over the canonical-args cap fired via MCP → size_exceeded, fail-closed."""
    huge = {"blob": "A" * 20_000}
    resp = _post_mcp(client, _mcp_call(_AUTO_ALIAS, huge), token=idp.mint())
    _assert_jsonrpc_deny(resp)
    assert _last_deny_reason() == "size_exceeded"


def test_mcp_deep_nesting_denied(client: TestClient, idp: _DemoIdP) -> None:
    """An over-deep nested object via MCP → depth_exceeded."""
    node: dict[str, Any] = {"v": 1}
    for _ in range(12):
        node = {"n": node}
    resp = _post_mcp(client, _mcp_call(_AUTO_ALIAS, node), token=idp.mint())
    _assert_jsonrpc_deny(resp)
    assert _last_deny_reason() == "depth_exceeded"


def test_mcp_forged_signature_denied(client: TestClient, idp: _DemoIdP) -> None:
    """A signature-tampered JWT over MCP → opaque JSON-RPC deny; WORM jwt_invalid."""
    resp = _post_mcp(client, _mcp_call(_AUTO_ALIAS, {}), token=_tamper_signature(idp.mint()))
    _assert_jsonrpc_deny(resp)
    assert _last_deny_reason() == "jwt_invalid"


def test_mcp_alg_none_denied(client: TestClient) -> None:
    """An unsigned alg=none token over MCP → opaque JSON-RPC deny; WORM jwt_invalid."""
    resp = _post_mcp(client, _mcp_call(_AUTO_ALIAS, {}), token=_forge_none_token())
    _assert_jsonrpc_deny(resp)
    assert _last_deny_reason() == "jwt_invalid"


def test_claude_forged_signature_denied(client: TestClient, idp: _DemoIdP) -> None:
    resp = _post_claude(
        client, alias=_AUTO_ALIAS, tool_input={"period": "Q1"}, token=_tamper_signature(idp.mint())
    )
    _assert_opaque_403(resp)
    assert _last_deny_reason() == "jwt_invalid"


def test_mcp_unknown_alias_opaque(client: TestClient, idp: _DemoIdP) -> None:
    """An alias unknown to every tenant → opaque deny; WORM unknown_alias."""
    resp = _post_mcp(client, _mcp_call("skill_definitely_not_real", {}), token=idp.mint())
    _assert_jsonrpc_deny(resp)
    assert _last_deny_reason() == "unknown_alias"


# ===========================================================================
# 3b. MRT (SEP-2322) step-up transport — the payload-bound PIN mapped onto the
#     MCP Multi-Round-Trip InputRequired shape on the tools/call branch. ADDITIVE
#     + opt-in: the classic staged-text result stays the default; the same
#     register_lock / consume_and_execute payload lock still gates execution.
# ===========================================================================


def _authenticator_otp(client: TestClient, request_state: str, *, token: str) -> str:
    """Fetch the out-of-band OTP for a requestState (== challenge_id) — sandbox only."""
    otp_resp = client.get(
        f"/v1/authenticator/{request_state}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert otp_resp.status_code == 200, otp_resp.text
    return str(_json(otp_resp)["otp"])


def test_mcp_initialize_advertises_mrt_stepup(client: TestClient) -> None:
    """initialize additively advertises the MRT step-up capability (experimental)."""
    resp = _post_mcp(client, _mcp("initialize", req_id=0), token=None)
    assert resp.status_code == 200, resp.text
    caps = _json(resp)["result"]["capabilities"]
    assert caps["experimental"]["mcpipStepUp"]["mode"] == "mrt"
    assert "tools" in caps  # existing capability untouched


def test_mcp_mrt_staging_returns_input_required(client: TestClient, idp: _DemoIdP) -> None:
    """tools/call for a PIN_REQUIRED alias with top-level stepUp='mrt' → an MRT
    InputRequired result carrying an OPAQUE requestState + a pin inputRequest; no OTP,
    no target/topology. Staging still emits the same WORM pin_required record."""
    body = _mcp_call(_PIN_ALIAS, {"run_id": "PR-MRT-1"})
    body["stepUp"] = "mrt"
    resp = _post_mcp(client, body, token=idp.mint())
    assert resp.status_code == 200, resp.text
    result = _json(resp)["result"]
    assert result["isError"] is True
    assert isinstance(result["requestState"], str) and result["requestState"]
    reqs = result["inputRequests"]
    assert [r["name"] for r in reqs] == ["pin"]
    assert reqs[0]["sensitive"] is True
    # No OTP / pin value and no target topology anywhere in the wire response.
    blob = json.dumps(result)
    assert "otp" not in blob.lower()
    assert "mainframe" not in blob and "." not in result["requestState"]
    assert _last_deny_reason() == "pin_required"


def test_mcp_mrt_completion_via_same_consume_path(client: TestClient, idp: _DemoIdP) -> None:
    """Stage via MRT → read requestState → fetch OTP out-of-band → re-issue the
    IDENTICAL tools/call with requestState + inputResponses → 200 allow receipt. A
    second identical re-issue → opaque deny (lock spent, PIN_NOT_FOUND in WORM only),
    proving exactly-once holds over the MRT transport."""
    token = idp.mint(agent_id="agent-mrt-complete")
    args = {"run_id": "PR-MRT-2"}
    stage = _mcp_call(_PIN_ALIAS, args)
    stage["stepUp"] = "mrt"
    staged = _post_mcp(client, stage, token=token)
    request_state = _json(staged)["result"]["requestState"]
    otp = _authenticator_otp(client, request_state, token=token)

    reissue = _mcp_call(_PIN_ALIAS, args, req_id=2)
    reissue["requestState"] = request_state
    reissue["inputResponses"] = {"pin": otp}
    done = _post_mcp(client, reissue, token=token)
    assert done.status_code == 200, done.text
    result = _json(done)["result"]
    assert result["isError"] is False
    receipt = json.loads(result["content"][0]["text"])
    assert receipt["decision"] == "allow" and receipt["status"] == "committed"

    # Replay the identical completion → lock already spent → opaque deny.
    replay = _post_mcp(client, reissue, token=token)
    _assert_jsonrpc_deny(replay)
    assert _last_deny_reason() == "pin_not_found"


def test_mcp_mrt_tampered_reissue_payload_mismatch(client: TestClient, idp: _DemoIdP) -> None:
    """A re-issue with the correct requestState + OTP but MUTATED arguments → opaque
    deny; the payload lock still gates over the same atomic Lua (PAYLOAD_MISMATCH)."""
    token = idp.mint(agent_id="agent-mrt-tamper")
    stage = _mcp_call(_PIN_ALIAS, {"run_id": "PR-MRT-3"})
    stage["stepUp"] = "mrt"
    staged = _post_mcp(client, stage, token=token)
    request_state = _json(staged)["result"]["requestState"]
    otp = _authenticator_otp(client, request_state, token=token)

    tampered = _mcp_call(_PIN_ALIAS, {"run_id": "PR-MRT-3-TAMPERED"}, req_id=2)
    tampered["requestState"] = request_state
    tampered["inputResponses"] = {"pin": otp}
    resp = _post_mcp(client, tampered, token=token)
    _assert_jsonrpc_deny(resp)
    assert _last_deny_reason() == "payload_mismatch"


@pytest.mark.parametrize(
    "input_responses",
    [None, "not-a-dict", {}, {"pin": 123}, {"other": "x"}],
)
def test_mcp_mrt_malformed_reissue_fails_closed_at_edge(
    client: TestClient, idp: _DemoIdP, input_responses: Any
) -> None:
    """A requestState present without a well-formed inputResponses.pin → opaque deny
    at the edge (no crash, no assert leak, never authorized)."""
    body = _mcp_call(_PIN_ALIAS, {"run_id": "PR-MRT-4"}, req_id=2)
    body["requestState"] = "deadbeefdeadbeefdeadbeefdeadbeef"
    if input_responses is not None:
        body["inputResponses"] = input_responses
    resp = _post_mcp(client, body, token=idp.mint())
    _assert_jsonrpc_deny(resp)


def test_mcp_mrt_classic_path_unchanged_without_optin(client: TestClient, idp: _DemoIdP) -> None:
    """WITHOUT any MRT key, a PIN_REQUIRED tools/call returns the classic staged-text
    result byte-for-byte (challenge_id, no requestState/inputRequests, no OTP) — proving
    N4 is additive and opt-in."""
    resp = _post_mcp(client, _mcp_call(_PIN_ALIAS, {"run_id": "PR-MRT-5"}), token=idp.mint())
    assert resp.status_code == 200, resp.text
    result = _json(resp)["result"]
    assert result["isError"] is True
    assert "requestState" not in result and "inputRequests" not in result
    staged = json.loads(result["content"][0]["text"])
    assert "challenge_id" in staged and "otp" not in staged


def _value_appears(obj: Any, needle: str) -> bool:
    """True iff ``needle`` appears as an exact string LEAF anywhere in ``obj``.
    Exact-value (not substring) so a 6-digit OTP coinciding with a timestamp / hex
    substring never yields a false positive."""
    if isinstance(obj, str):
        return obj == needle
    if isinstance(obj, dict):
        return any(_value_appears(v, needle) for v in obj.values()) or needle in obj
    if isinstance(obj, list):
        return any(_value_appears(v, needle) for v in obj)
    return False


def test_mcp_mrt_no_otp_in_worm_across_stage_and_complete(
    client: TestClient, idp: _DemoIdP
) -> None:
    """Defence-in-depth beyond redaction: the OTP never appears (as a value or key) in
    the WORM stream across BOTH MRT staging and completion, nor in either wire
    response. Exact-value check — a 6-digit OTP is never asserted by substring."""
    token = idp.mint(agent_id="agent-mrt-noleak")
    args = {"run_id": "PR-MRT-6"}
    stage = _mcp_call(_PIN_ALIAS, args)
    stage["stepUp"] = "mrt"
    staged = _post_mcp(client, stage, token=token)
    request_state = _json(staged)["result"]["requestState"]
    otp = _authenticator_otp(client, request_state, token=token)

    reissue = _mcp_call(_PIN_ALIAS, args, req_id=2)
    reissue["requestState"] = request_state
    reissue["inputResponses"] = {"pin": otp}
    done = _post_mcp(client, reissue, token=token)
    assert done.status_code == 200, done.text
    # The OTP is absent from the most-recent WORM records (staging + completion) …
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=5)
    finally:
        reader.close()
    for _sid, fields in entries:
        assert not _value_appears(json.loads(fields["record"]), otp)
    # … and from both wire responses.
    assert not _value_appears(staged.json(), otp)
    assert not _value_appears(done.json(), otp)


# ===========================================================================
# 4. Integration — WORM ledger + threat-policy enforcement over simulated traffic.
# ===========================================================================


def test_worm_records_reason_while_agent_sees_opacity(client: TestClient, idp: _DemoIdP) -> None:
    """The asymmetry: the operator's WORM log holds the concrete reason for a simulated
    injection; the agent's response holds only a correlation id."""
    resp = _post_claude(
        client, alias=_AUTO_ALIAS, tool_input={"role": "admin"}, token=idp.mint()
    )
    _assert_opaque_403(resp)
    body = _json(resp)
    assert body["error"] == AGENT_FACING_DENY_MESSAGE  # opaque to the agent
    assert _last_deny_reason() == "identity_injection"  # concrete in WORM


def test_canary_over_mcp_trips_and_quarantines(client: TestClient, idp: _DemoIdP) -> None:
    """Selecting a decoy skill over MCP denies + freezes the caller; the next call —
    even a legitimate AUTO alias — is quarantined until the TTL lapses."""
    token = idp.mint(agent_id="agent-mcp-canary")
    trip = _post_mcp(client, _mcp_call(_CANARY_ALIAS, {}), token=token)
    _assert_jsonrpc_deny(trip)
    assert _last_deny_reason() == "canary_tripped"
    # The tripped agent is now frozen fail-closed.
    frozen = _post_mcp(client, _mcp_call(_AUTO_ALIAS, {"period": "Q4"}), token=token)
    _assert_jsonrpc_deny(frozen)
    assert _last_deny_reason() == "agent_quarantined"


def test_audit_chain_intact_after_mixed_connector_traffic(client: TestClient, idp: _DemoIdP) -> None:
    """After a burst of mixed MCP + Claude traffic (allow + deny), the signed
    Merkle-epoch WORM chain verifies intact (write-before-execute, tamper-evident)."""
    tok = idp.mint()
    _post_mcp(client, _mcp_call(_AUTO_ALIAS, {"period": "AX"}), token=tok)
    _post_claude(client, alias=_AUTO_ALIAS, tool_input={"period": "AY"}, token=tok)
    _post_mcp(client, _mcp_call("skill_nope", {}), token=tok)
    verify = client.get("/v1/audit/verify", headers={"Authorization": f"Bearer {tok}"})
    assert verify.status_code == 200, verify.text
    assert _json(verify)["intact"] is True


# ===========================================================================
# 5. Degenerate MCP framing — every malformed shape fails CLOSED, never 500.
# ===========================================================================
#
# Regression gate for a hunt that found ZERO unhandled-exception paths: the bridge
# parser + single fail-closed funnel turn every degenerate tools/call body into an
# opaque JSON-RPC deny (or a framing error), never an HTTP 5xx that would leak a
# stack trace or a parser-state oracle.

_MALFORMED_TOOLS_CALL: list[dict[str, Any]] = [
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call"},                                   # no params
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "nope"},                 # params not a dict
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"arguments": {}}},       # no name
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": _AUTO_ALIAS, "arguments": "{}"}},                                    # arguments as string
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": _AUTO_ALIAS, "arguments": [1, 2]}},                                  # arguments as list
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
     "params": {"name": 123, "arguments": {}}},                                             # name not a string
    {"jsonrpc": "2.0", "id": None, "method": "tools/call",
     "params": {"name": _AUTO_ALIAS, "arguments": {}}},                                     # null id
]


@pytest.mark.parametrize("body", _MALFORMED_TOOLS_CALL)
def test_malformed_mcp_tools_call_fails_closed(
    client: TestClient, idp: _DemoIdP, body: dict[str, Any]
) -> None:
    resp = _post_mcp(client, body, token=idp.mint())
    assert resp.status_code < 500, resp.text  # NEVER an unhandled 5xx
    data = _json(resp)
    assert "result" not in data  # never authorized
    assert data["error"]["code"] in (-32000, -32600, -32602)  # opaque deny / invalid params


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
