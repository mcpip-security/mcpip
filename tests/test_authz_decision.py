"""
MCPIP V2 — OpenID-AuthZEN / COAZ decision surface (``POST /v1/authz/decision``).

    ◐ "Would you allow this exact call? — answered without executing a thing."

Exercises the inbound PDP decision surface end to end against the REAL gateway app
(``TestClient``, sandbox, Redis :63790 — mirrors ``test_authorize_api``'s namespaced
sandbox env so importing the composition root is safe regardless of import order), plus
the outbound COAZ PEP-mode scaffold (``ExternalPdpGateProvider`` / ``DenyOnlyGateChain``)
in isolation.

Decision-only contract asserted here:
  * permit → ``{"decision": true}`` (+ optional standards-shaped obligations);
  * deny   → the bare opaque ``{"decision": false}`` (no reason/target/topology);
  * a PIN_REQUIRED tier → a ``mcpip.step_up.pin`` OBLIGATION, NOT a leaked reason, and
    NO lock is staged / no PIN consumed;
  * the AuthZEN ``subject`` is NEVER identity (identity is only the verified JWT);
  * an identity-shaped argument key is a HARD DENY;
  * no execution / no vend / no PIN consume / no velocity INCR;
  * a canary query trips the quarantine (the one deliberate side effect);
  * ONE distinct ADVISORY WORM record (never an execution ALLOW).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# MUST be set before importing app.main (settings are lru_cached at import). Uses the SAME
# namespaced sandbox db as the adversarial API suite, so import order is immaterial.
_TEST_REDIS_URL = "redis://localhost:63790/5"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_worm.jsonl"),
)

import asyncio
import json
import time
import uuid
from typing import Any, Awaitable, Iterator, Optional, TypeVar

import pytest
import redis as redis_sync
from fastapi.testclient import TestClient
from httpx import Response

from core.security import AGENT_FACING_DENY_MESSAGE
from interfaces import (
    GATE_CONTEXT_FIELDS,
    GATE_RESOURCE_TYPE,
    CommunityGateContext,
    CommunityGateProvider,
    Classification,
    GateDecision,
    RiskTier,
)
from models.schemas import AuthzenResource
from obfuscator.tenant_catalog import FALCON

from core.config import Settings
from app.main import _build_community_gate, _components, app
from services.community_gate import (
    DenyOnlyGateChain,
    NoOpCommunityGateProvider,
    community_gate_engine_registered,
)
from services.external_pdp import ExternalPdpGateProvider
from main import _DemoIdP

_AEGIS = "aegis-dynamics"
_AUTO_ALIAS = "skill_spend_summary"                # tenant-acme AUTO, un-compartmented.
_PIN_ALIAS = "skill_payroll_run"                   # tenant-acme PIN_REQUIRED, un-comp.
_CANARY_ALIAS = "skill_export_all_credentials"     # seeded deception tripwire (every tenant).
_FALCON_SC_ALIAS = "skill_airframe_telemetry"        # aegis FALCON, AUTO, require_sender_constraint.
_FALCON_PIN_ALIAS = "skill_flight_command_issue"      # aegis FALCON, PIN_REQUIRED (no SC).
_EVENTS_STREAM = "mcpip:worm:events"
_CORR_HEADER = "x-mcpip-correlation-id"

_T = TypeVar("_T")


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def idp() -> _DemoIdP:
    demo = _components.demo_idp
    assert demo is not None, "sandbox IdP must be present in sandbox mode"
    return demo


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _run(coro: "Awaitable[_T]") -> _T:
    return asyncio.run(coro)  # type: ignore[arg-type]


def _sign(idp: _DemoIdP, claims: dict[str, Any]) -> str:
    import jwt

    token: str = jwt.encode(claims, idp._private_pem, algorithm="EdDSA")
    return token


def _cnf_token(
    idp: _DemoIdP,
    *,
    tenant_id: str,
    agent_id: str,
    compartment: Optional[str] = None,
    jkt: str = "test-cnf-jkt-thumbprint",
) -> str:
    """Mint a validly-signed, sender-constrained (cnf) JWT with optional compartment.

    A single-issuer deployment treats its one issuer as attesting, so a cnf here yields
    ``cnf_attested=True`` — exactly what a ``require_sender_constraint`` resource demands.
    """
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": _DemoIdP.ISSUER,
        "aud": _DemoIdP.AUDIENCE,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "role": "ops",
        "exp": now + 300,
        "iat": now,
        "nbf": now,
        "jti": uuid.uuid4().hex,
        "cnf": {"jkt": jkt},
    }
    if compartment is not None:
        claims["compartment"] = compartment
    return _sign(idp, claims)


def _decide(
    client: TestClient,
    *,
    alias: str,
    bearer: Optional[str],
    arguments: Optional[dict[str, Any]] = None,
    subject: Optional[dict[str, Any]] = None,
    send_auth: bool = True,
) -> Response:
    """POST ``/v1/authz/decision`` shaped as an AuthZEN request."""
    body: dict[str, Any] = {
        "subject": subject if subject is not None else {"type": "agent", "id": "advisory"},
        "resource": {"type": "mcpip.tool", "id": alias},
        "action": {"name": "invoke", "properties": arguments or {}},
    }
    headers: dict[str, str] = {}
    if send_auth and bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    response: Response = client.post("/v1/authz/decision", json=body, headers=headers)
    return response


def _json(resp: Response) -> dict[str, Any]:
    data: Any = resp.json()
    assert isinstance(data, dict)
    return data


def _recent_events(count: int = 50) -> list[dict[str, Any]]:
    """The most-recent buffered WORM event ctx dicts (newest first)."""
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=count)
    finally:
        reader.close()
    out: list[dict[str, Any]] = []
    for _sid, fields in entries:
        record: Any = json.loads(fields["record"])
        event = record.get("event")
        if isinstance(event, dict):
            out.append(event)
    return out


def _last_event() -> dict[str, Any]:
    events = _recent_events(count=1)
    assert events, "expected at least one WORM event"
    return events[0]


def _events_for(correlation_id: str) -> list[dict[str, Any]]:
    return [e for e in _recent_events(count=100) if e.get("correlation_id") == correlation_id]


def _count_keys(pattern: str) -> int:
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        return len(list(reader.scan_iter(match=pattern, count=500)))
    finally:
        reader.close()


def _openai_call(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "call_test",
        "type": "function",
        "function": {"name": alias, "arguments": json.dumps(arguments)},
    }


# ---------------------------------------------------------------------------
# decision=true.
# ---------------------------------------------------------------------------


def test_decision_true_auto_no_obligations(client: TestClient, idp: _DemoIdP) -> None:
    """An entitled caller querying a reachable AUTO alias → bare {"decision": true}."""
    token = idp.mint(tenant_id="tenant-acme", agent_id="agent-decide-auto")
    resp = _decide(client, alias=_AUTO_ALIAS, bearer=token)
    assert resp.status_code == 200, resp.text
    assert _json(resp) == {"decision": True}


# ---------------------------------------------------------------------------
# decision=false — opacity (exactly {"decision": false}, no other keys).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tenant,agent,alias",
    [
        ("tenant-acme", "agent-decide-unknown", "skill_does_not_exist_anywhere"),
        ("tenant-acme", "agent-decide-xtenant", _FALCON_SC_ALIAS),   # exists only in aegis.
        (_AEGIS, "agent-decide-compartment", _FALCON_PIN_ALIAS),     # FALCON, caller has no comp.
    ],
)
def test_decision_false_is_opaque(
    client: TestClient, idp: _DemoIdP, tenant: str, agent: str, alias: str
) -> None:
    token = idp.mint(tenant_id=tenant, agent_id=agent)
    resp = _decide(client, alias=alias, bearer=token)
    assert resp.status_code == 200, resp.text
    # Exactly {"decision": false} — NO reason / target / obligations / context leaked.
    assert _json(resp) == {"decision": False}


# ---------------------------------------------------------------------------
# PIN_REQUIRED → obligation (no lock staged, no PIN consumed).
# ---------------------------------------------------------------------------


def test_pin_required_maps_to_obligation_no_lock(client: TestClient, idp: _DemoIdP) -> None:
    token = idp.mint(tenant_id="tenant-acme", agent_id="agent-decide-pin")
    locks_before = _count_keys("mcpip:pinlock:*")
    resp = _decide(client, alias=_PIN_ALIAS, bearer=token)
    assert resp.status_code == 200, resp.text
    assert _json(resp) == {"decision": True, "obligations": [{"id": "mcpip.step_up.pin"}]}
    # Decision-only: no payload lock was registered (no PIN staged / consumed).
    assert _count_keys("mcpip:pinlock:*") == locks_before


# ---------------------------------------------------------------------------
# Sender-constraint obligation (attested cnf) vs bare-bearer deny.
# ---------------------------------------------------------------------------


def test_sender_constraint_attested_gets_dpop_obligation(
    client: TestClient, idp: _DemoIdP
) -> None:
    token = _cnf_token(
        idp, tenant_id=_AEGIS, agent_id="agent-decide-sc-ok", compartment=FALCON
    )
    resp = _decide(client, alias=_FALCON_SC_ALIAS, bearer=token)
    assert resp.status_code == 200, resp.text
    assert _json(resp) == {
        "decision": True,
        "obligations": [{"id": "mcpip.sender_constraint.dpop"}],
    }


def test_sender_constraint_bare_bearer_denied(client: TestClient, idp: _DemoIdP) -> None:
    """A bare bearer (non-attested) on a require_sender_constraint resource → deny."""
    token = idp.mint(
        tenant_id=_AEGIS, agent_id="agent-decide-sc-bare", compartment=FALCON
    )
    resp = _decide(client, alias=_FALCON_SC_ALIAS, bearer=token)
    assert resp.status_code == 200, resp.text
    assert _json(resp) == {"decision": False}


# ---------------------------------------------------------------------------
# Identity injection via the AuthZEN subject is IGNORED (identity = JWT only).
# ---------------------------------------------------------------------------


def test_subject_identity_injection_ignored(client: TestClient, idp: _DemoIdP) -> None:
    """A limited JWT + a subject claiming admin/other-tenant/caps → verdict reflects the JWT."""
    limited = idp.mint(tenant_id="tenant-acme", agent_id="agent-decide-inject")
    hostile_subject = {
        "type": "user",
        "id": "admin",
        "properties": {
            "tenant_id": _AEGIS,
            "role": "admin",
            "compartment": FALCON,
            "capabilities": ["ffffffff-0000-4000-8000-000000000000"],
        },
    }
    # The JWT is tenant-acme with no FALCON compartment; the falcon alias lives in aegis.
    resp = _decide(
        client, alias=_FALCON_SC_ALIAS, bearer=limited, subject=hostile_subject
    )
    assert _json(resp) == {"decision": False}
    # The advisory WORM record is scoped to the JWT identity, NOT the subject's claims.
    ev = _last_event()
    assert ev["admin_action"] == "authz_decision"
    assert ev["tenant_id"] == "tenant-acme"
    assert ev["agent_id"] == "agent-decide-inject"


def test_identity_shaped_arg_key_hard_deny(client: TestClient, idp: _DemoIdP) -> None:
    """An identity-shaped key in action.properties is a HARD DENY (enforce_argument_safety)."""
    token = idp.mint(tenant_id="tenant-acme", agent_id="agent-decide-argkey")
    resp = _decide(
        client, alias=_AUTO_ALIAS, bearer=token, arguments={"role": "admin"}
    )
    assert _json(resp) == {"decision": False}


# ---------------------------------------------------------------------------
# No execution / no vend / no consume / no velocity INCR + advisory-record shape.
# ---------------------------------------------------------------------------


def test_no_execution_only_advisory_record(client: TestClient, idp: _DemoIdP) -> None:
    token = idp.mint(tenant_id="tenant-acme", agent_id="agent-decide-noexec")
    vel_before = _count_keys("mcpip:policy:vel:*")
    resp = _decide(client, alias=_PIN_ALIAS, bearer=token)
    body = _json(resp)
    assert body["decision"] is True
    # No vended credential ever rides on a decision response.
    assert "vended_credential" not in body
    corr = resp.headers.get(_CORR_HEADER)
    assert corr is not None
    events = _events_for(corr)
    assert events, "the advisory record must be present for this correlation id"
    # ONLY the advisory admin_action record — never an execution allow/deny for this corr.
    for ev in events:
        assert ev["decision"] == "admin_action"
        assert ev["admin_action"] == "authz_decision"
        assert ev["advisory"] is True
        # No target / secret ever enters the advisory record.
        assert "target" not in ev
        for forbidden in ("pin", "otp", "jwt", "lock_code", "payload_hash", "vended_credential"):
            assert forbidden not in ev
    # No velocity budget was consumed (the G3 overlay is excluded from the decision path).
    assert _count_keys("mcpip:policy:vel:*") == vel_before


# ---------------------------------------------------------------------------
# Canary trip — a decision query naming bait quarantines the caller.
# ---------------------------------------------------------------------------


def test_canary_query_trips_quarantine(client: TestClient, idp: _DemoIdP) -> None:
    agent = "agent-decide-canary"
    token = idp.mint(tenant_id="tenant-acme", agent_id=agent)
    resp = _decide(client, alias=_CANARY_ALIAS, bearer=token)
    assert _json(resp) == {"decision": False}
    # The caller is now quarantined — a subsequent /v1/authorize is AGENT_QUARANTINED.
    follow = client.post(
        "/v1/authorize",
        json={
            "source_format": "openai_tool_call",
            "tool_call": _openai_call(_AUTO_ALIAS, {"period": "Q"}),
            "jwt": token,
        },
    )
    assert follow.status_code == 403, follow.text
    assert set(_json(follow).keys()) == {"error", "correlation_id"}
    # The concrete reason is WORM-only.
    ev = _recent_events(count=5)
    assert any(e.get("deny_reason") == "agent_quarantined" for e in ev)


# ---------------------------------------------------------------------------
# Auth: never unauthenticated (distinct from a decision:false body).
# ---------------------------------------------------------------------------


def test_no_token_is_opaque_403(client: TestClient, idp: _DemoIdP) -> None:
    resp = _decide(client, alias=_AUTO_ALIAS, bearer=None, send_auth=False)
    assert resp.status_code == 403, resp.text
    assert set(_json(resp).keys()) == {"error", "correlation_id"}
    assert _json(resp)["error"] == AGENT_FACING_DENY_MESSAGE


def test_invalid_token_is_opaque_403(client: TestClient, idp: _DemoIdP) -> None:
    resp = _decide(client, alias=_AUTO_ALIAS, bearer="not.a.jwt")
    assert resp.status_code == 403, resp.text
    assert set(_json(resp).keys()) == {"error", "correlation_id"}


# ---------------------------------------------------------------------------
# COAZ advertisement on the MCP edge.
# ---------------------------------------------------------------------------


def test_tools_list_advertises_coaz(client: TestClient, idp: _DemoIdP) -> None:
    token = idp.mint(tenant_id="tenant-acme", agent_id="agent-coaz")
    resp = client.post(
        "/v1/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    result = _json(resp)["result"]
    assert result["coaz"] is True
    assert isinstance(result["tools"], list)  # the existing sibling key is intact.


# ---------------------------------------------------------------------------
# PEP mode OFF (default) + the external-PDP scaffold in isolation.
# ---------------------------------------------------------------------------


def test_pep_mode_off_by_default() -> None:
    """Default composition: the shipped NO-OP community gate, no engine registered."""
    assert isinstance(_components.community_gate, NoOpCommunityGateProvider)
    assert community_gate_engine_registered() is False


class _FakeGate(CommunityGateProvider):
    def __init__(self, outcome: str) -> None:
        self._outcome = outcome

    async def evaluate(self, ctx: CommunityGateContext) -> GateDecision:
        return GateDecision(outcome=self._outcome)  # type: ignore[arg-type]


def _ctx() -> CommunityGateContext:
    return CommunityGateContext(
        alias=_AUTO_ALIAS,
        transport_class="cloud_rest",
        risk_tier=RiskTier.AUTO,
        classification=Classification.UNCLASSIFIED,
    )


def test_deny_only_chain_first_deny_wins() -> None:
    chain = DenyOnlyGateChain([_FakeGate("continue"), _FakeGate("deny")])
    decision = _run(chain.evaluate(_ctx()))
    assert decision.outcome == "deny"


def test_deny_only_chain_all_continue() -> None:
    chain = DenyOnlyGateChain([_FakeGate("continue"), _FakeGate("continue")])
    decision = _run(chain.evaluate(_ctx()))
    assert decision.outcome == "continue"


def test_external_pdp_ssrf_blocked_host_fails_closed() -> None:
    """A PDP URL resolving to a loopback/internal IP fails closed to deny (no network)."""
    provider = ExternalPdpGateProvider(url="https://127.0.0.1/authzen")
    decision = _run(provider.evaluate(_ctx()))
    assert decision.outcome == "deny"


def test_external_pdp_rejects_non_https() -> None:
    with pytest.raises(ValueError):
        ExternalPdpGateProvider(url="http://pdp.example.com/authzen")


# -- outbound COAZ PEP-mode composition (fail-closed on half-configuration) ---


def test_community_gate_default_is_noop() -> None:
    """No external-PDP config -> the strict NO-OP base provider (unchanged hot path)."""
    gate = _build_community_gate(Settings())
    assert isinstance(gate, NoOpCommunityGateProvider)


def test_community_gate_full_config_wraps_external_pdp() -> None:
    """Both flag + url set -> a DenyOnlyGateChain appending the external PDP consult."""
    gate = _build_community_gate(
        Settings(external_pdp_enabled=True, external_pdp_url="https://pdp.example.com/authzen")
    )
    assert isinstance(gate, DenyOnlyGateChain)


def test_community_gate_url_without_flag_is_staged_but_off() -> None:
    """A url set with the flag OFF is the legitimate 'staged but disabled' state (no raise)."""
    gate = _build_community_gate(
        Settings(external_pdp_url="https://pdp.example.com/authzen")
    )
    assert isinstance(gate, NoOpCommunityGateProvider)


def test_community_gate_enabled_without_url_fails_closed_at_boot() -> None:
    """
    HALF-CONFIGURATION: the flag ON with no url must be a fail-closed boot error, not a
    silent fall-through to the base provider — silently dropping a deny-only control the
    operator turned on would leave a security control they believe is enforcing ABSENT
    (a fail-OPEN). Same family as the authenticator-webhook / integrity / license refusals.
    """
    with pytest.raises(RuntimeError, match="MCPIP_EXTERNAL_PDP_ENABLED"):
        _build_community_gate(Settings(external_pdp_enabled=True))


# ---------------------------------------------------------------------------
# X4 — AuthZEN-shape alignment: COAZ and the community gate share ONE model.
# (Appended at end of module: the projection is pure, but the decision call emits an
# advisory WORM record, so this test must not sit ahead of the `_recent_events`-based
# assertions earlier in the file.)
# ---------------------------------------------------------------------------


def test_authzen_shared_model_context_projects_to_whitelist_resource(
    client: TestClient, idp: _DemoIdP
) -> None:
    """COAZ and the community gate share ONE evaluation model (X4 alignment).

    The decision surface stays byte-identical (backward-compat), AND the SAME
    ``CommunityGateContext`` type that ``_community_gate`` builds for a permitted alias
    projects cleanly to the AuthZEN SARC ``resource`` entity — whitelist-only, the exact
    ``AuthzenResource`` wire shape — demonstrating the one shared model with no CEL runtime.
    """
    token = idp.mint(tenant_id="tenant-acme", agent_id="agent-decide-shared")
    resp = _decide(client, alias=_AUTO_ALIAS, bearer=token)
    assert resp.status_code == 200, resp.text
    assert _json(resp) == {"decision": True}  # decision surface unchanged.

    # The SAME context type both /v1/authz/decision and /v1/authorize evaluate.
    ctx = CommunityGateContext(
        alias=_AUTO_ALIAS,
        transport_class="cloud_rest",
        risk_tier=RiskTier.AUTO,
        classification=Classification.UNCLASSIFIED,
    )
    res = ctx.as_authzen_resource()
    # Projects into the exact AuthzenResource wire shape (id/type/properties) the COAZ
    # surface uses — a strict, extra='forbid' model accepts it unchanged.
    parsed = AuthzenResource.model_validate(res)
    assert parsed.id == _AUTO_ALIAS and parsed.type == GATE_RESOURCE_TYPE
    # Whitelist-only: properties keyset == GATE_CONTEXT_FIELDS - {alias}; no target/secret.
    assert set(res["properties"].keys()) == GATE_CONTEXT_FIELDS - {"alias"}
    assert "target" not in res and "target" not in res["properties"]
    assert "celpy" not in sys.modules  # alignment pulls no CEL runtime.
