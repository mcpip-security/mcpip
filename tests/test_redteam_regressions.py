"""
Regressions for the adversarial security campaign (wf_bee26c70-a95).

Each test pins a CONFIRMED break so it can never silently return:
  * C1/C2/C3 — delegation compartment escalation: an un-compartmented parent
    (itself denied every compartmented alias) could pin a child INTO a
    compartment, and _apply_delegation overwrote the child's compartment with
    the grant's wholesale, widening it past its own verified identity.
  * C5 — the principal kill-switch did not cascade to delegated children: a
    compromised admin pre-positioned an escape delegation on a fresh agent_id
    and survived its own revocation.
  * C4 — /v1/audit/proof leaked the obfuscator's hidden real target to ANY
    authenticated caller of ANY tenant (no capability, no tenant scope).
"""

from __future__ import annotations

import os

_TEST_REDIS_URL = "redis://localhost:63790/5"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_worm.jsonl"),
)

import json
import uuid
from typing import Any, Iterator, Optional

import pytest
import redis as redis_sync
from fastapi.testclient import TestClient
from httpx import Response

from app.main import _components, app
from interfaces import CAP_DIRECTORY_ADMIN
from main import _DemoIdP

_ENG = "e0900000-0000-4000-8000-e0900000e090"  # mcpip-inc / team-engineering
_ENG_ALIAS = "skill_engineering_roadmap"        # AUTO tier, compartment ENG
_INC = "mcpip-inc"
_ACME = "tenant-acme"


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    reset: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    reset.flushdb()
    reset.close()
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def idp(client: TestClient) -> _DemoIdP:
    demo = _components.demo_idp
    assert demo is not None
    return demo


@pytest.fixture()
def enabled() -> Iterator[None]:
    before = _components.settings.delegation_enabled
    _components.settings.delegation_enabled = True
    try:
        yield
    finally:
        _components.settings.delegation_enabled = before


def _j(r: Response) -> dict[str, Any]:
    return json.loads(r.text)


def _mint(
    idp: _DemoIdP,
    *,
    tenant: str,
    agent: str,
    session: Optional[str] = None,
    caps: Optional[list[str]] = None,
    compartment: Optional[str] = None,
    delegation_id: Optional[str] = None,
) -> str:
    return idp.mint(
        tenant_id=tenant,
        agent_id=agent,
        session_id=session,
        capabilities=caps,
        compartment=compartment,
        delegation_id=delegation_id,
    )


def _delegate(client: TestClient, tok: str, **body: Any) -> Response:
    return client.post(
        "/v1/delegate", headers={"Authorization": f"Bearer {tok}"}, json=body
    )


def _authorize(client: TestClient, tok: str, alias: str) -> Response:
    return client.post(
        "/v1/authorize",
        headers={"Authorization": f"Bearer {tok}"},
        json={"source_format": "raw_mcp", "tool_call": {"tool": alias, "arguments": {}}},
    )


# ---------------------------------------------------------------------------
# C1/C2/C3 — compartment escalation.
# ---------------------------------------------------------------------------


def test_c1_uncompartmented_parent_cannot_pin_child_to_a_compartment(
    client: TestClient, idp: _DemoIdP, enabled: None
) -> None:
    """The core break: a tenant-wide parent (denied every compartmented alias)
    conjuring compartment access for a child. Registration must refuse it."""
    parent = _mint(idp, tenant=_INC, agent="agent-parent", session=str(uuid.uuid4()))
    # Sanity: the parent is itself walled out of the ENG alias.
    assert _authorize(client, parent, _ENG_ALIAS).status_code == 403
    resp = _delegate(
        client,
        parent,
        child_agent_id="agent-child",
        child_session_id=str(uuid.uuid4()),
        capabilities=[],
        compartment=_ENG,
        expires_in_s=300,
    )
    assert resp.status_code == 400, resp.text
    assert "compartment" in resp.text


def test_c1_delegated_child_never_exceeds_its_own_jwt_compartment(
    client: TestClient, idp: _DemoIdP, enabled: None
) -> None:
    """A legit ENG parent delegates ENG, but the CHILD's own JWT is un-compartmented.
    _apply_delegation must NOT widen it back to ENG (the wholesale-overwrite bug)."""
    psid, csid = str(uuid.uuid4()), str(uuid.uuid4())
    parent = _mint(idp, tenant=_INC, agent="agent-eng", session=psid, compartment=_ENG)
    granted = _delegate(
        client,
        parent,
        child_agent_id="agent-child",
        child_session_id=csid,
        capabilities=[],
        compartment=_ENG,
        expires_in_s=300,
    )
    assert granted.status_code == 201, granted.text
    child = _mint(
        idp,
        tenant=_INC,
        agent="agent-child",
        session=csid,
        compartment=None,  # the child's own identity has NO compartment
        delegation_id=_j(granted)["delegation_id"],
    )
    assert _authorize(client, child, _ENG_ALIAS).status_code == 403


def test_compartmented_delegation_happy_path_still_works(
    client: TestClient, idp: _DemoIdP, enabled: None
) -> None:
    """When BOTH the grant and the child's JWT carry ENG, the child is allowed —
    the fix narrows, it does not break legitimate delegation."""
    psid, csid = str(uuid.uuid4()), str(uuid.uuid4())
    parent = _mint(idp, tenant=_INC, agent="agent-eng2", session=psid, compartment=_ENG)
    granted = _delegate(
        client,
        parent,
        child_agent_id="agent-child2",
        child_session_id=csid,
        capabilities=[],
        compartment=_ENG,
        expires_in_s=300,
    )
    assert granted.status_code == 201, granted.text
    child = _mint(
        idp,
        tenant=_INC,
        agent="agent-child2",
        session=csid,
        compartment=_ENG,
        delegation_id=_j(granted)["delegation_id"],
    )
    assert _authorize(client, child, _ENG_ALIAS).status_code == 200


# ---------------------------------------------------------------------------
# C5 — principal kill-switch cascades to delegated descendants.
# ---------------------------------------------------------------------------


def test_c5_principal_revocation_cascades_to_delegated_children(
    client: TestClient, idp: _DemoIdP, enabled: None
) -> None:
    boss_sid, escape_sid = str(uuid.uuid4()), str(uuid.uuid4())
    boss = _mint(
        idp, tenant=_ACME, agent="admin-boss", session=boss_sid,
        caps=[CAP_DIRECTORY_ADMIN],
    )
    granted = _delegate(
        client, boss,
        child_agent_id="escape-agent",
        child_session_id=escape_sid,
        capabilities=[CAP_DIRECTORY_ADMIN],  # ⊆ parent — attenuation allows it
        expires_in_s=3600,
    )
    assert granted.status_code == 201, granted.text
    escape = _mint(
        idp, tenant=_ACME, agent="escape-agent", session=escape_sid,
        caps=[CAP_DIRECTORY_ADMIN], delegation_id=_j(granted)["delegation_id"],
    )
    # The escape token works BEFORE containment.
    assert client.get(
        "/v1/admin/users", headers={"Authorization": f"Bearer {escape}"}
    ).status_code == 200

    # A warden revokes the compromised principal (the boss's agent_id).
    warden = _mint(idp, tenant=_ACME, agent="agent-warden", caps=[CAP_DIRECTORY_ADMIN])
    revoke = client.post(
        "/v1/admin/principals/admin-boss/revoke",
        headers={"Authorization": f"Bearer {warden}"},
        json={"reason": "compromised"},
    )
    assert revoke.status_code == 200, revoke.text

    # The escape child — a DIFFERENT, un-revoked agent_id — must now be severed too.
    assert client.get(
        "/v1/admin/users", headers={"Authorization": f"Bearer {escape}"}
    ).status_code == 403
    assert _authorize(client, escape, "skill_spend_summary").status_code == 403


# ---------------------------------------------------------------------------
# C4 — /v1/audit/proof authorization + tenant scope.
# ---------------------------------------------------------------------------


def test_c4_audit_proof_is_admin_gated_and_tenant_scoped(
    client: TestClient, idp: _DemoIdP
) -> None:
    # A zero-capability agent emits an event, then an admin seals + locates it.
    agent = _mint(idp, tenant=_ACME, agent="agent-zero", session=str(uuid.uuid4()))
    ok = _authorize(client, agent, "skill_spend_summary")
    assert ok.status_code == 200, ok.text
    corr = _j(ok)["correlation_id"]

    admin = _mint(idp, tenant=_ACME, agent="agent-adm", caps=[CAP_DIRECTORY_ADMIN])
    ah = {"Authorization": f"Bearer {admin}"}
    assert client.get("/v1/audit/verify", headers=ah).status_code == 200  # seal
    feed = client.get("/v1/admin/decisions/recent?limit=100", headers=ah)
    row = next(r for r in _j(feed)["decisions"] if r.get("correlation_id") == corr)
    event_id = row["event_id"]

    # (a) the zero-cap agent that MADE the call cannot read the proof — no capability.
    assert client.get(
        f"/v1/audit/proof/{event_id}",
        headers={"Authorization": f"Bearer {agent}"},
    ).status_code == 403

    # (b) an admin of a DIFFERENT tenant gets an indistinguishable 404, not the target.
    other = _mint(idp, tenant="tenant-globex", agent="agent-adm", caps=[CAP_DIRECTORY_ADMIN])
    assert client.get(
        f"/v1/audit/proof/{event_id}",
        headers={"Authorization": f"Bearer {other}"},
    ).status_code == 404

    # (c) the same-tenant admin gets the proof.
    good = client.get(f"/v1/audit/proof/{event_id}", headers=ah)
    assert good.status_code == 200, good.text
    assert _j(good)["event_id"] == event_id
