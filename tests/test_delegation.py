"""
Attenuated session delegation (docs/SESSION_DELEGATION_DESIGN.md, phase 2).

The property under test: a delegated token operates under the INTERSECTION of
its JWT claims and its live grant — never more — and every failure mode of the
grant (missing, expired, revoked anywhere in the chain, mis-bound, or the
feature being disabled) denies fail-closed rather than silently passing the
token through un-narrowed.
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

_TENANT = "tenant-acme"
_AUTO_ALIAS = "skill_spend_summary"


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    reset: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    reset.flushdb()
    reset.close()
    with TestClient(app) as test_client:
        # The flag defaults OFF; this module exercises the feature, so flip it on
        # the live settings object (and restore, so sibling modules see the
        # documented default). test_flag_off below covers the off state.
        yield test_client


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


def _json(resp: Response) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(resp.text)
    return parsed


def _mint_parent(
    idp: _DemoIdP,
    *,
    session_id: str,
    capabilities: Optional[list[str]] = None,
    compartment: Optional[str] = None,
) -> str:
    return idp.mint(
        tenant_id=_TENANT,
        agent_id="agent-dispatcher",
        session_id=session_id,
        capabilities=capabilities,
        compartment=compartment,
    )


def _delegate(
    client: TestClient,
    token: str,
    *,
    child_session_id: str,
    child_agent_id: str = "agent-worker",
    capabilities: Optional[list[str]] = None,
    compartment: Optional[str] = None,
    expires_in_s: int = 120,
) -> Response:
    return client.post(
        "/v1/delegate",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "child_agent_id": child_agent_id,
            "child_session_id": child_session_id,
            "capabilities": capabilities or [],
            "compartment": compartment,
            "expires_in_s": expires_in_s,
        },
    )


def _authorize(client: TestClient, token: str) -> Response:
    return client.post(
        "/v1/authorize",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "source_format": "raw_mcp",
            "tool_call": {"tool": _AUTO_ALIAS, "arguments": {"period": "2026-Q2"}},
        },
    )


# ---------------------------------------------------------------------------
# The flag.
# ---------------------------------------------------------------------------


def test_flag_off_the_surface_does_not_exist_and_claims_deny(
    client: TestClient, idp: _DemoIdP
) -> None:
    assert _components.settings.delegation_enabled is False  # the documented default
    sid = str(uuid.uuid4())
    resp = _delegate(client, _mint_parent(idp, session_id=sid), child_session_id=str(uuid.uuid4()))
    assert resp.status_code == 404

    # A token CARRYING delegation_id while the feature is off must deny — ignoring
    # the claim would grant MORE than the token was minted for.
    token = idp.mint(
        tenant_id=_TENANT,
        agent_id="agent-worker",
        session_id=str(uuid.uuid4()),
        delegation_id=str(uuid.uuid4()),
    )
    denied = _authorize(client, token)
    assert denied.status_code == 403
    assert "delegation" not in denied.text.lower()  # opaque


# ---------------------------------------------------------------------------
# Registration rules.
# ---------------------------------------------------------------------------


def test_register_requires_a_session_and_refuses_excess_capabilities(
    client: TestClient, idp: _DemoIdP, enabled: None
) -> None:
    # No session claim → diagnosable 400 (the parent's mistake, named).
    no_session = idp.mint(tenant_id=_TENANT, agent_id="agent-dispatcher")
    resp = _delegate(client, no_session, child_session_id=str(uuid.uuid4()))
    assert resp.status_code == 400
    assert "session_id" in resp.text

    # Requesting a capability the parent lacks → the WHOLE registration refused.
    parent = _mint_parent(idp, session_id=str(uuid.uuid4()), capabilities=[])
    resp = _delegate(
        client,
        parent,
        child_session_id=str(uuid.uuid4()),
        capabilities=[CAP_DIRECTORY_ADMIN],
    )
    assert resp.status_code == 400
    assert "not held" in resp.text


def test_delegated_token_is_narrowed_to_the_intersection(
    client: TestClient, idp: _DemoIdP, enabled: None
) -> None:
    """Parent holds CAP_DIRECTORY_ADMIN; the grant deliberately does NOT hand it
    down. The child's JWT still CLAIMS the capability — and the admin surface
    must refuse it, because the intersection with the grant is empty."""
    parent_sid, child_sid = str(uuid.uuid4()), str(uuid.uuid4())
    parent = _mint_parent(
        idp, session_id=parent_sid, capabilities=[CAP_DIRECTORY_ADMIN]
    )
    granted = _delegate(
        client, parent, child_session_id=child_sid, capabilities=[]
    )
    assert granted.status_code == 201, granted.text
    delegation_id = _json(granted)["delegation_id"]

    child = idp.mint(
        tenant_id=_TENANT,
        agent_id="agent-worker",
        session_id=child_sid,
        capabilities=[CAP_DIRECTORY_ADMIN],  # claimed, but not granted
        delegation_id=delegation_id,
    )
    admin_read = client.get(
        "/v1/admin/users", headers={"Authorization": f"Bearer {child}"}
    )
    assert admin_read.status_code == 403, admin_read.text

    # ...while the ordinary authorize path still works (nothing else narrowed).
    allowed = _authorize(client, child)
    assert allowed.status_code == 200, allowed.text
    assert _json(allowed)["decision"] == "allow"


def test_handed_down_capability_survives_the_intersection(
    client: TestClient, idp: _DemoIdP, enabled: None
) -> None:
    parent_sid, child_sid = str(uuid.uuid4()), str(uuid.uuid4())
    parent = _mint_parent(idp, session_id=parent_sid, capabilities=[CAP_DIRECTORY_ADMIN])
    granted = _delegate(
        client, parent, child_session_id=child_sid, capabilities=[CAP_DIRECTORY_ADMIN]
    )
    assert granted.status_code == 201, granted.text
    child = idp.mint(
        tenant_id=_TENANT,
        agent_id="agent-worker",
        session_id=child_sid,
        capabilities=[CAP_DIRECTORY_ADMIN],
        delegation_id=_json(granted)["delegation_id"],
    )
    admin_read = client.get(
        "/v1/admin/users", headers={"Authorization": f"Bearer {child}"}
    )
    assert admin_read.status_code == 200, admin_read.text


# ---------------------------------------------------------------------------
# Fail-closed grant liveness.
# ---------------------------------------------------------------------------


def test_missing_grant_denies_and_the_reason_lands_in_the_projection(
    client: TestClient, idp: _DemoIdP, enabled: None
) -> None:
    token = idp.mint(
        tenant_id=_TENANT,
        agent_id="agent-worker",
        session_id=str(uuid.uuid4()),
        delegation_id=str(uuid.uuid4()),  # no such grant
    )
    denied = _authorize(client, token)
    assert denied.status_code == 403
    corr = _json(denied)["correlation_id"]

    admin = idp.mint(
        tenant_id=_TENANT, agent_id="agent-adm", capabilities=[CAP_DIRECTORY_ADMIN]
    )
    feed = client.get(
        "/v1/admin/decisions/recent?limit=100",
        headers={"Authorization": f"Bearer {admin}"},
    )
    row = next(
        r for r in _json(feed)["decisions"] if r.get("correlation_id") == corr
    )
    assert row["deny_reason"] == "delegation_invalid"


def test_binding_mismatches_deny(
    client: TestClient, idp: _DemoIdP, enabled: None
) -> None:
    parent_sid, child_sid = str(uuid.uuid4()), str(uuid.uuid4())
    parent = _mint_parent(idp, session_id=parent_sid)
    granted = _delegate(client, parent, child_session_id=child_sid)
    assert granted.status_code == 201
    delegation_id = _json(granted)["delegation_id"]

    # Wrong session: the grant is not a bearer widget.
    wrong_session = idp.mint(
        tenant_id=_TENANT,
        agent_id="agent-worker",
        session_id=str(uuid.uuid4()),
        delegation_id=delegation_id,
    )
    assert _authorize(client, wrong_session).status_code == 403

    # Wrong agent, right session.
    wrong_agent = idp.mint(
        tenant_id=_TENANT,
        agent_id="agent-impostor",
        session_id=child_sid,
        delegation_id=delegation_id,
    )
    assert _authorize(client, wrong_agent).status_code == 403


# ---------------------------------------------------------------------------
# Revocation cascade.
# ---------------------------------------------------------------------------


def _spawn_chain(
    client: TestClient, idp: _DemoIdP, depth: int
) -> list[tuple[str, str, str]]:
    """Build a delegation chain of ``depth`` links. Returns
    [(session_id, delegation_id, token), ...] child-first order excluded — root
    parent first."""
    out: list[tuple[str, str, str]] = []
    parent_sid = str(uuid.uuid4())
    parent_token = _mint_parent(idp, session_id=parent_sid)
    out.append((parent_sid, "", parent_token))
    for _ in range(depth):
        child_sid = str(uuid.uuid4())
        granted = _delegate(
            client, out[-1][2], child_session_id=child_sid, child_agent_id="agent-worker"
        )
        assert granted.status_code == 201, granted.text
        did = _json(granted)["delegation_id"]
        token = idp.mint(
            tenant_id=_TENANT,
            agent_id="agent-worker",
            session_id=child_sid,
            delegation_id=did,
        )
        out.append((child_sid, did, token))
    return out


def test_parent_revokes_a_descendant_and_the_subtree_dies(
    client: TestClient, idp: _DemoIdP, enabled: None
) -> None:
    chain = _spawn_chain(client, idp, 3)
    root_sid, _, root_token = chain[0]
    mid_sid = chain[1][0]
    leaf_token = chain[3][2]

    assert _authorize(client, leaf_token).status_code == 200

    # The ROOT revokes the MID session — the grandchild leaf must die with it.
    resp = client.post(
        "/v1/delegate/revoke",
        headers={"Authorization": f"Bearer {root_token}"},
        json={"session_id": mid_sid},
    )
    assert resp.status_code == 200, resp.text
    assert _authorize(client, leaf_token).status_code == 403

    # A STRANGER session cannot revoke anything (opaque, no existence oracle).
    stranger = _mint_parent(idp, session_id=str(uuid.uuid4()))
    resp = client.post(
        "/v1/delegate/revoke",
        headers={"Authorization": f"Bearer {stranger}"},
        json={"session_id": root_sid},
    )
    assert resp.status_code == 403


def test_depth_limit_holds(client: TestClient, idp: _DemoIdP, enabled: None) -> None:
    chain = _spawn_chain(client, idp, 4)  # depths 1..4 succeed
    deepest_token = chain[-1][2]
    resp = _delegate(client, deepest_token, child_session_id=str(uuid.uuid4()))
    assert resp.status_code == 400
    assert "depth" in resp.text


def test_admin_lists_and_revokes(
    client: TestClient, idp: _DemoIdP, enabled: None
) -> None:
    chain = _spawn_chain(client, idp, 1)
    child_sid, child_token = chain[1][0], chain[1][2]
    admin = idp.mint(
        tenant_id=_TENANT, agent_id="agent-adm2", capabilities=[CAP_DIRECTORY_ADMIN]
    )
    listing = client.get(
        "/v1/admin/delegations", headers={"Authorization": f"Bearer {admin}"}
    )
    assert listing.status_code == 200
    rows = _json(listing)["delegations"]
    assert any(r["child_session_id"] == child_sid for r in rows)

    resp = client.post(
        "/v1/admin/delegations/revoke",
        headers={"Authorization": f"Bearer {admin}"},
        json={"session_id": child_sid},
    )
    assert resp.status_code == 200
    assert _authorize(client, child_token).status_code == 403
