"""
Session attribution (docs/SESSION_DELEGATION_DESIGN.md, phase 1).

The claim under test: an OPTIONAL, VERIFIED ``session_id`` JWT claim rides the
identity into the WORM chain and its tenant-scoped projection, so sessions of
one ``agent_id`` stop collapsing into one indistinguishable principal — while a
token WITHOUT the claim stays byte-for-byte legacy (no key recorded at all).

Fail-closed edge: the claim is UUID-or-deny at the resolver, and the sandbox
forge pre-checks it for a diagnosable 400 instead of a later opaque 403.
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
import stat
import uuid
from typing import Any, Iterator, Optional

import jwt
import pytest
import redis as redis_sync
from fastapi.testclient import TestClient
from httpx import Response

from app.main import _components, app
from interfaces import CAP_DIRECTORY_ADMIN
from main import _DemoIdP

_AUTO_ALIAS = "skill_spend_summary"
_TENANT = "tenant-acme"


# ---------------------------------------------------------------------------
# Fixtures (the established db-5 flush-before-lifespan harness).
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    reset: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    reset.flushdb()
    reset.close()
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def idp(client: TestClient) -> _DemoIdP:
    demo = _components.demo_idp
    assert demo is not None, "sandbox IdP must be present in sandbox mode"
    return demo


def _json(resp: Response) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads(resp.text)
    return parsed


def _authorize(
    client: TestClient, token: str, arguments: Optional[dict[str, Any]] = None
) -> Response:
    return client.post(
        "/v1/authorize",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "source_format": "raw_mcp",
            "tool_call": {"tool": _AUTO_ALIAS, "arguments": arguments or {}},
        },
    )


# ---------------------------------------------------------------------------
# Forge + resolver.
# ---------------------------------------------------------------------------


def test_forge_stamps_the_claim_and_resolver_reads_it(client: TestClient) -> None:
    sid = str(uuid.uuid4())
    resp = client.post("/v1/dev/token", json={"tenant_id": _TENANT, "session_id": sid})
    assert resp.status_code == 200, resp.text
    token = _json(resp)["jwt"]
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["session_id"] == sid

    identity = _components.auth.verify_identity(token)
    assert identity.session_id == sid


def test_absent_claim_resolves_to_none_and_mints_no_key(client: TestClient) -> None:
    resp = client.post("/v1/dev/token", json={"tenant_id": _TENANT})
    assert resp.status_code == 200, resp.text
    token = _json(resp)["jwt"]
    assert "session_id" not in jwt.decode(token, options={"verify_signature": False})
    assert _components.auth.verify_identity(token).session_id is None


def test_forge_rejects_a_malformed_session_id_diagnosably(client: TestClient) -> None:
    resp = client.post(
        "/v1/dev/token", json={"tenant_id": _TENANT, "session_id": "not-a-uuid"}
    )
    assert resp.status_code == 400, resp.text
    assert "not-a-uuid" in resp.text


def test_resolver_fails_closed_on_a_malformed_claim(
    client: TestClient, idp: _DemoIdP
) -> None:
    """A validly-signed token whose session_id is not a UUID must deny opaquely,
    never silently downgrade to an un-sessioned identity."""
    token = idp.mint(session_id="not-a-uuid")
    resp = _authorize(client, token)
    assert resp.status_code == 403, resp.text
    body = _json(resp)
    assert "correlation_id" in body
    assert "session" not in resp.text.lower()  # opaque — the reason never leaks


# ---------------------------------------------------------------------------
# WORM chain + tenant-scoped projection, end to end.
# ---------------------------------------------------------------------------


def _feed_row(
    client: TestClient, idp: _DemoIdP, correlation_id: str
) -> dict[str, Any]:
    admin = idp.mint(
        tenant_id=_TENANT,
        agent_id="agent-session-admin",
        capabilities=[CAP_DIRECTORY_ADMIN],
    )
    resp = client.get(
        "/v1/admin/decisions/recent?limit=200",
        headers={"Authorization": f"Bearer {admin}"},
    )
    assert resp.status_code == 200, resp.text
    for row in _json(resp)["decisions"]:
        if row.get("correlation_id") == correlation_id:
            assert isinstance(row, dict)
            return row
    raise AssertionError(f"correlation {correlation_id} not in the projection")


def test_projection_carries_the_session_of_an_allow(
    client: TestClient, idp: _DemoIdP
) -> None:
    sid = str(uuid.uuid4())
    token = idp.mint(tenant_id=_TENANT, agent_id="agent-worker-1", session_id=sid)
    allowed = _authorize(client, token, {"period": "2026-Q2"})
    assert allowed.status_code == 200, allowed.text
    row = _feed_row(client, idp, _json(allowed)["correlation_id"])
    assert row["session_id"] == sid
    assert row["agent_id"] == "agent-worker-1"


def test_two_sessions_of_one_agent_stay_distinguishable(
    client: TestClient, idp: _DemoIdP
) -> None:
    """The gap this feature closes: same agent_id, two sessions, two rows that
    no longer collapse."""
    sid_a, sid_b = str(uuid.uuid4()), str(uuid.uuid4())
    corr = {}
    for sid in (sid_a, sid_b):
        token = idp.mint(tenant_id=_TENANT, agent_id="agent-worker-2", session_id=sid)
        resp = _authorize(client, token, {"period": "2026-Q3"})
        assert resp.status_code == 200, resp.text
        corr[sid] = _json(resp)["correlation_id"]
    assert _feed_row(client, idp, corr[sid_a])["session_id"] == sid_a
    assert _feed_row(client, idp, corr[sid_b])["session_id"] == sid_b


def test_legacy_token_projects_a_null_session(
    client: TestClient, idp: _DemoIdP
) -> None:
    """Absent → the WORM EVENT records nothing (the ctx stamp is conditional);
    the projection then normalizes shape like every optional safe key — the row
    carries ``session_id: None`` exactly as ``deny_reason`` is None on allows."""
    token = idp.mint(tenant_id=_TENANT, agent_id="agent-worker-3")
    resp = _authorize(client, token, {"period": "2026-Q4"})
    assert resp.status_code == 200, resp.text
    row = _feed_row(client, idp, _json(resp)["correlation_id"])
    assert row["session_id"] is None


def test_whoami_reports_the_session(client: TestClient, idp: _DemoIdP) -> None:
    sid = str(uuid.uuid4())
    token = idp.mint(tenant_id=_TENANT, session_id=sid)
    resp = client.get("/v1/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text
    assert _json(resp)["session_id"] == sid


# ---------------------------------------------------------------------------
# CLI context: the stable per-context id round-trips the config store.
# ---------------------------------------------------------------------------


def test_cli_context_session_id_roundtrips(tmp_path: Any, monkeypatch: Any) -> None:
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk", "python", "src"))
    from mcpip_sdk.cli import config as cfg

    monkeypatch.setenv("MCPIP_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("MCPIP_CONFIG", raising=False)
    sid = str(uuid.uuid4())
    config = cfg.Config(
        current_context="sbx",
        contexts={
            "sbx": cfg.Context(
                name="sbx",
                base_url="http://localhost:8080",
                sandbox=True,
                token_source="file:/tmp/x.jwt",
                session_id=sid,
            )
        },
    )
    cfg.save(config)
    mode = stat.S_IMODE(os.stat(cfg.config_path()).st_mode)
    assert mode == 0o600
    reloaded = cfg.load()
    assert reloaded.contexts["sbx"].session_id == sid
