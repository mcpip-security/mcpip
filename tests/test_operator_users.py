"""
MCPIP — Operator/team USER MANAGEMENT test suite.

    ◐ "Who may operate the gateway is a roster the admin curates. But the roster
       authorizes nothing — identity + authz stay JWT + capabilities."

Exercises the admin-managed operator roster end-to-end against the REAL composition
root (``app.main._components``), REAL Redis (``:63790``), and the REAL FastAPI edge via
Starlette's ``TestClient`` — nothing under test is mocked. Covers: the CAP_DIRECTORY_ADMIN
gate (opaque deny for a plain token), invite → list → update → remove, additive-only
(no repoint) invitation, email/role/status validation + identity-shaped refusal, the
secret invite token never crossing into the projection or WORM, WORM emit-before-mutate,
tenant isolation, and cursor pagination.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Dedicated db (/14) keeps this suite isolated from the other API suites.
_TEST_REDIS_URL = "redis://localhost:63790/14"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_opusers_test_worm.jsonl"),
)

import json
from typing import Any, Iterator

import pytest
import redis as redis_sync
from fastapi.testclient import TestClient
from httpx import Response

from core.security import AGENT_FACING_DENY_MESSAGE
from interfaces import CAP_DIRECTORY_ADMIN, MAX_OPERATOR_USERS
from services.operator_users import OperatorUserError, normalize_email
from app.main import _components, app

_CORR_HEADER = "x-mcpip-correlation-id"
_EVENTS_STREAM = "mcpip:worm:events"


@pytest.fixture(scope="module")
def idp() -> Any:
    demo = _components.demo_idp
    assert demo is not None, "sandbox IdP must be present in sandbox mode"
    return demo


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    reset: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    reset.flushdb()
    reset.close()
    with TestClient(app) as test_client:
        yield test_client


# --- helpers ----------------------------------------------------------------
def _admin(idp: Any, tenant_id: str = "tenant-acme") -> str:
    return idp.mint(
        tenant_id=tenant_id, agent_id="agent-admin", capabilities=[CAP_DIRECTORY_ADMIN]
    )


def _plain(idp: Any, tenant_id: str = "tenant-acme") -> str:
    return idp.mint(tenant_id=tenant_id, agent_id="agent-plain", capabilities=[])


def _bh(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _json(resp: Response) -> dict[str, Any]:
    data: Any = resp.json()
    assert isinstance(data, dict)
    return data


def _assert_opaque(resp: Response) -> None:
    assert resp.status_code == 403, resp.text
    data = _json(resp)
    assert set(data.keys()) == {"error", "correlation_id"}, data
    assert data["error"] == AGENT_FACING_DENY_MESSAGE


def _invite(client: TestClient, token: str, email: str, role: str = "member") -> Response:
    return client.post(
        "/v1/admin/users/invite", json={"email": email, "role": role}, headers=_bh(token)
    )


def _app_redis_sync() -> Any:
    """A SYNC reader bound to the db the running app ACTUALLY uses.

    ``app.main`` is a module singleton; when this suite runs alongside the other
    API suites, whichever imported first wins the Redis-URL binding — so a
    hardcoded db url would read the wrong stream. Deriving host/port/db from the
    live component's connection pool makes the WORM assertions correct regardless
    of collection order.
    """
    kw: Any = _components.redis_client.connection_pool.connection_kwargs
    return redis_sync.Redis(
        host=kw.get("host", "localhost"),
        port=kw.get("port", 6379),
        db=kw.get("db", 0),
        decode_responses=True,
    )


def _worm_events(action: str) -> list[dict[str, Any]]:
    reader: Any = _app_redis_sync()
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=800)
    finally:
        reader.close()
    out: list[dict[str, Any]] = []
    for _sid, fields in entries:
        rec: Any = json.loads(fields["record"])
        event = rec.get("event", {})
        if isinstance(event, dict) and event.get("admin_action") == action:
            out.append(event)
    return out


def _all_worm_records_raw() -> str:
    reader: Any = _app_redis_sync()
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=800)
    finally:
        reader.close()
    return json.dumps(entries)


# --- store-level unit tests -------------------------------------------------
def test_normalize_email_valid_and_lowercased() -> None:
    assert normalize_email("  Alice@Example.COM ") == "alice@example.com"


@pytest.mark.parametrize(
    "bad",
    ["", "no-at-sign", "a@b", "a@@b.com", "spaces in@x.com", "x@y." , 1, None],
)
def test_normalize_email_rejects_malformed(bad: Any) -> None:
    with pytest.raises(OperatorUserError):
        normalize_email(bad)


def test_normalize_email_rejects_identity_shaped_local_part() -> None:
    # ``role`` is an identity-shaped token — it can never become a roster key.
    with pytest.raises(OperatorUserError):
        normalize_email("role@example.com")


# --- endpoint gating --------------------------------------------------------
def test_all_user_routes_require_directory_admin(client: TestClient, idp: Any) -> None:
    plain = _plain(idp)
    _assert_opaque(client.get("/v1/admin/users", headers=_bh(plain)))
    _assert_opaque(_invite(client, plain, "x@example.com"))
    _assert_opaque(
        client.put("/v1/admin/users/x@example.com", json={"role": "admin"}, headers=_bh(plain))
    )
    _assert_opaque(client.delete("/v1/admin/users/x@example.com", headers=_bh(plain)))


# --- invite → list → update → remove ---------------------------------------
def test_invite_lists_updates_removes_and_audits(client: TestClient, idp: Any) -> None:
    admin = _admin(idp)
    # Invite.
    resp = _invite(client, admin, "Bob@Example.com", role="admin")
    assert resp.status_code == 201, resp.text
    body = _json(resp)
    user = body["user"]
    assert user["email"] == "bob@example.com"
    assert user["role"] == "admin"
    assert user["status"] == "invited"
    assert "invite_token_hash" not in user  # secret hash never projected
    token = body["invite_token"]
    assert isinstance(token, str) and len(token) > 20

    # The raw invite token never entered WORM.
    assert token not in _all_worm_records_raw()
    invites = _worm_events("operator_user_invite")
    assert any(e.get("operator_email") == "bob@example.com" for e in invites)
    assert all("invite_token" not in e for e in invites)

    # List shows the member; projection has no secret.
    listing = _json(client.get("/v1/admin/users", headers=_bh(admin)))
    emails = {u["email"] for u in listing["users"]}
    assert "bob@example.com" in emails
    assert all("invite_token_hash" not in u for u in listing["users"])
    assert listing["count"] >= 1
    assert listing["cap"] == MAX_OPERATOR_USERS

    # Activate (status → active) clears the pending invite.
    upd = client.put(
        "/v1/admin/users/bob@example.com", json={"status": "active"}, headers=_bh(admin)
    )
    assert upd.status_code == 200, upd.text
    assert _json(upd)["user"]["status"] == "active"
    assert _worm_events("operator_user_update")

    # Remove.
    rem = client.delete("/v1/admin/users/bob@example.com", headers=_bh(admin))
    assert rem.status_code == 200 and _json(rem)["removed"] is True
    rem2 = client.delete("/v1/admin/users/bob@example.com", headers=_bh(admin))
    assert _json(rem2)["removed"] is False  # idempotent
    assert _worm_events("operator_user_remove")


def test_invite_is_additive_only_no_repoint(client: TestClient, idp: Any) -> None:
    admin = _admin(idp)
    assert _invite(client, admin, "carol@example.com").status_code == 201
    # A second invite for the same email is an opaque conflict — never a silent repoint.
    _assert_opaque(_invite(client, admin, "Carol@example.com"))


def test_invite_rejects_bad_email_and_role(client: TestClient, idp: Any) -> None:
    admin = _admin(idp)
    _assert_opaque(_invite(client, admin, "not-an-email"))
    _assert_opaque(_invite(client, admin, "role@example.com"))  # identity-shaped stays opaque
    # An UNKNOWN ROLE, for an already-authenticated admin, is a helpful 400 (QA #9) —
    # never an undiagnosable opaque deny. Outsiders still get the opaque deny (they
    # never pass the CAP_DIRECTORY_ADMIN gate that runs before the body is read).
    bad_role = _invite(client, admin, "dave@example.com", role="superuser")
    assert bad_role.status_code == 400
    assert "superuser" in bad_role.text and "allowed" in bad_role.text


def test_update_rejects_unknown_and_bad_status(client: TestClient, idp: Any) -> None:
    admin = _admin(idp)
    # Updating a NON-EXISTENT user stays opaque — never leak whether a user exists.
    _assert_opaque(
        client.put(
            "/v1/admin/users/ghost@example.com", json={"role": "member"}, headers=_bh(admin)
        )
    )
    assert _invite(client, admin, "erin@example.com").status_code == 201
    # An unknown STATUS value / empty body, for an authenticated admin, is a helpful
    # 400 (QA #9) — a vocabulary error the operator can self-fix, not an opaque deny.
    bad_status = client.put(
        "/v1/admin/users/erin@example.com", json={"status": "banished"}, headers=_bh(admin)
    )
    assert bad_status.status_code == 400 and "banished" in bad_status.text
    empty = client.put("/v1/admin/users/erin@example.com", json={}, headers=_bh(admin))
    assert empty.status_code == 400


def test_tenant_isolation(client: TestClient, idp: Any) -> None:
    admin_acme = _admin(idp, "tenant-acme")
    admin_other = _admin(idp, "tenant-other")
    assert _invite(client, admin_acme, "shared@example.com").status_code == 201
    # The other tenant's roster never sees acme's member.
    other = _json(client.get("/v1/admin/users", headers=_bh(admin_other)))
    assert all(u["email"] != "shared@example.com" for u in other["users"])
    # And the other tenant can invite the SAME email independently (separate keyspace).
    assert _invite(client, admin_other, "shared@example.com").status_code == 201


def test_list_pagination_cursor(client: TestClient, idp: Any) -> None:
    admin = _admin(idp, "tenant-page")
    for i in range(5):
        assert _invite(client, admin, f"user{i}@example.com").status_code == 201
    seen: set[str] = set()
    cursor = "0"
    for _ in range(20):  # bounded loop; HSCAN completes well within this
        page = _json(
            client.get(f"/v1/admin/users?cursor={cursor}&limit=2", headers=_bh(admin))
        )
        seen.update(u["email"] for u in page["users"])
        cursor = page["next_cursor"]
        if cursor == "0":
            break
    assert len([e for e in seen if e.startswith("user")]) == 5
