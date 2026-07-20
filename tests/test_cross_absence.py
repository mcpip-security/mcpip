"""
MCPIP V2 — CROSS suite: DENY-BY-DEFAULT / "nothing was created" absence scenarios.

    ◐  "Authorize every AI action before execution — and when the enabling thing
        was never created, deny, opaquely, and say why only to the WORM log."

Every gate in MCPIP defaults to DENY when the thing that would enable an ALLOW is
ABSENT: an alias that was never registered (or was disabled / deregistered), a
compartment grant that was never issued, a capability the JWT never carried, a
sender-constraint proof that was never presented, a payload lock that was never
staged, a tenant whose catalog is empty. This module drives those "absence" paths
through the SAME Starlette ``TestClient`` the primary authorize suite uses and asserts
the invariant BOTH ways on every deny:

  * the CALLER sees only the opaque ``{error, correlation_id}`` envelope (403) — a
    denial NEVER leaks whether the thing exists (no 200-with-empty existence oracle);
  * the concrete reason lands in the durable WORM buffer (read directly), where the
    operator — and only the operator — learns *why*.

Self-contained per the cross-test brief: every tenant / agent / alias is a fresh
``uuid4`` so no test depends on a clean db or on another test's state; nothing asserts
a global count; no network / SMTP / socket is touched.

The Redis db is chosen via ``setdefault`` (fallback ``/2``); the WORM reader binds to
whatever ``MCPIP_REDIS_URL`` the composition root actually booted with, so the
opaque-vs-logged split is proven against the SAME db in a standalone run and inside the
full suite alike.
"""

from __future__ import annotations

import os
import sys

# Make the repo root importable when run directly; pytest already adds it via rootdir.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# --- Namespaced sandbox environment MUST be set before importing app.main, whose
#     composition root reads the (lru_cached) settings once, at import. --------------
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault("MCPIP_REDIS_URL", "redis://localhost:63790/2")
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_cross_absence_worm.jsonl"),
)

# The db the gateway actually booted with (== our setdefault standalone; == whatever an
# earlier-imported API suite already pinned, when run inside the full suite). Binding the
# WORM reader here keeps the opaque-vs-logged proof reading the SAME stream the app writes.
_TEST_REDIS_URL = os.environ["MCPIP_REDIS_URL"]

import json
import uuid
from typing import Any, Iterator, Optional

import pytest
import redis as redis_sync
from fastapi.testclient import TestClient
from httpx import Response

from core.security import AGENT_FACING_DENY_MESSAGE
from interfaces import CAP_COMPARTMENT_GRANT, CAP_DIRECTORY_ADMIN, grant_capability_for
from obfuscator.tenant_catalog import (
    AEGIS,
    FALCON,
    MCPIP_ENGINEERING,
    MCPIP_FINANCE,
    SENTINEL,
)

from app.main import _components, app
from main import _DemoIdP, _tamper_signature

_EVENTS_STREAM = "mcpip:worm:events"
_CORR_HEADER = "x-mcpip-correlation-id"

# Well-known catalog aliases exercised as "present here, absent there" probes.
_ACME_AUTO = "skill_spend_summary"       # tenant-acme, AUTO
_ACME_PIN = "skill_payroll_run"          # tenant-acme, PIN_REQUIRED
_ACME_ONLY = "skill_wire_transfer"       # tenant-acme, PIN_REQUIRED
_SHARED_AUTO = "skill_status_probe"      # acme + globex + aegis, AUTO, un-compartmented
_AEGIS = "aegis-dynamics"
_FALCON_TELEMETRY = "skill_falcon_telemetry"   # aegis, FALCON, AUTO, sender-constraint
_FALCON_FLIGHT = "skill_falcon_flight_cmd"     # aegis, FALCON, PIN, no sender-constraint
_AEGIS_RADAR = "skill_aegis_radar_tune"        # aegis, AEGIS, PIN
_AEGIS_INTERCEPT = "skill_aegis_intercept_plan"  # aegis, AEGIS, PIN
_SENTINEL_FEED = "skill_sentinel_recon_feed"   # aegis, SENTINEL, AUTO, sender-constraint
_GRANT_ALIAS = "skill_compartment_grant"       # aegis, grant_issue, cap-gated
_MCPIP_FINANCE_WAGES = "skill_financial_wage_sheet"  # mcpip-inc, FINANCE compartment


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def idp() -> _DemoIdP:
    """The in-process sandbox IdP the composition root booted (same keypair)."""
    demo = _components.demo_idp
    assert demo is not None, "sandbox IdP must be present in sandbox mode"
    return demo


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    """Module-scoped TestClient. Deliberately does NOT flush the db (no clean-db
    assumption): every test mints unique ids and reads only the WORM tail it just wrote."""
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Fresh-id + envelope helpers (unique per test — the brief's self-containment rule).
# ---------------------------------------------------------------------------


def _tid() -> str:
    """A never-before-seen tenant id (its catalog is empty by construction)."""
    return f"tenant-{uuid.uuid4().hex}"


def _aid() -> str:
    """A never-before-seen agent id (so quarantine/lock state never bleeds across tests)."""
    return f"agent-{uuid.uuid4().hex}"


def _alias() -> str:
    """A never-registered opaque alias name."""
    return f"skill_{uuid.uuid4().hex}"


def _bh(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _openai_call(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Wrap arguments in an OpenAI ``tool_call`` envelope (bridge deep-validates)."""
    return {
        "id": "call_absence",
        "type": "function",
        "function": {"name": alias, "arguments": json.dumps(arguments)},
    }


def _post(
    client: TestClient,
    *,
    alias: str,
    arguments: dict[str, Any],
    token: Optional[str] = None,
    bearer: Optional[str] = None,
    pin: Optional[str] = None,
    challenge_id: Optional[str] = None,
) -> Response:
    """POST ``/v1/authorize`` with an OpenAI envelope; identity via body ``jwt`` or header."""
    body: dict[str, Any] = {
        "source_format": "openai_tool_call",
        "tool_call": _openai_call(alias, arguments),
    }
    if token is not None:
        body["jwt"] = token
    if pin is not None:
        body["pin"] = pin
    if challenge_id is not None:
        body["challenge_id"] = challenge_id
    headers: dict[str, str] = {}
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    return client.post("/v1/authorize", json=body, headers=headers)


def _json(resp: Response) -> dict[str, Any]:
    data: Any = resp.json()
    assert isinstance(data, dict)
    return data


def _assert_opaque_denial(resp: Response) -> None:
    """A policy deny is EXACTLY ``{error, correlation_id}`` (403) + an echoed header id —
    identical for every reason, so the caller can never tell absence-of-X from absence-of-Y."""
    assert resp.status_code == 403, resp.text
    data = _json(resp)
    assert set(data.keys()) == {"error", "correlation_id"}, data
    assert data["error"] == AGENT_FACING_DENY_MESSAGE
    header_id = resp.headers.get(_CORR_HEADER)
    assert header_id is not None
    assert header_id == data["correlation_id"]


def _last_deny_reason() -> Optional[str]:
    """Read the most-recently buffered WORM event's concrete ``deny_reason`` (WORM-only)."""
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


def _worm_dump() -> str:
    """Raw concatenation of the recent WORM records — for the wire-vs-log split proof."""
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=50)
    finally:
        reader.close()
    return "".join(fields.get("record", "") for _sid, fields in entries)


def _admin(idp: _DemoIdP, tenant: str) -> str:
    """Mint a CAP_DIRECTORY_ADMIN token in ``tenant`` (fresh admin agent id)."""
    return idp.mint(
        tenant_id=tenant, agent_id=_aid(), capabilities=[CAP_DIRECTORY_ADMIN]
    )


def _register(
    client: TestClient, admin: str, alias: str, *, risk: str = "auto"
) -> Response:
    """Register a NEW overlay skill (additive-only; cloud_rest target)."""
    return client.post(
        "/v1/admin/skills/register",
        json={"alias": alias, "target": f"rest.{uuid.uuid4().hex}.get", "risk_tier": risk},
        headers=_bh(admin),
    )


def _cnf_token(idp: _DemoIdP, *, tenant_id: str, agent_id: str) -> str:
    """A validly-signed token carrying a ``cnf.jkt`` (so it is NOT a bearer token) but for
    which NO DPoP proof is ever presented — the possession proof is ABSENT."""
    import time

    import jwt as _jwt

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
        "cnf": {"jkt": uuid.uuid4().hex},  # a plausible thumbprint; no matching proof exists.
    }
    return _jwt.encode(claims, idp._private_pem, algorithm="EdDSA")


# ===========================================================================
# A. A never-registered alias → opaque deny + concrete WORM ``unknown_alias``.
# ===========================================================================


def test_never_registered_alias_denies_unknown_alias(client: TestClient, idp: _DemoIdP) -> None:
    """No gate is created for an alias nobody registered → opaque 403, WORM unknown_alias."""
    resp = _post(client, alias=_alias(), arguments={}, token=idp.mint(agent_id=_aid()))
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "unknown_alias"


def test_never_registered_alias_is_opaque_envelope(client: TestClient, idp: _DemoIdP) -> None:
    """The absent-alias denial body is exactly the generic envelope — nothing else."""
    resp = _post(client, alias=_alias(), arguments={"x": 1}, token=idp.mint(agent_id=_aid()))
    assert resp.status_code == 403
    assert set(_json(resp).keys()) == {"error", "correlation_id"}


def test_two_distinct_random_aliases_both_unknown(client: TestClient, idp: _DemoIdP) -> None:
    """Two independent never-registered aliases each deny the SAME opaque way + reason."""
    for _ in range(2):
        resp = _post(client, alias=_alias(), arguments={}, token=idp.mint(agent_id=_aid()))
        _assert_opaque_denial(resp)
        assert _last_deny_reason() == "unknown_alias"


def test_unknown_alias_reason_never_crosses_the_wire(client: TestClient, idp: _DemoIdP) -> None:
    """The concrete reason lands in the durable WORM buffer but NEVER in the caller's body."""
    resp = _post(client, alias=_alias(), arguments={}, token=idp.mint(agent_id=_aid()))
    _assert_opaque_denial(resp)
    assert "unknown_alias" not in resp.text          # opaque to the agent …
    assert "unknown_alias" in _worm_dump()           # … recorded for the operator.
    assert _last_deny_reason() == "unknown_alias"


def test_unknown_alias_with_empty_arguments(client: TestClient, idp: _DemoIdP) -> None:
    """An absent alias with an empty argument object still fails closed (no lenient path)."""
    resp = _post(client, alias=_alias(), arguments={}, token=idp.mint(agent_id=_aid()))
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "unknown_alias"


def test_unknown_alias_leaks_no_receipt_fields(client: TestClient, idp: _DemoIdP) -> None:
    """An absent alias never yields the ALLOW-shaped keys (no target class / txn ref)."""
    resp = _post(client, alias=_alias(), arguments={}, token=idp.mint(agent_id=_aid()))
    _assert_opaque_denial(resp)
    body = _json(resp)
    assert "executed_target_class" not in body
    assert "transaction_ref" not in body
    assert "decision" not in body


# ===========================================================================
# B. No verified identity present → deny (identity is the enabling thing).
# ===========================================================================


def test_authorize_without_any_jwt_denied(client: TestClient) -> None:
    """No JWT anywhere (body or header) → opaque 403: absent identity authorizes nothing."""
    resp = _post(client, alias=_ACME_AUTO, arguments={"period": "Q1"})
    _assert_opaque_denial(resp)


def test_catalog_without_jwt_denied(client: TestClient) -> None:
    """The catalog is JWT-gated — absent identity → opaque 403 (no anonymous enumeration)."""
    resp = client.get("/v1/catalog")
    assert resp.status_code == 403


def test_forged_jwt_identity_absent_denied(client: TestClient, idp: _DemoIdP) -> None:
    """A signature-tampered JWT proves no identity → opaque 403, WORM jwt_invalid."""
    resp = _post(
        client, alias=_ACME_AUTO, arguments={"period": "Q1"},
        token=_tamper_signature(idp.mint(agent_id=_aid())),
    )
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "jwt_invalid"


# ===========================================================================
# C. Unknown tenant / empty catalog → deny; nothing is visible by default.
# ===========================================================================


def test_unknown_tenant_known_alias_is_cross_tenant(client: TestClient, idp: _DemoIdP) -> None:
    """A brand-new tenant reaching a real (other-tenant) alias → opaque 403, cross_tenant."""
    token = idp.mint(tenant_id=_tid(), agent_id=_aid())
    resp = _post(client, alias=_ACME_AUTO, arguments={"period": "Q1"}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "cross_tenant"


def test_unknown_tenant_random_alias_is_unknown_alias(client: TestClient, idp: _DemoIdP) -> None:
    """A brand-new tenant reaching a never-registered alias → opaque 403, unknown_alias."""
    token = idp.mint(tenant_id=_tid(), agent_id=_aid())
    resp = _post(client, alias=_alias(), arguments={}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "unknown_alias"


def test_unknown_tenant_catalog_is_empty(client: TestClient, idp: _DemoIdP) -> None:
    """A tenant with no rows sees an EMPTY catalog (200, []): deny-by-default visibility,
    not a leak of other tenants' aliases and not an error."""
    token = idp.mint(tenant_id=_tid(), agent_id=_aid())
    resp = client.get("/v1/catalog", headers=_bh(token))
    assert resp.status_code == 200, resp.text
    assert _json(resp)["catalog"] == []


def test_unknown_tenant_every_known_alias_denied(client: TestClient, idp: _DemoIdP) -> None:
    """From an empty-catalog tenant, EVERY real alias of every other tenant denies opaquely."""
    token = idp.mint(tenant_id=_tid(), agent_id=_aid())
    for alias in (_ACME_AUTO, _ACME_PIN, _FALCON_TELEMETRY, _MCPIP_FINANCE_WAGES):
        resp = _post(client, alias=alias, arguments={}, token=token)
        _assert_opaque_denial(resp)
        assert _last_deny_reason() == "cross_tenant"


def test_fresh_agent_valid_tenant_random_alias_unknown(client: TestClient, idp: _DemoIdP) -> None:
    """A never-seen agent in a REAL tenant is still denied a never-registered alias —
    a valid identity does not conjure a nonexistent skill."""
    token = idp.mint(tenant_id="tenant-acme", agent_id=_aid())
    resp = _post(client, alias=_alias(), arguments={}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "unknown_alias"


# ===========================================================================
# D. Per-tenant isolation — present for tenant A is ABSENT for tenant B → deny.
# ===========================================================================


def test_acme_pin_alias_absent_for_globex_cross_tenant(client: TestClient, idp: _DemoIdP) -> None:
    """tenant-acme's payroll alias does not exist for tenant-globex → opaque cross_tenant."""
    token = idp.mint(tenant_id="tenant-globex", agent_id=_aid())
    resp = _post(client, alias=_ACME_PIN, arguments={"run_id": "x"}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "cross_tenant"


def test_aegis_alias_absent_for_acme_cross_tenant(client: TestClient, idp: _DemoIdP) -> None:
    """A defense-tenant alias is absent for tenant-acme → opaque cross_tenant."""
    token = idp.mint(tenant_id="tenant-acme", agent_id=_aid())
    resp = _post(client, alias=_FALCON_TELEMETRY, arguments={}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "cross_tenant"


def test_mcpip_alias_absent_for_acme_cross_tenant(client: TestClient, idp: _DemoIdP) -> None:
    """The demo-company finance alias is absent for tenant-acme → opaque cross_tenant."""
    token = idp.mint(tenant_id="tenant-acme", agent_id=_aid())
    resp = _post(client, alias=_MCPIP_FINANCE_WAGES, arguments={}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "cross_tenant"


def test_shared_alias_present_but_acme_only_absent_for_globex(
    client: TestClient, idp: _DemoIdP
) -> None:
    """Isolation is per-alias: globex CAN reach the shared probe (200) yet an acme-only
    alias of the SAME tenant surface is absent for it → cross_tenant."""
    token = idp.mint(tenant_id="tenant-globex", agent_id=_aid())
    shared = _post(client, alias=_SHARED_AUTO, arguments={}, token=token)
    assert shared.status_code == 200, shared.text
    absent = _post(client, alias=_ACME_ONLY, arguments={"amount": "1"}, token=token)
    _assert_opaque_denial(absent)
    assert _last_deny_reason() == "cross_tenant"


def test_acme_alias_absent_for_fresh_tenant_cross_tenant(client: TestClient, idp: _DemoIdP) -> None:
    """A freshly-minted tenant never owns tenant-acme's alias → opaque cross_tenant."""
    token = idp.mint(tenant_id=_tid(), agent_id=_aid())
    resp = _post(client, alias=_ACME_ONLY, arguments={"amount": "1"}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "cross_tenant"


# ===========================================================================
# E. A compartment grant that was never issued → COMPARTMENT_DENIED.
# ===========================================================================


def test_compartment_alias_denied_without_native_scope(client: TestClient, idp: _DemoIdP) -> None:
    """A defense agent with NO compartment claim and NO grant cannot reach a compartmented
    alias → opaque 403, WORM compartment_denied."""
    token = idp.mint(tenant_id=_AEGIS, agent_id=_aid())  # no compartment, no grant.
    resp = _post(client, alias=_FALCON_FLIGHT, arguments={}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "compartment_denied"


def test_compartment_alias_denied_with_wrong_compartment(client: TestClient, idp: _DemoIdP) -> None:
    """A FALCON-scoped agent reaching an AEGIS alias holds the wrong need-to-know and has
    no cross grant → opaque compartment_denied."""
    token = idp.mint(tenant_id=_AEGIS, agent_id=_aid(), compartment=FALCON)
    resp = _post(client, alias=_AEGIS_RADAR, arguments={}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "compartment_denied"


def test_falcon_alias_denied_for_sentinel_agent(client: TestClient, idp: _DemoIdP) -> None:
    """A SENTINEL agent has no FALCON grant → the FALCON alias is denied compartment_denied."""
    token = idp.mint(tenant_id=_AEGIS, agent_id=_aid(), compartment=SENTINEL)
    resp = _post(client, alias=_FALCON_FLIGHT, arguments={}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "compartment_denied"


def test_aegis_intercept_denied_for_no_compartment(client: TestClient, idp: _DemoIdP) -> None:
    """The AEGIS intercept alias with neither native scope nor grant → compartment_denied."""
    token = idp.mint(tenant_id=_AEGIS, agent_id=_aid())
    resp = _post(client, alias=_AEGIS_INTERCEPT, arguments={}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "compartment_denied"


def test_mcpip_finance_denied_for_engineering(client: TestClient, idp: _DemoIdP) -> None:
    """A demo-company ENGINEERING agent has no FINANCE grant → the wage sheet is denied."""
    token = idp.mint(tenant_id="mcpip-inc", agent_id=_aid(), compartment=MCPIP_ENGINEERING)
    resp = _post(client, alias=_MCPIP_FINANCE_WAGES, arguments={}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "compartment_denied"


def test_mcpip_finance_denied_for_no_compartment(client: TestClient, idp: _DemoIdP) -> None:
    """A demo-company agent with no team compartment cannot read the FINANCE wage sheet."""
    token = idp.mint(tenant_id="mcpip-inc", agent_id=_aid())
    resp = _post(client, alias=_MCPIP_FINANCE_WAGES, arguments={}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "compartment_denied"


def test_grant_absent_grantee_denied_compartment(client: TestClient, idp: _DemoIdP) -> None:
    """A fresh would-be grantee that was NEVER granted anything is denied the compartment —
    the absence of an issued grant IS the deny (compartment_denied)."""
    grantee = idp.mint(tenant_id=_AEGIS, agent_id=_aid())  # never appears in any GrantStore key.
    resp = _post(client, alias=_FALCON_FLIGHT, arguments={}, token=grantee)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "compartment_denied"


def test_compartment_denied_is_opaque_and_worm_logged(client: TestClient, idp: _DemoIdP) -> None:
    """The compartment deny is opaque to the agent yet concretely recorded to WORM."""
    token = idp.mint(tenant_id=_AEGIS, agent_id=_aid(), compartment=AEGIS)
    resp = _post(client, alias=_FALCON_FLIGHT, arguments={}, token=token)
    _assert_opaque_denial(resp)
    assert "compartment" not in resp.text
    assert _last_deny_reason() == "compartment_denied"


# ===========================================================================
# F. A required capability the JWT never carried → CAPABILITY_DENIED.
# ===========================================================================


def test_grant_governance_denied_without_capability(client: TestClient, idp: _DemoIdP) -> None:
    """Issuing a grant needs CAP_COMPARTMENT_GRANT; absent it → opaque 403, capability_denied
    (the mandate gate runs BEFORE PIN staging, so the deny fires with no pin)."""
    officer = idp.mint(tenant_id=_AEGIS, agent_id=_aid())  # no capabilities at all.
    args = {"grantee": _aid(), "compartment": FALCON}
    resp = _post(client, alias=_GRANT_ALIAS, arguments=args, token=officer)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "capability_denied"


def test_grant_governance_denied_without_scoped_capability(client: TestClient, idp: _DemoIdP) -> None:
    """Holding only the COARSE grant capability (no compartment-SCOPED one) still cannot
    issue a compartment grant — the scoped authority is absent → capability_denied."""
    officer = idp.mint(
        tenant_id=_AEGIS, agent_id=_aid(), capabilities=[CAP_COMPARTMENT_GRANT]
    )
    args = {"grantee": _aid(), "compartment": FALCON, "ttl_seconds": 3600}
    resp = _post(client, alias=_GRANT_ALIAS, arguments=args, token=officer)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "capability_denied"


def test_capability_denied_is_opaque_and_worm_logged(client: TestClient, idp: _DemoIdP) -> None:
    """A missing-capability governance call is opaque to the caller, concrete in WORM; the
    intended grantee gains nothing (a classified AEGIS alias stays denied for it)."""
    officer = idp.mint(tenant_id=_AEGIS, agent_id=_aid())
    mole = _aid()
    denied = _post(
        client, alias=_GRANT_ALIAS,
        arguments={"grantee": mole, "compartment": AEGIS}, token=officer,
    )
    _assert_opaque_denial(denied)
    assert _last_deny_reason() == "capability_denied"
    mole_token = idp.mint(tenant_id=_AEGIS, agent_id=mole)
    still = _post(client, alias=_AEGIS_RADAR, arguments={}, token=mole_token)
    _assert_opaque_denial(still)
    assert _last_deny_reason() == "compartment_denied"


# ===========================================================================
# G. A sender-constraint proof that was never presented → fail closed (never fail open).
#    The resource DEMANDS a key-proof "gate"; when none is presented the request is
#    denied, not admitted.
# ===========================================================================


def test_falcon_telemetry_bare_bearer_denied_sender_constraint(
    client: TestClient, idp: _DemoIdP
) -> None:
    """A FALCON alias that DEMANDS sender-constraint: an entitled but BARE bearer (no proof)
    is denied SENDER_CONSTRAINT_REQUIRED — fail-closed, never fail-open on the missing proof."""
    token = idp.mint(tenant_id=_AEGIS, agent_id=_aid(), compartment=FALCON)
    resp = _post(client, alias=_FALCON_TELEMETRY, arguments={}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "sender_constraint_required"


def test_sentinel_feed_bare_bearer_denied_sender_constraint(
    client: TestClient, idp: _DemoIdP
) -> None:
    """The SENTINEL recon feed likewise demands a key-proof; a bare bearer → the proof is
    absent → SENDER_CONSTRAINT_REQUIRED."""
    token = idp.mint(tenant_id=_AEGIS, agent_id=_aid(), compartment=SENTINEL)
    resp = _post(client, alias=_SENTINEL_FEED, arguments={}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "sender_constraint_required"


def test_cnf_token_without_dpop_proof_denied_jwt_invalid(client: TestClient, idp: _DemoIdP) -> None:
    """A cnf-bound token is NOT a bearer token: with NO DPoP proof presented, the demanded
    possession proof is absent → opaque 403, WORM jwt_invalid (distinct from a bad proof)."""
    token = _cnf_token(idp, tenant_id="tenant-acme", agent_id=_aid())
    resp = _post(client, alias=_ACME_AUTO, arguments={"period": "Q1"}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "jwt_invalid"


def test_sender_constraint_deny_is_opaque(client: TestClient, idp: _DemoIdP) -> None:
    """The sender-constraint denial never reveals that a proof was the missing ingredient."""
    token = idp.mint(tenant_id=_AEGIS, agent_id=_aid(), compartment=FALCON)
    resp = _post(client, alias=_FALCON_TELEMETRY, arguments={}, token=token)
    _assert_opaque_denial(resp)
    assert "sender" not in resp.text and "constraint" not in resp.text


# ===========================================================================
# H. A skill that was registered then DISABLED → immediate deny; re-enable restores.
# ===========================================================================


def test_registered_skill_then_disabled_denies_alias_disabled(
    client: TestClient, idp: _DemoIdP
) -> None:
    """Register a new skill, prove it authorizes, then DISABLE it → the very next call is an
    opaque 403 with WORM alias_disabled (off for everyone, regardless of entitlement)."""
    tenant = _tid()
    admin = _admin(idp, tenant)
    alias = _alias()
    assert _register(client, admin, alias).status_code == 200
    assert _post(client, alias=alias, arguments={}, token=idp.mint(tenant_id=tenant, agent_id=_aid())).status_code == 200

    assert client.post(f"/v1/admin/skills/{alias}/disable", headers=_bh(admin)).status_code == 200
    blocked = _post(client, alias=alias, arguments={}, token=idp.mint(tenant_id=tenant, agent_id=_aid()))
    _assert_opaque_denial(blocked)
    assert _last_deny_reason() == "alias_disabled"


def test_disabled_skill_opaque_and_worm_logged(client: TestClient, idp: _DemoIdP) -> None:
    """A disabled skill's deny reason is WORM-only; the agent body stays the opaque envelope."""
    tenant = _tid()
    admin = _admin(idp, tenant)
    alias = _alias()
    assert _register(client, admin, alias).status_code == 200
    assert client.post(f"/v1/admin/skills/{alias}/disable", headers=_bh(admin)).status_code == 200
    resp = _post(client, alias=alias, arguments={}, token=idp.mint(tenant_id=tenant, agent_id=_aid()))
    _assert_opaque_denial(resp)
    assert "alias_disabled" not in resp.text
    assert _last_deny_reason() == "alias_disabled"


def test_disabled_skill_appears_in_disabled_roster(client: TestClient, idp: _DemoIdP) -> None:
    """A disabled skill is enumerated on the admin disabled roster (operator visibility)."""
    tenant = _tid()
    admin = _admin(idp, tenant)
    alias = _alias()
    assert _register(client, admin, alias).status_code == 200
    assert client.post(f"/v1/admin/skills/{alias}/disable", headers=_bh(admin)).status_code == 200
    listing = client.get("/v1/admin/skills/disabled", headers=_bh(admin))
    assert listing.status_code == 200
    assert alias in _json(listing)["disabled"]


def test_disable_then_enable_restores_authorization(client: TestClient, idp: _DemoIdP) -> None:
    """Re-enabling a disabled skill restores it — disable is a reversible DENY, not a delete."""
    tenant = _tid()
    admin = _admin(idp, tenant)
    alias = _alias()
    assert _register(client, admin, alias).status_code == 200
    assert client.post(f"/v1/admin/skills/{alias}/disable", headers=_bh(admin)).status_code == 200
    _assert_opaque_denial(
        _post(client, alias=alias, arguments={}, token=idp.mint(tenant_id=tenant, agent_id=_aid()))
    )
    ez = client.post(f"/v1/admin/skills/{alias}/enable", headers=_bh(admin))
    assert ez.status_code == 200 and _json(ez)["removed"] is True
    assert _post(client, alias=alias, arguments={}, token=idp.mint(tenant_id=tenant, agent_id=_aid())).status_code == 200


# ===========================================================================
# I. A skill that was DEREGISTERED → gone from the catalog + denied unknown_alias.
# ===========================================================================


def test_registered_then_deregistered_is_unknown_alias(client: TestClient, idp: _DemoIdP) -> None:
    """Deregister removes the alias entirely — the next call denies unknown_alias (as if it
    had never existed), opaquely."""
    tenant = _tid()
    admin = _admin(idp, tenant)
    alias = _alias()
    assert _register(client, admin, alias).status_code == 200
    assert client.post(f"/v1/admin/skills/{alias}/deregister", headers=_bh(admin)).status_code == 200
    resp = _post(client, alias=alias, arguments={}, token=idp.mint(tenant_id=tenant, agent_id=_aid()))
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "unknown_alias"


def test_deregistered_skill_absent_from_catalog(client: TestClient, idp: _DemoIdP) -> None:
    """A deregistered skill disappears from the tenant catalog (present, then gone)."""
    tenant = _tid()
    admin = _admin(idp, tenant)
    agent = idp.mint(tenant_id=tenant, agent_id=_aid())
    alias = _alias()
    assert _register(client, admin, alias).status_code == 200
    before = client.get("/v1/catalog", headers=_bh(agent))
    assert alias in {i["alias"] for i in _json(before)["catalog"]}
    assert client.post(f"/v1/admin/skills/{alias}/deregister", headers=_bh(admin)).status_code == 200
    after = client.get("/v1/catalog", headers=_bh(agent))
    assert alias not in {i["alias"] for i in _json(after)["catalog"]}


def test_deregistered_skill_absent_from_registered_roster(client: TestClient, idp: _DemoIdP) -> None:
    """A deregistered skill is no longer listed among operator-registered skills."""
    tenant = _tid()
    admin = _admin(idp, tenant)
    alias = _alias()
    assert _register(client, admin, alias).status_code == 200
    assert alias in _json(client.get("/v1/admin/skills/registered", headers=_bh(admin)))["registered"]
    assert client.post(f"/v1/admin/skills/{alias}/deregister", headers=_bh(admin)).status_code == 200
    assert alias not in _json(client.get("/v1/admin/skills/registered", headers=_bh(admin)))["registered"]


def test_full_register_lifecycle_absent_present_absent(client: TestClient, idp: _DemoIdP) -> None:
    """Absent → (register) → present → (deregister) → absent again: deny is the default at
    both ends of the lifecycle, an ALLOW exists ONLY while the gate is created."""
    tenant = _tid()
    admin = _admin(idp, tenant)
    alias = _alias()

    _assert_opaque_denial(_post(client, alias=alias, arguments={}, token=idp.mint(tenant_id=tenant, agent_id=_aid())))
    assert _last_deny_reason() == "unknown_alias"

    assert _register(client, admin, alias).status_code == 200
    assert _post(client, alias=alias, arguments={}, token=idp.mint(tenant_id=tenant, agent_id=_aid())).status_code == 200

    assert client.post(f"/v1/admin/skills/{alias}/deregister", headers=_bh(admin)).status_code == 200
    _assert_opaque_denial(_post(client, alias=alias, arguments={}, token=idp.mint(tenant_id=tenant, agent_id=_aid())))
    assert _last_deny_reason() == "unknown_alias"


def test_never_registered_alias_absent_from_registered_roster(client: TestClient, idp: _DemoIdP) -> None:
    """Nothing was created: a random alias is not present on a fresh tenant's registered roster."""
    tenant = _tid()
    admin = _admin(idp, tenant)
    roster = _json(client.get("/v1/admin/skills/registered", headers=_bh(admin)))["registered"]
    assert _alias() not in roster


# ===========================================================================
# J. A payload lock that was never staged / no PIN presented → deny (not allow).
# ===========================================================================


def test_pin_required_without_pin_stages_not_allows(client: TestClient, idp: _DemoIdP) -> None:
    """A high-risk alias with NO pin does NOT allow — it stages a 202 challenge, and the
    WORM records pin_required (the OTP is the absent enabling factor)."""
    resp = _post(client, alias=_ACME_PIN, arguments={"run_id": _aid()}, token=idp.mint(agent_id=_aid()))
    assert resp.status_code == 202, resp.text
    body = _json(resp)
    assert "challenge_id" in body
    assert "decision" not in body and "transaction_ref" not in body
    assert _last_deny_reason() == "pin_required"


def test_pin_completion_with_absent_lock_denied_pin_not_found(client: TestClient, idp: _DemoIdP) -> None:
    """Presenting a pin against a challenge that was NEVER staged (no lock exists) → opaque
    403, WORM pin_not_found: absence of the payload lock fails closed."""
    resp = _post(
        client, alias=_ACME_PIN, arguments={"run_id": _aid()},
        token=idp.mint(agent_id=_aid()), pin="123456", challenge_id=uuid.uuid4().hex,
    )
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "pin_not_found"


def test_pin_staging_returns_no_receipt_or_otp(client: TestClient, idp: _DemoIdP) -> None:
    """The staged 202 never carries a receipt NOR the out-of-band OTP (nothing executed)."""
    resp = _post(client, alias=_ACME_PIN, arguments={"run_id": _aid()}, token=idp.mint(agent_id=_aid()))
    assert resp.status_code == 202, resp.text
    body = _json(resp)
    assert "otp" not in body and "pin" not in body
    assert "executed_target_class" not in body and "vended_credential" not in body


# ===========================================================================
# K. Umbrella: absence is ALWAYS opaque + never a 200-with-empty existence oracle.
# ===========================================================================


def test_absence_denials_are_indistinguishable(client: TestClient, idp: _DemoIdP) -> None:
    """Four DIFFERENT absent-enabler reasons (unknown_alias / cross_tenant /
    compartment_denied / capability_denied) all present the byte-identical opaque envelope,
    so the caller can never distinguish which enabling thing was missing."""
    denials = [
        _post(client, alias=_alias(), arguments={}, token=idp.mint(agent_id=_aid())),
        _post(client, alias=_ACME_PIN, arguments={"run_id": "x"},
              token=idp.mint(tenant_id="tenant-globex", agent_id=_aid())),
        _post(client, alias=_FALCON_FLIGHT, arguments={},
              token=idp.mint(tenant_id=_AEGIS, agent_id=_aid(), compartment=AEGIS)),
        _post(client, alias=_GRANT_ALIAS, arguments={"grantee": _aid(), "compartment": FALCON},
              token=idp.mint(tenant_id=_AEGIS, agent_id=_aid())),
    ]
    bodies = []
    for resp in denials:
        _assert_opaque_denial(resp)
        bodies.append(set(_json(resp).keys()))
    assert all(keys == {"error", "correlation_id"} for keys in bodies)


def test_absence_never_yields_200(client: TestClient, idp: _DemoIdP) -> None:
    """No absent target EVER slips through as a 200: a random alias, a cross-tenant alias,
    and an unentitled compartment alias are all 403 — never a permissive fall-through."""
    probes = [
        _post(client, alias=_alias(), arguments={}, token=idp.mint(agent_id=_aid())),
        _post(client, alias=_FALCON_TELEMETRY, arguments={},
              token=idp.mint(tenant_id="tenant-acme", agent_id=_aid())),
        _post(client, alias=_AEGIS_RADAR, arguments={},
              token=idp.mint(tenant_id=_AEGIS, agent_id=_aid(), compartment=FALCON)),
    ]
    assert [p.status_code for p in probes] == [403, 403, 403]


def test_catalog_hides_unentitled_compartment_alias(client: TestClient, idp: _DemoIdP) -> None:
    """An entitlement that was never granted means the compartmented alias is ABSENT from
    the caller's catalog — visibility, like execution, is deny-by-default."""
    token = idp.mint(tenant_id=_AEGIS, agent_id=_aid())  # no compartment.
    resp = client.get("/v1/catalog", headers=_bh(token))
    assert resp.status_code == 200, resp.text
    names = {i["alias"] for i in _json(resp)["catalog"]}
    assert _SHARED_AUTO in names                # tenant-wide, un-compartmented → visible.
    assert _FALCON_TELEMETRY not in names       # FALCON compartment → hidden (no grant).
    assert _AEGIS_RADAR not in names            # AEGIS compartment → hidden.
    assert _SENTINEL_FEED not in names          # SENTINEL compartment → hidden.


def test_disabled_and_unknown_share_opaque_shape(client: TestClient, idp: _DemoIdP) -> None:
    """A disabled-skill deny and an unknown-alias deny are indistinguishable at the wire —
    'disabled' vs 'never existed' is an operator-only (WORM) distinction."""
    tenant = _tid()
    admin = _admin(idp, tenant)
    alias = _alias()
    assert _register(client, admin, alias).status_code == 200
    assert client.post(f"/v1/admin/skills/{alias}/disable", headers=_bh(admin)).status_code == 200

    disabled = _post(client, alias=alias, arguments={}, token=idp.mint(tenant_id=tenant, agent_id=_aid()))
    unknown = _post(client, alias=_alias(), arguments={}, token=idp.mint(tenant_id=tenant, agent_id=_aid()))
    _assert_opaque_denial(disabled)
    _assert_opaque_denial(unknown)
    assert set(_json(disabled)) == set(_json(unknown)) == {"error", "correlation_id"}
    assert _json(disabled)["error"] == _json(unknown)["error"] == AGENT_FACING_DENY_MESSAGE
