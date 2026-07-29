"""
MCPIP V2 — /v1/authorize adversarial + compartment/grant + WORM test suite.

    ◐  "Authorize every AI action before execution."

Materializes the 19 adversarial ``POST /v1/authorize`` scenarios plus extras
(catalog filtering, signed Merkle-epoch audit verify, O(log n) inclusion proof, and
direct WORM tamper detection). Driven through Starlette's ``TestClient`` so the FastAPI
lifespan (Redis rebind onto the portal loop + epoch daemon) and every request run on a
single dedicated loop, exactly as production would.

Redis is NAMESPACED to a dedicated db (``/9`` for the API suite, ``/10`` for the
isolated WORM-tamper probe) so concurrent agents/tests never cross-contaminate. The db
is flushed once at session start; ``MCPIP_SANDBOX_MODE=true`` mounts the dev-token /
authenticator / audit affordances the suite drives.

Every scenario asserts BOTH the HTTP contract and — via a direct read of the durable
WORM buffer — that the concrete deny reason landed in the audit log while the agent saw
only the opaque ``{error, correlation_id}`` envelope (invariant #5).
"""

from __future__ import annotations

import os
import sys

# Make the repo root importable when this file is run directly (``python
# tests/test_authorize_api.py``); pytest already adds it via rootdir.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# --- Namespaced sandbox environment MUST be set before importing app.main, whose
#     composition root reads the (lru_cached) settings once, at import. --------------
_TEST_REDIS_URL = "redis://localhost:63790/5"
_TAMPER_REDIS_URL = "redis://localhost:63790/6"
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
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Iterator, Optional

import jwt
import pytest
import redis as redis_sync
import redis.asyncio as aioredis
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from httpx import Response

import base64
import hashlib

from jwt.algorithms import OKPAlgorithm

from audit import WormLogger, merkle
from auth import (
    MultiIssuerResolver,
    StaticPEMKeyProvider,
    TokenResolver,
    lock_payload_hash,
)
from auth.pop import jwk_thumbprint
from core.security import AGENT_FACING_DENY_MESSAGE
from core.version import get_version
from interfaces import (
    JWT_CLOCK_SKEW_LEEWAY_SECONDS,
    CAP_COMPARTMENT_GRANT,
    CAP_DIRECTORY_ADMIN,
    RiskTier,
    grant_capability_for,
)
from obfuscator.alias_registry import AliasEntry
from obfuscator.tenant_catalog import AEGIS, FALCON

from app.main import _components, app
from main import _DemoIdP, _forge_none_token, _tamper_signature

# Aliases exercised across the suite (tenant-acme / aegis-dynamics catalog rows).
_AUTO_ALIAS = "skill_spend_summary"
_PIN_ALIAS = "skill_payroll_run"
_GRANT_ALIAS = "skill_compartment_grant"
_FALCON_ALIAS = "skill_airframe_telemetry"
_CANARY_ALIAS = "skill_export_all_credentials"  # a seeded deception tripwire row.
_AEGIS = "aegis-dynamics"
_EVENTS_STREAM = "mcpip:worm:events"
_CORR_HEADER = "x-mcpip-correlation-id"


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
    """Module-scoped TestClient; flushes the dedicated test db before the lifespan."""
    reset: Any = redis_sync.Redis.from_url(
        _TEST_REDIS_URL, decode_responses=True
    )
    reset.flushdb()
    reset.close()
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _openai_call(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Wrap arguments in an OpenAI ``tool_call`` envelope (bridge deep-validates)."""
    return {
        "id": "call_test",
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
    """POST ``/v1/authorize`` with an OpenAI envelope; identity via body or header."""
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
    resp: Response = client.post("/v1/authorize", json=body, headers=headers)
    return resp


def _json(resp: Response) -> dict[str, Any]:
    """Typed view of a JSON response body."""
    data: Any = resp.json()
    assert isinstance(data, dict)
    return data


def _assert_opaque_denial(resp: Response) -> None:
    """A policy deny is exactly ``{error, correlation_id}`` + an echoed header id."""
    assert resp.status_code == 403, resp.text
    data = _json(resp)
    assert set(data.keys()) == {"error", "correlation_id"}, data
    assert data["error"] == AGENT_FACING_DENY_MESSAGE
    header_id = resp.headers.get(_CORR_HEADER)
    assert header_id is not None
    assert header_id == data["correlation_id"]


def _last_deny_reason() -> Optional[str]:
    """Read the most-recently buffered WORM event's concrete ``deny_reason``."""
    reader: Any = redis_sync.Redis.from_url(
        _TEST_REDIS_URL, decode_responses=True
    )
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
    """The raw concatenation of every buffered WORM record — for secret-leak scans."""
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=200)
    finally:
        reader.close()
    return "".join(fields.get("record", "") for _sid, fields in entries)


def _last_event_id() -> Optional[str]:
    """The most-recently buffered WORM event's ``event_id`` (for proof lookups)."""
    reader: Any = redis_sync.Redis.from_url(
        _TEST_REDIS_URL, decode_responses=True
    )
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=1)
    finally:
        reader.close()
    if not entries:
        return None
    _sid, fields = entries[0]
    return str(fields["event_id"])


def _sign(idp: _DemoIdP, claims: dict[str, Any]) -> str:
    """Sign arbitrary claims with the IdP's real private key (validly-signed token)."""
    token: str = jwt.encode(claims, idp._private_pem, algorithm="EdDSA")
    return token


def _stage_and_otp(
    client: TestClient, idp: _DemoIdP, token: str, alias: str, arguments: dict[str, Any]
) -> tuple[str, str]:
    """Stage a PIN_REQUIRED action → (challenge_id, otp) fetched out-of-band."""
    staged = _post(client, alias=alias, arguments=arguments, token=token)
    assert staged.status_code == 202, staged.text
    challenge_id = str(_json(staged)["challenge_id"])
    otp_resp = client.get(
        f"/v1/authenticator/{challenge_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert otp_resp.status_code == 200, otp_resp.text
    otp = str(_json(otp_resp)["otp"])
    return challenge_id, otp


# ---------------------------------------------------------------------------
# 1–19: the adversarial /v1/authorize suite.
# ---------------------------------------------------------------------------


def test_01_auto_happy_path(client: TestClient, idp: _DemoIdP) -> None:
    """AUTO alias → 200 ExecutionReceipt; class is a transport CLASS, not a target."""
    resp = _post(
        client, alias=_AUTO_ALIAS, arguments={"period": "2026-Q2"}, token=idp.mint()
    )
    assert resp.status_code == 200, resp.text
    data = _json(resp)
    assert data["decision"] == "allow"
    assert data["status"] == "committed"
    assert data["transaction_ref"].startswith("txn_")
    # Coarse transport class only — never the dotted topology (invariant #4).
    assert data["executed_target_class"] == "cloud_rest"
    assert "." not in data["executed_target_class"]
    assert _last_deny_reason() is None  # the tail event is the ALLOW.


def test_02_pin_required_staging(client: TestClient, idp: _DemoIdP) -> None:
    """PIN_REQUIRED with no pin → 202 StagedChallenge; the OTP never appears in body."""
    resp = _post(
        client, alias=_PIN_ALIAS, arguments={"run_id": "PR-1"}, token=idp.mint()
    )
    assert resp.status_code == 202, resp.text
    data = _json(resp)
    assert "challenge_id" in data
    assert "otp" not in data and "pin" not in data
    assert _last_deny_reason() == "pin_required"


def test_03_staging_then_consume(client: TestClient, idp: _DemoIdP) -> None:
    """202 → fetch OTP out-of-band → resubmit pin+challenge_id → 200."""
    token = idp.mint()
    args = {"run_id": "PR-3", "cycle": "monthly"}
    challenge_id, otp = _stage_and_otp(client, idp, token, _PIN_ALIAS, args)
    done = _post(
        client,
        alias=_PIN_ALIAS,
        arguments=args,
        token=token,
        pin=otp,
        challenge_id=challenge_id,
    )
    assert done.status_code == 200, done.text
    assert _json(done)["decision"] == "allow"


def test_04_replay_denied(client: TestClient, idp: _DemoIdP) -> None:
    """Replaying a spent challenge → opaque 403; WORM records pin_not_found."""
    token = idp.mint()
    args = {"run_id": "PR-4", "cycle": "weekly"}
    challenge_id, otp = _stage_and_otp(client, idp, token, _PIN_ALIAS, args)
    first = _post(
        client, alias=_PIN_ALIAS, arguments=args, token=token, pin=otp,
        challenge_id=challenge_id,
    )
    assert first.status_code == 200, first.text
    replay = _post(
        client, alias=_PIN_ALIAS, arguments=args, token=token, pin=otp,
        challenge_id=challenge_id,
    )
    _assert_opaque_denial(replay)
    assert _last_deny_reason() == "pin_not_found"


def test_05_payload_tamper_lock_survives(client: TestClient, idp: _DemoIdP) -> None:
    """Payload drift after staging → payload_mismatch; the lock survives a correct retry."""
    token = idp.mint()
    args = {"run_id": "PR-5", "cycle": "monthly"}
    challenge_id, otp = _stage_and_otp(client, idp, token, _PIN_ALIAS, args)
    drifted = {"run_id": "PR-5", "cycle": "monthlyX"}  # one byte changed.
    tampered = _post(
        client, alias=_PIN_ALIAS, arguments=drifted, token=token, pin=otp,
        challenge_id=challenge_id,
    )
    _assert_opaque_denial(tampered)
    assert _last_deny_reason() == "payload_mismatch"
    # The lock is NOT consumed by a payload mismatch — the correct payload still spends it.
    retry = _post(
        client, alias=_PIN_ALIAS, arguments=args, token=token, pin=otp,
        challenge_id=challenge_id,
    )
    assert retry.status_code == 200, retry.text


def test_06_forged_jwt(client: TestClient, idp: _DemoIdP) -> None:
    """A signature-tampered JWT → opaque 403; WORM records jwt_invalid."""
    resp = _post(
        client, alias=_AUTO_ALIAS, arguments={"period": "Q1"},
        token=_tamper_signature(idp.mint()),
    )
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "jwt_invalid"


def test_07_alg_none(client: TestClient, idp: _DemoIdP) -> None:
    """An ``alg=none`` token → opaque 403; rejected at the header allow-list."""
    resp = _post(
        client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=_forge_none_token()
    )
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "jwt_invalid"


def test_08_expired_jwt(client: TestClient, idp: _DemoIdP) -> None:
    """A validly-signed but expired JWT → opaque 403; WORM records jwt_invalid.

    Expired by more than JWT_CLOCK_SKEW_LEEWAY_SECONDS. The gateway deliberately
    tolerates that much drift on exp/iat/nbf (without it, a one-second disagreement with
    the IdP's clock is a total auth outage), so this stays a real expiry rejection only
    if it sits OUTSIDE the window — derived from the constant so widening the leeway can
    never silently defang the test.
    """
    now = int(time.time())
    expired_by = JWT_CLOCK_SKEW_LEEWAY_SECONDS + 10
    claims: dict[str, Any] = {
        "iss": _DemoIdP.ISSUER,
        "aud": _DemoIdP.AUDIENCE,
        "tenant_id": "tenant-acme",
        "agent_id": "agent-orchestrator-1",
        "role": "ops",
        "exp": now - expired_by,
        "iat": now - expired_by - 120,
        "nbf": now - expired_by - 120,
        "jti": uuid.uuid4().hex,
    }
    resp = _post(
        client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=_sign(idp, claims)
    )
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "jwt_invalid"


def test_09_missing_required_claim(client: TestClient, idp: _DemoIdP) -> None:
    """Dropping the required ``role`` claim → opaque 403; WORM records jwt_claims_missing."""
    resp = _post(
        client, alias=_AUTO_ALIAS, arguments={"period": "Q1"},
        token=idp.mint(drop_claim="role"),
    )
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "jwt_claims_missing"


def test_10_identity_injection(client: TestClient, idp: _DemoIdP) -> None:
    """An identity-shaped argument key → opaque 403; WORM records identity_injection."""
    resp = _post(
        client, alias=_AUTO_ALIAS, arguments={"tenant_id": "evil"}, token=idp.mint()
    )
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "identity_injection"


def test_11_unknown_alias(client: TestClient, idp: _DemoIdP) -> None:
    """An unregistered alias → opaque 403; WORM records unknown_alias."""
    resp = _post(client, alias="skill_does_not_exist", arguments={}, token=idp.mint())
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "unknown_alias"


def test_12_cross_tenant(client: TestClient, idp: _DemoIdP) -> None:
    """Reaching another tenant's alias → opaque 403; WORM records cross_tenant."""
    globex = idp.mint(tenant_id="tenant-globex", agent_id="agent-globex-1")
    resp = _post(client, alias=_PIN_ALIAS, arguments={"run_id": "x"}, token=globex)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "cross_tenant"


def test_13_oversize_arguments(client: TestClient, idp: _DemoIdP) -> None:
    """Too many argument keys → opaque 403; WORM records size_exceeded."""
    oversize = {f"key_{i}": "x" for i in range(200)}
    resp = _post(client, alias=_AUTO_ALIAS, arguments=oversize, token=idp.mint())
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "size_exceeded"


def test_14_compartment_cross_team(client: TestClient, idp: _DemoIdP) -> None:
    """An AEGIS agent reaching a FALCON alias → opaque 403; WORM compartment_denied."""
    aegis_token = idp.mint(
        tenant_id=_AEGIS, agent_id="agent-aegis-x", compartment=AEGIS
    )
    resp = _post(client, alias=_FALCON_ALIAS, arguments={}, token=aegis_token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "compartment_denied"


def test_15_grant_without_capability(client: TestClient, idp: _DemoIdP) -> None:
    """Issuing a grant without the capability UUID → opaque 403; WORM capability_denied.

    The capability/mandate gate runs BEFORE PIN staging, so the deny fires with no pin.
    """
    officer = idp.mint(tenant_id=_AEGIS, agent_id="agent-officer-nocap")
    grant_args: dict[str, Any] = {"grantee": "agent-y", "compartment": FALCON}
    resp = _post(client, alias=_GRANT_ALIAS, arguments=grant_args, token=officer)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "capability_denied"


def test_16_grant_issue_then_revoke(client: TestClient, idp: _DemoIdP) -> None:
    """Capability-holder issues a grant (step-up) → grantee ALLOWED → revoke → denied."""
    grantee_id = "agent-grantee-16"
    officer = idp.mint(
        tenant_id=_AEGIS,
        agent_id="agent-officer-16",
        # Coarse grant authority PLUS the FALCON-scoped grant capability (grant issuance
        # is compartment-scoped — see test_16b for the cross-compartment refusal).
        capabilities=[CAP_COMPARTMENT_GRANT, grant_capability_for(FALCON)],
    )
    grant_args: dict[str, Any] = {
        "grantee": grantee_id,
        "compartment": FALCON,
        "ttl_seconds": 3600,
    }
    challenge_id, otp = _stage_and_otp(client, idp, officer, _GRANT_ALIAS, grant_args)
    issued = _post(
        client, alias=_GRANT_ALIAS, arguments=grant_args, token=officer, pin=otp,
        challenge_id=challenge_id,
    )
    assert issued.status_code == 200, issued.text

    # The grantee now reaches the FALCON alias via the delegated grant. FALCON
    # telemetry is CLASSIFIED + require_sender_constraint, so the grant alone is not
    # enough: the grantee must ALSO present a key-proof (grant proves entitlement,
    # PoP proves the presenter). A bare bearer with the same grant is refused.
    bare = idp.mint(tenant_id=_AEGIS, agent_id=grantee_id)
    refused = _post(client, alias=_FALCON_ALIAS, arguments={}, token=bare)
    _assert_opaque_denial(refused)
    assert _last_deny_reason() == "sender_constraint_required"

    pk, jwk, jkt = _proof_keypair()
    grantee = _sc_token(idp, jkt=jkt, tenant_id=_AEGIS, agent_id=grantee_id)
    proof = _dpop_proof(
        pk, jwk, token=grantee, alias=_FALCON_ALIAS, arguments={},
        tenant_id=_AEGIS, agent_id=grantee_id,
    )
    allowed = _post_sc(client, alias=_FALCON_ALIAS, arguments={}, token=grantee, proof=proof)
    assert allowed.status_code == 200, allowed.text

    # Revoke the grant (Redis auto-expiry / delete IS the active test) and re-attempt.
    # The compartment gate runs before the sender-constraint gate, so a revoked grant
    # denies at the compartment even for a proven token.
    killer: Any = redis_sync.Redis.from_url(
        _TEST_REDIS_URL, decode_responses=True
    )
    try:
        killer.delete(f"mcpip:grant:{_AEGIS}:{FALCON}:{grantee_id}")
    finally:
        killer.close()
    denied = _post_sc(client, alias=_FALCON_ALIAS, arguments={}, token=grantee, proof=None)
    _assert_opaque_denial(denied)
    assert _last_deny_reason() == "compartment_denied"


def test_16b_cross_compartment_grant_denied(
    client: TestClient, idp: _DemoIdP
) -> None:
    """A FALCON-scoped grant holder CANNOT grant a different compartment (AEGIS).

    Reproduces the cross-compartment isolation escape: an honestly-minted holder of
    ``CAP_COMPARTMENT_GRANT`` + ``grant_capability_for(FALCON)`` tries to issue a grant
    for AEGIS. The coarse capability admits it to the governance alias, but grant
    issuance is COMPARTMENT-SCOPED, so it is refused (it lacks
    ``grant_capability_for(AEGIS)``). The deny fires at the mandate gate — before PIN
    staging — and the intended grantee gains no AEGIS entitlement.
    """
    mole_id = "agent-mole-16b"
    officer = idp.mint(
        tenant_id=_AEGIS,
        agent_id="agent-officer-16b",
        capabilities=[CAP_COMPARTMENT_GRANT, grant_capability_for(FALCON)],
    )
    cross_args: dict[str, Any] = {
        "grantee": mole_id,
        "compartment": AEGIS,
        "ttl_seconds": 3600,
    }
    resp = _post(client, alias=_GRANT_ALIAS, arguments=cross_args, token=officer)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "capability_denied"

    # The mole never gained AEGIS access — a classified AEGIS alias stays denied.
    mole = idp.mint(tenant_id=_AEGIS, agent_id=mole_id)
    denied = _post(client, alias="skill_radar_calibration_set", arguments={}, token=mole)
    _assert_opaque_denial(denied)
    assert _last_deny_reason() == "compartment_denied"


def test_17_malformed_capabilities_claim(client: TestClient, idp: _DemoIdP) -> None:
    """A non-UUID or oversized ``capabilities`` claim → opaque 403; WORM jwt_invalid."""
    bad_uuid = idp.mint(capabilities=["not-a-uuid"])
    resp = _post(client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=bad_uuid)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "jwt_invalid"

    oversized = idp.mint(capabilities=[uuid.uuid4().hex for _ in range(33)])
    resp2 = _post(client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=oversized)
    _assert_opaque_denial(resp2)
    assert _last_deny_reason() == "jwt_invalid"


def test_18_concurrent_exactly_once(client: TestClient, idp: _DemoIdP) -> None:
    """25-way concurrent consume of ONE lock → exactly one 200, the rest opaque denies."""
    token = idp.mint()
    args = {"run_id": "PR-18", "cycle": "annual"}
    challenge_id, otp = _stage_and_otp(client, idp, token, _PIN_ALIAS, args)

    def _consume(_: int) -> int:
        return _post(
            client, alias=_PIN_ALIAS, arguments=args, token=token, pin=otp,
            challenge_id=challenge_id,
        ).status_code

    with ThreadPoolExecutor(max_workers=25) as pool:
        codes = list(pool.map(_consume, range(25)))

    assert codes.count(200) == 1, codes
    assert codes.count(403) == 24, codes


def test_20_capability_injection(client: TestClient, idp: _DemoIdP) -> None:
    """An in-band ``capabilities`` argument key → opaque 403; WORM identity_injection.

    Authorization is JWT-only; a smuggled capabilities/entitlement claim in the
    tool-call payload is hard-denied (never silently ignored), same as tenant_id/role.
    """
    resp = _post(
        client,
        alias=_AUTO_ALIAS,
        arguments={"capabilities": [CAP_COMPARTMENT_GRANT]},
        token=idp.mint(),
    )
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "identity_injection"


def test_21_pre_auth_body_size_limit(client: TestClient, idp: _DemoIdP) -> None:
    """An oversized body is rejected with 413 at the edge — before parsing/auth.

    The JWT is invalid (would 403 if parsed), proving the size gate fires FIRST.
    """
    # ~400 KiB raw body (> MAX_REQUEST_BODY_BYTES) with an invalid credential.
    payload = json.dumps(
        {
            "source_format": "openai_tool_call",
            "jwt": "invalid.token.here",
            "tool_call": {
                "id": "x",
                "type": "function",
                "function": {"name": _AUTO_ALIAS, "arguments": "x" * 400_000},
            },
        }
    )
    resp = client.post(
        "/v1/authorize",
        content=payload,
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 413, resp.text
    data = _json(resp)
    assert set(data.keys()) == {"error", "correlation_id"}


def test_22_canary_trips_and_quarantines(client: TestClient, idp: _DemoIdP) -> None:
    """
    Selecting a canary alias → opaque 403 + WORM ``canary_tripped``; the agent is
    then frozen so its NEXT (otherwise-valid) request denies ``agent_quarantined``,
    and a DIFFERENT agent of the same tenant is unaffected.
    """
    agent_id = "agent-canary-trip"
    token = idp.mint(tenant_id="tenant-acme", agent_id=agent_id)

    # 1) Trip the canary — an AUTO-tier decoy, so it fires with no step-up.
    tripped = _post(
        client, alias=_CANARY_ALIAS, arguments={"scope": "all"}, token=token
    )
    _assert_opaque_denial(tripped)
    assert _last_deny_reason() == "canary_tripped"

    # 2) The same agent is now quarantined: even a normal AUTO skill is denied,
    #    and the concrete reason is agent_quarantined (not the skill's own path).
    frozen = _post(
        client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=token
    )
    _assert_opaque_denial(frozen)
    assert _last_deny_reason() == "agent_quarantined"

    # 3) Blast radius is one agent: a sibling agent authorizes normally.
    sibling = idp.mint(tenant_id="tenant-acme", agent_id="agent-canary-sibling")
    ok = _post(client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=sibling)
    assert ok.status_code == 200, ok.text


def test_23_canary_not_listed_in_catalog_target(
    client: TestClient, idp: _DemoIdP
) -> None:
    """
    Canary rows ARE visible bait in the catalog (that is the point), but the
    ``canary`` flag itself never crosses the boundary — no catalog item leaks it,
    and the real target is never surfaced (invariant #4).
    """
    token = idp.mint(tenant_id="tenant-acme", agent_id="agent-canary-cat")
    resp = client.get("/v1/catalog", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text
    items: Any = _json(resp)["catalog"]
    names = {str(item["alias"]) for item in items}
    assert _CANARY_ALIAS in names  # bait is visible …
    for item in items:
        assert "canary" not in item  # … but the tripwire flag never leaks.
        assert "target" not in item


# ---------------------------------------------------------------------------
# A2A task-envelope connector (7th SOURCE_FORMAT) — end-to-end via the same pipeline.
# ---------------------------------------------------------------------------


def _a2a_task(
    alias: str,
    arguments: dict[str, Any],
    *,
    task_id: str = "task-a2a-e2e",
    context_id: str = "ctx-a2a-e2e",
    message_id: str = "msg-a2a-e2e",
    metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """A representative A2A Task envelope carrying ONE DataPart skill invocation."""
    message: dict[str, Any] = {
        "kind": "message",
        "role": "agent",
        "messageId": message_id,
        "parts": [{"kind": "data", "data": {"skill": alias, "arguments": arguments}}],
    }
    if metadata is not None:
        message["metadata"] = metadata
    return {
        "kind": "task",
        "id": task_id,
        "contextId": context_id,
        "status": {"state": "submitted"},
        "message": message,
    }


def _post_a2a(
    client: TestClient,
    *,
    envelope: dict[str, Any],
    token: Optional[str] = None,
    pin: Optional[str] = None,
    challenge_id: Optional[str] = None,
) -> Response:
    """POST ``/v1/authorize`` with an ``a2a_task`` envelope (opt-in via source_format)."""
    body: dict[str, Any] = {"source_format": "a2a_task", "tool_call": envelope}
    if token is not None:
        body["jwt"] = token
    if pin is not None:
        body["pin"] = pin
    if challenge_id is not None:
        body["challenge_id"] = challenge_id
    resp: Response = client.post("/v1/authorize", json=body)
    return resp


def test_a2a_01_auto_authorizes_like_any_dialect(
    client: TestClient, idp: _DemoIdP
) -> None:
    """A valid a2a_task AUTO call authorizes identically to the same call in OpenAI."""
    args = {"period": "2026-Q4"}
    a2a_resp = _post_a2a(
        client, envelope=_a2a_task(_AUTO_ALIAS, args), token=idp.mint()
    )
    assert a2a_resp.status_code == 200, a2a_resp.text
    a2a_body = _json(a2a_resp)
    assert a2a_body["decision"] == "allow"
    assert a2a_body["executed_target_class"] == "cloud_rest"
    # Same call in OpenAI → same terminal class (format-independent authorization).
    openai_resp = _post(client, alias=_AUTO_ALIAS, arguments=args, token=idp.mint())
    assert openai_resp.status_code == 200, openai_resp.text
    assert _json(openai_resp)["executed_target_class"] == "cloud_rest"


def test_a2a_02_context_is_worm_only_never_agent_wire(
    client: TestClient, idp: _DemoIdP
) -> None:
    """A2A task/context/message IDs + declared actor ride WORM ctx, NOT the agent wire."""
    envelope = _a2a_task(
        _AUTO_ALIAS,
        {"period": "2026-Q4"},
        task_id="task-worm-probe-42",
        context_id="ctx-worm-probe-42",
        message_id="msg-worm-probe-42",
        metadata={"actor": "urn:a2a:orchestrator-alpha", "hint": "recorded-not-trusted"},
    )
    resp = _post_a2a(client, envelope=envelope, token=idp.mint())
    assert resp.status_code == 200, resp.text
    # The agent-facing response body carries none of the A2A correlation provenance.
    assert "task-worm-probe-42" not in resp.text
    assert "orchestrator-alpha" not in resp.text
    # … but the WORM ctx records it (recorded-not-trusted correlation).
    dump = _worm_dump()
    assert "task-worm-probe-42" in dump
    assert "ctx-worm-probe-42" in dump
    assert "msg-worm-probe-42" in dump
    assert "orchestrator-alpha" in dump  # declared-untrusted actor recorded.
    # The catalog agent-wire projection likewise never surfaces a2a fields.
    cat = client.get(
        "/v1/catalog", headers={"Authorization": f"Bearer {idp.mint()}"}
    )
    assert "task-worm-probe-42" not in cat.text


def test_a2a_03_pin_required_still_needs_oob_otp(
    client: TestClient, idp: _DemoIdP
) -> None:
    """A PIN_REQUIRED A2A egress stages 202 and completes ONLY with the OOB OTP."""
    token = idp.mint()
    args = {"run_id": "A2A-PR-1", "cycle": "monthly"}
    staged = _post_a2a(client, envelope=_a2a_task(_PIN_ALIAS, args), token=token)
    assert staged.status_code == 202, staged.text
    staged_body = _json(staged)
    challenge_id = str(staged_body["challenge_id"])
    assert "otp" not in staged_body and "pin" not in staged_body
    # Wrong/absent OTP fails closed.
    bad = _post_a2a(
        client, envelope=_a2a_task(_PIN_ALIAS, args), token=token,
        pin="000000", challenge_id=challenge_id,
    )
    _assert_opaque_denial(bad)
    # Fetch the real OTP out-of-band and complete.
    otp_resp = client.get(
        f"/v1/authenticator/{challenge_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert otp_resp.status_code == 200, otp_resp.text
    otp = str(_json(otp_resp)["otp"])
    done = _post_a2a(
        client, envelope=_a2a_task(_PIN_ALIAS, args), token=token,
        pin=otp, challenge_id=challenge_id,
    )
    assert done.status_code == 200, done.text
    assert _json(done)["decision"] == "allow"


def test_a2a_04_pin_lock_is_format_independent(
    client: TestClient, idp: _DemoIdP
) -> None:
    """An A2A staging is completable by the SAME call in OpenAI — the lock hashes only
    {tenant,agent,alias,arguments}, so it is dialect-independent."""
    token = idp.mint()
    args = {"run_id": "A2A-XFMT-1", "cycle": "weekly"}
    staged = _post_a2a(client, envelope=_a2a_task(_PIN_ALIAS, args), token=token)
    assert staged.status_code == 202, staged.text
    challenge_id = str(_json(staged)["challenge_id"])
    otp_resp = client.get(
        f"/v1/authenticator/{challenge_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    otp = str(_json(otp_resp)["otp"])
    # Complete with an OpenAI envelope carrying the identical (alias, arguments).
    done = _post(
        client, alias=_PIN_ALIAS, arguments=args, token=token,
        pin=otp, challenge_id=challenge_id,
    )
    assert done.status_code == 200, done.text
    assert _json(done)["decision"] == "allow"


def test_a2a_05_identity_smuggling_hard_deny(
    client: TestClient, idp: _DemoIdP
) -> None:
    """An identity-shaped key inside data.arguments → opaque deny, IDENTITY_INJECTION."""
    envelope = _a2a_task(_AUTO_ALIAS, {"period": "Q1", "actor": "urn:evil"})
    resp = _post_a2a(client, envelope=envelope, token=idp.mint())
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "identity_injection"


def test_a2a_06_declared_actor_metadata_is_inert(
    client: TestClient, idp: _DemoIdP
) -> None:
    """A declared actor in message.metadata is recorded-not-trusted — it does NOT
    smuggle identity and does NOT block the AUTO call (JWT is the only authority)."""
    envelope = _a2a_task(
        _AUTO_ALIAS,
        {"period": "Q1"},
        metadata={"actor": "urn:a2a:someone-else", "sub": "urn:human:claimed"},
    )
    resp = _post_a2a(client, envelope=envelope, token=idp.mint())
    assert resp.status_code == 200, resp.text
    assert _json(resp)["decision"] == "allow"


def test_a2a_07_malformed_fails_closed(client: TestClient, idp: _DemoIdP) -> None:
    """A malformed A2A envelope (>1 part) → opaque 403, schema_violation in WORM."""
    envelope = _a2a_task(_AUTO_ALIAS, {"period": "Q1"})
    envelope["message"]["parts"].append(
        {"kind": "data", "data": {"skill": "skill_other", "arguments": {}}}
    )
    resp = _post_a2a(client, envelope=envelope, token=idp.mint())
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "schema_violation"


def test_a2a_08_oversized_fails_closed(client: TestClient, idp: _DemoIdP) -> None:
    """An oversized A2A arguments object → opaque 403, size_exceeded in WORM."""
    big = {"blob": ["x" * 100 for _ in range(256)]}  # canonical > MAX_CANONICAL_BYTES.
    resp = _post_a2a(
        client, envelope=_a2a_task(_AUTO_ALIAS, big), token=idp.mint()
    )
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "size_exceeded"


def test_a2a_09_context_charset_scrubbed_before_worm(
    client: TestClient, idp: _DemoIdP
) -> None:
    """The recorded-not-trusted a2a_context (task/context/message ids + declared metadata)
    is charset-scrubbed like every other untrusted ingress string, so a control/bidi byte
    can never smuggle a terminal-escape / audit-log-injection into the signed WORM record.
    The charset guard is applied WITHOUT the identity hard-deny (a declared actor is still a
    legal recorded-not-trusted value — see test_a2a_06); only the bytes are refused."""
    # A bidi override (U+202E) hidden in the task id → opaque schema_violation deny.
    env_id = _a2a_task(_AUTO_ALIAS, {"period": "Q1"})
    env_id["id"] = "task-‮-evil"
    resp = _post_a2a(client, envelope=env_id, token=idp.mint())
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "illegal_character"

    # A NUL control byte in a declared-metadata value → opaque illegal_character deny
    # (the metadata is recorded, but its BYTES must still be charset-safe).
    env_meta = _a2a_task(
        _AUTO_ALIAS, {"period": "Q1"}, metadata={"note": "clean\x00injected"}
    )
    resp2 = _post_a2a(client, envelope=env_meta, token=idp.mint())
    _assert_opaque_denial(resp2)
    assert _last_deny_reason() == "illegal_character"


def test_a2a_10_oversized_metadata_fails_closed(
    client: TestClient, idp: _DemoIdP
) -> None:
    """Declared metadata over MAX_A2A_META_BYTES is bounded in the `_scrub_metadata`
    field validator BEFORE the recursive charset walk, so an oversized object can never
    drive an unbounded recursive traversal → opaque 403, schema_violation in WORM. The
    parse-time MAX_A2A_META_BYTES check (size_exceeded) is retained as a belt behind it."""
    oversized = {"pad": "x" * 5000}  # serialized well over MAX_A2A_META_BYTES (=4096).
    env = _a2a_task(_AUTO_ALIAS, {"period": "Q1"}, metadata=oversized)
    resp = _post_a2a(client, envelope=env, token=idp.mint())
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "schema_violation"


def test_19_opacity_of_all_denials(client: TestClient, idp: _DemoIdP) -> None:
    """Every denial body is exactly ``{error, correlation_id}`` with an echoed header id."""
    denials = [
        _post(client, alias=_AUTO_ALIAS, arguments={"period": "Q1"},
              token=_tamper_signature(idp.mint())),
        _post(client, alias="skill_nope", arguments={}, token=idp.mint()),
        _post(client, alias=_PIN_ALIAS, arguments={"run_id": "x"},
              token=idp.mint(tenant_id="tenant-globex", agent_id="g")),
        _post(client, alias=_FALCON_ALIAS, arguments={},
              token=idp.mint(tenant_id=_AEGIS, agent_id="a", compartment=AEGIS)),
    ]
    for resp in denials:
        _assert_opaque_denial(resp)


# ---------------------------------------------------------------------------
# Extras: catalog filtering, signed-epoch verify, inclusion proof.
# ---------------------------------------------------------------------------


def test_catalog_team_separation(client: TestClient, idp: _DemoIdP) -> None:
    """The catalog lists only entitled aliases (own compartment + tenant-wide), no target."""
    falcon = idp.mint(tenant_id=_AEGIS, agent_id="agent-falcon-cat", compartment=FALCON)
    resp = client.get("/v1/catalog", headers={"Authorization": f"Bearer {falcon}"})
    assert resp.status_code == 200, resp.text
    items: Any = _json(resp)["catalog"]
    names = {str(item["alias"]) for item in items}
    assert _FALCON_ALIAS in names
    assert "skill_status_probe" in names  # tenant-wide, un-compartmented.
    assert "skill_radar_calibration_set" not in names
    assert "skill_recon_feed_read" not in names
    for item in items:
        assert "target" not in item  # topology never surfaces (invariant #4).


def test_catalog_requires_jwt(client: TestClient) -> None:
    """The catalog is JWT-gated — no bearer → opaque deny."""
    resp = client.get("/v1/catalog")
    assert resp.status_code == 403


def test_audit_verify_intact(client: TestClient, idp: _DemoIdP) -> None:
    """After activity, force an epoch close and verify the signed Merkle-epoch chain."""
    _post(client, alias=_AUTO_ALIAS, arguments={"period": "verify"}, token=idp.mint())
    resp = client.get(
        "/v1/audit/verify", headers={"Authorization": f"Bearer {idp.mint()}"}
    )
    assert resp.status_code == 200, resp.text
    data = _json(resp)
    assert data["intact"] is True
    assert data["first_bad_epoch"] is None


def test_audit_inclusion_proof(client: TestClient, idp: _DemoIdP) -> None:
    """An emitted event has an O(log n) inclusion proof that verifies to its signed root."""
    token = idp.mint()
    _post(client, alias=_AUTO_ALIAS, arguments={"period": "proof"}, token=token)
    event_id = _last_event_id()
    assert event_id is not None
    # Force an epoch close so the event is sealed under a signed root.
    verify = client.get(
        "/v1/audit/verify", headers={"Authorization": f"Bearer {token}"}
    )
    assert verify.status_code == 200
    proof_resp = client.get(
        f"/v1/audit/proof/{event_id}", headers={"Authorization": f"Bearer {token}"}
    )
    assert proof_resp.status_code == 200, proof_resp.text
    proof = _json(proof_resp)
    assert proof["event_id"] == event_id
    # Recompute the leaf from the sealed record and verify the Merkle path locally.
    path: list[tuple[str, str]] = [(str(s), str(h)) for s, h in proof["proof"]]
    ok = merkle.verify_inclusion(
        merkle.leaf_digest(str(proof["record"]).encode("utf-8")),
        path,
        bytes.fromhex(str(proof["merkle_root"])),
    )
    assert ok is True


def test_healthz(client: TestClient) -> None:
    """Liveness probe returns the product glyph."""
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert _json(resp)["status"] == "live"


# ---------------------------------------------------------------------------
# Operator-console CORS (browser plug-and-play). Sandbox allows any origin so
# "Test & Connect" works cross-origin; production is closed unless
# MCPIP_CONSOLE_ORIGINS lists the console explicitly. CORS is browser-only —
# authorization is unchanged (still JWT, still opaque).
# ---------------------------------------------------------------------------


def test_cors_sandbox_allows_console_origin(client: TestClient) -> None:
    """Sandbox: a cross-origin console GET gets Access-Control-Allow-Origin."""
    resp = client.get("/healthz", headers={"Origin": "http://localhost:5173"})
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "*"
    # The console reads the correlation id off denials — it must be exposed.
    assert "x-mcpip-correlation-id" in (
        resp.headers.get("access-control-expose-headers") or ""
    ).lower()


def test_cors_preflight_answers_for_authorize(client: TestClient) -> None:
    """Sandbox: the OPTIONS preflight for POST /v1/authorize is answered with the
    Authorization header allowed — and never touches the authorize pipeline."""
    resp = client.options(
        "/v1/authorize",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "*"
    allowed = (resp.headers.get("access-control-allow-headers") or "").lower()
    assert "authorization" in allowed and "content-type" in allowed


def test_cors_never_relaxes_authorization(client: TestClient) -> None:
    """An allowed origin changes NOTHING about authorization: a tokenless call from
    the console origin is still an opaque deny."""
    resp = client.post(
        "/v1/authorize",
        json={"source_format": "raw_mcp", "tool_call": {"tool": _AUTO_ALIAS, "arguments": {}}},
        headers={"Origin": "http://localhost:5173"},
    )
    assert resp.status_code == 403
    body = _json(resp)
    assert set(body) == {"error", "correlation_id"}


# ---------------------------------------------------------------------------
# Version / update surface + license visibility (both JWT-gated, opaque deny).
# ---------------------------------------------------------------------------


def test_version_requires_jwt(client: TestClient) -> None:
    """The version/provenance surface is JWT-gated — no bearer → opaque deny."""
    resp = client.get("/v1/version")
    assert resp.status_code == 403


def test_version_reports_running_and_posture(client: TestClient, idp: _DemoIdP) -> None:
    """
    /v1/version reports the single-source running version, a redeploy-only update
    policy, and — with NO signed update feed configured — no available update. The
    endpoint is a notifier: it never claims something newer than it can prove.
    """
    resp = client.get("/v1/version", headers={"Authorization": f"Bearer {idp.mint()}"})
    assert resp.status_code == 200, resp.text
    data = _json(resp)
    assert data["running"] == get_version()
    assert data["update_policy"] == "redeploy"  # immutable, signed — never auto-install
    assert data["update_available"] is False  # no feed configured => nothing newer
    assert data["latest"] == data["running"]
    assert data["channel"] == "sandbox"  # sandbox boots without a license
    # The signed release manifest shipped alongside the source is surfaced for
    # provenance. It is the LAST OWNER-SIGNED release, which legitimately LAGS the
    # running VERSION between a version bump and the owner's offline re-sign (the real
    # signed artifact can only be produced with the owner's offline roots). So it is
    # compared to the SHIPPED manifest, never to get_version().
    import json as _json_mod
    from pathlib import Path as _Path

    _signed = _json_mod.loads(
        (_Path(__file__).resolve().parent.parent / "release" / "manifest.json").read_text()
    )
    assert data["release"]["version"] == _signed["version"]


def test_license_requires_jwt(client: TestClient) -> None:
    """The license view is JWT-gated — no bearer → opaque deny."""
    resp = client.get("/v1/license")
    assert resp.status_code == 403


def test_license_unlicensed_in_sandbox(client: TestClient, idp: _DemoIdP) -> None:
    """
    Sandbox boots without a license → the view discloses the fact and nothing else
    (no customer/tier/dates fabricated). Licensing never touches the authz path.
    """
    resp = client.get("/v1/license", headers={"Authorization": f"Bearer {idp.mint()}"})
    assert resp.status_code == 200, resp.text
    assert _json(resp) == {"licensed": False}


# ---------------------------------------------------------------------------
# Operator principal kill-switch (admin revocation) — hot-path enforcement.
# ---------------------------------------------------------------------------

_ADMIN_ID = "agent-directory-admin"


def _admin(idp: _DemoIdP, tenant_id: str = "tenant-acme") -> str:
    """Mint a JWT holding CAP_DIRECTORY_ADMIN in ``tenant_id``."""
    return idp.mint(tenant_id=tenant_id, agent_id=_ADMIN_ID, capabilities=[CAP_DIRECTORY_ADMIN])


def test_revoke_blocks_then_reactivate_restores(client: TestClient, idp: _DemoIdP) -> None:
    """
    An admin-revoked principal is denied PRINCIPAL_REVOKED on its very next request
    (concrete reason in WORM only, opaque to the agent); reactivate restores it.
    """
    admin = _admin(idp)
    victim_id = "agent-revoke-victim"
    victim = idp.mint(tenant_id="tenant-acme", agent_id=victim_id)

    # Baseline: the victim can run a benign AUTO skill.
    ok = _post(client, alias=_AUTO_ALIAS, arguments={"period": "pre"}, token=victim)
    assert ok.status_code == 200, ok.text

    # Revoke → the next request is an OPAQUE deny; WORM carries the real reason.
    rv = client.post(
        f"/v1/admin/principals/{victim_id}/revoke",
        json={"reason": "offboarded"},
        headers={"Authorization": f"Bearer {admin}"},
    )
    assert rv.status_code == 200, rv.text
    blocked = _post(client, alias=_AUTO_ALIAS, arguments={"period": "post"}, token=victim)
    _assert_opaque_denial(blocked)
    assert _last_deny_reason() == "principal_revoked"

    # Reactivate → the victim is allowed again.
    ra = client.post(
        f"/v1/admin/principals/{victim_id}/reactivate",
        headers={"Authorization": f"Bearer {admin}"},
    )
    assert ra.status_code == 200, ra.text
    assert _json(ra)["removed"] is True
    restored = _post(client, alias=_AUTO_ALIAS, arguments={"period": "after"}, token=victim)
    assert restored.status_code == 200, restored.text


def test_revoke_requires_directory_admin_cap(client: TestClient, idp: _DemoIdP) -> None:
    """The revoke endpoint is capability-gated — a token WITHOUT the cap is opaque-denied."""
    no_cap = idp.mint(tenant_id="tenant-acme", agent_id="agent-nocap")
    resp = client.post(
        "/v1/admin/principals/agent-x/revoke",
        json={},
        headers={"Authorization": f"Bearer {no_cap}"},
    )
    assert resp.status_code == 403
    # And with no bearer at all.
    assert client.post("/v1/admin/principals/agent-x/revoke", json={}).status_code == 403


def test_revoke_lists_and_is_tenant_scoped(client: TestClient, idp: _DemoIdP) -> None:
    """
    Revocation is tenant-scoped: an admin only ever blocks within its own tenant, and
    the listing reflects exactly that tenant's revoked principals.
    """
    admin_acme = _admin(idp, "tenant-acme")
    target = "agent-scoped-victim"
    client.post(
        f"/v1/admin/principals/{target}/revoke",
        json={},
        headers={"Authorization": f"Bearer {admin_acme}"},
    )
    listing = client.get(
        "/v1/admin/principals/revoked", headers={"Authorization": f"Bearer {admin_acme}"}
    )
    assert listing.status_code == 200, listing.text
    assert target in _json(listing)["revoked"]

    # A same-named principal in ANOTHER tenant is unaffected (different key namespace).
    other = idp.mint(tenant_id="tenant-globex", agent_id=target)
    resp = _post(client, alias="skill_status_probe", arguments={}, token=other)
    # tenant-globex has skill_status_probe (AUTO) — not blocked by tenant-acme's revoke.
    assert resp.status_code == 200, resp.text

    # Cleanup so later tests aren't affected by this module-scoped client.
    client.post(
        f"/v1/admin/principals/{target}/reactivate",
        headers={"Authorization": f"Bearer {admin_acme}"},
    )


# ---------------------------------------------------------------------------
# Operator directory persistence (non-authoritative metadata; admin-gated).
# ---------------------------------------------------------------------------

_DIRECTORY_DOC = {
    "schema": "mcpip-directory/1",
    "org_units": [
        {"id": "ou1", "label": "Aegis Dynamics", "tenant": "tenant-acme", "teams": []},
    ],
    "rbac": {"operator": ["authorize", "mcp_edge"]},
}


def test_directory_put_get_roundtrip(client: TestClient, idp: _DemoIdP) -> None:
    """An admin PUT persists the org document; GET returns it verbatim for that tenant."""
    admin = _admin(idp)
    put = client.put("/v1/directory", json=_DIRECTORY_DOC, headers={"Authorization": f"Bearer {admin}"})
    assert put.status_code == 200, put.text
    assert _json(put)["ok"] is True
    got = client.get("/v1/directory", headers={"Authorization": f"Bearer {admin}"})
    assert got.status_code == 200, got.text
    assert _json(got)["document"] == _DIRECTORY_DOC


def test_directory_requires_admin_cap(client: TestClient, idp: _DemoIdP) -> None:
    """GET/PUT are capability-gated — a token without CAP_DIRECTORY_ADMIN is opaque-denied."""
    no_cap = idp.mint(tenant_id="tenant-acme", agent_id="agent-nocap-dir")
    assert client.get("/v1/directory", headers={"Authorization": f"Bearer {no_cap}"}).status_code == 403
    assert client.put("/v1/directory", json=_DIRECTORY_DOC, headers={"Authorization": f"Bearer {no_cap}"}).status_code == 403
    assert client.get("/v1/directory").status_code == 403


def test_directory_is_tenant_scoped(client: TestClient, idp: _DemoIdP) -> None:
    """A tenant's directory is invisible to another tenant's admin."""
    admin_acme = _admin(idp, "tenant-acme")
    client.put("/v1/directory", json=_DIRECTORY_DOC, headers={"Authorization": f"Bearer {admin_acme}"})
    admin_globex = _admin(idp, "tenant-globex")
    got = client.get("/v1/directory", headers={"Authorization": f"Bearer {admin_globex}"})
    assert got.status_code == 200
    assert _json(got)["document"] is None  # tenant-globex never wrote one.


def test_directory_rejects_malformed(client: TestClient, idp: _DemoIdP) -> None:
    """Bad schema / wrong shape / oversized documents are opaque-denied, never stored."""
    admin = _admin(idp)
    hdr = {"Authorization": f"Bearer {admin}"}
    assert client.put("/v1/directory", json={"org_units": []}, headers=hdr).status_code == 403  # no schema
    assert client.put("/v1/directory", json={"schema": "mcpip-directory/1"}, headers=hdr).status_code == 403  # no org_units
    huge = {"schema": "mcpip-directory/1", "org_units": [{"id": "x", "blob": "A" * 200_000}]}
    assert client.put("/v1/directory", json=huge, headers=hdr).status_code == 403  # over the size cap


# ---------------------------------------------------------------------------
# Operator skill kill-switch (admin-disabled alias; fail-closed hot-path).
# ---------------------------------------------------------------------------


def test_skill_disable_blocks_then_enable_restores(client: TestClient, idp: _DemoIdP) -> None:
    """
    A disabled skill is denied SKILL_DISABLED for EVERY caller (opaque, WORM-only
    reason), regardless of entitlement; re-enabling restores it. Never edits the
    alias→target mapping.
    """
    admin = _admin(idp)
    hdr = {"Authorization": f"Bearer {admin}"}

    # Baseline: a benign AUTO skill runs.
    assert _post(client, alias=_AUTO_ALIAS, arguments={"period": "pre"}, token=idp.mint()).status_code == 200

    # Disable it → the next invocation is an opaque deny; WORM carries the reason.
    dz = client.post(f"/v1/admin/skills/{_AUTO_ALIAS}/disable", headers=hdr)
    assert dz.status_code == 200, dz.text
    blocked = _post(client, alias=_AUTO_ALIAS, arguments={"period": "post"}, token=idp.mint())
    _assert_opaque_denial(blocked)
    assert _last_deny_reason() == "alias_disabled"

    # Listed as disabled.
    listing = client.get("/v1/admin/skills/disabled", headers=hdr)
    assert _AUTO_ALIAS in _json(listing)["disabled"]

    # Enable → restored.
    ez = client.post(f"/v1/admin/skills/{_AUTO_ALIAS}/enable", headers=hdr)
    assert ez.status_code == 200 and _json(ez)["removed"] is True
    assert _post(client, alias=_AUTO_ALIAS, arguments={"period": "after"}, token=idp.mint()).status_code == 200


def test_skill_disable_requires_admin_cap(client: TestClient, idp: _DemoIdP) -> None:
    """The skill endpoints are capability-gated — a token without the cap is opaque-denied."""
    no_cap = idp.mint(tenant_id="tenant-acme", agent_id="agent-nocap-skill")
    assert client.post(f"/v1/admin/skills/{_AUTO_ALIAS}/disable", headers={"Authorization": f"Bearer {no_cap}"}).status_code == 403
    assert client.get("/v1/admin/skills/disabled", headers={"Authorization": f"Bearer {no_cap}"}).status_code == 403
    assert client.post(f"/v1/admin/skills/{_AUTO_ALIAS}/disable").status_code == 403


def test_skill_disable_is_tenant_scoped(client: TestClient, idp: _DemoIdP) -> None:
    """Disabling a skill in one tenant does not disable it in another."""
    admin_acme = _admin(idp, "tenant-acme")
    probe = "skill_status_probe"
    client.post(f"/v1/admin/skills/{probe}/disable", headers={"Authorization": f"Bearer {admin_acme}"})
    # tenant-globex has skill_status_probe (AUTO) and is unaffected by tenant-acme's disable.
    other = idp.mint(tenant_id="tenant-globex", agent_id="agent-globex-skill")
    assert _post(client, alias=probe, arguments={}, token=other).status_code == 200
    # Cleanup.
    client.post(f"/v1/admin/skills/{probe}/enable", headers={"Authorization": f"Bearer {admin_acme}"})


# ---------------------------------------------------------------------------
# Operator-registered skills (additive catalog overlay; never shadows config).
# ---------------------------------------------------------------------------


def test_register_skill_makes_it_authorizable_then_deregister(client: TestClient, idp: _DemoIdP) -> None:
    """
    A registered skill is unknown before and authorizable after; deregister removes
    it. Additive-only: it introduces a NEW alias, never a config target.
    """
    admin = _admin(idp)
    hdr = {"Authorization": f"Bearer {admin}"}
    new_alias = "skill_test_analytics"

    # Unknown before registration.
    before = _post(client, alias=new_alias, arguments={}, token=idp.mint())
    _assert_opaque_denial(before)

    reg = client.post(
        "/v1/admin/skills/register",
        json={"alias": new_alias, "target": "rest.analytics.reports.get", "risk_tier": "auto"},
        headers=hdr,
    )
    assert reg.status_code == 200, reg.text
    # Now authorizable through the real pipeline.
    assert _post(client, alias=new_alias, arguments={}, token=idp.mint()).status_code == 200
    # And it appears in the operator-registered (deregisterable) listing.
    listed = client.get("/v1/admin/skills/registered", headers=hdr)
    assert listed.status_code == 200 and new_alias in _json(listed)["registered"]

    dz = client.post(f"/v1/admin/skills/{new_alias}/deregister", headers=hdr)
    assert dz.status_code == 200 and _json(dz)["removed"] is True
    after = _post(client, alias=new_alias, arguments={}, token=idp.mint())
    _assert_opaque_denial(after)
    # Deregistered → no longer in the operator-registered listing.
    assert new_alias not in _json(client.get("/v1/admin/skills/registered", headers=hdr))["registered"]


def test_register_skill_cannot_shadow_config_alias(client: TestClient, idp: _DemoIdP) -> None:
    """Registration NEVER overrides a config alias.

    The refusal is a concrete 409 for the operator (this route is CAP_DIRECTORY_ADMIN-gated
    and that caller can already enumerate the catalog, so naming the collision discloses
    nothing). The INVARIANT is what matters and is asserted below: the config alias still
    resolves to its own untouched target, and the attacker's proposed target is never
    echoed back.
    """
    admin = _admin(idp)
    resp = client.post(
        "/v1/admin/skills/register",
        json={"alias": _AUTO_ALIAS, "target": "rest.evil.example"},
        headers={"Authorization": f"Bearer {admin}"},
    )
    assert resp.status_code == 409, resp.text
    assert resp.json()["error"] == "alias_exists"
    assert "evil" not in resp.text
    # And the config alias still resolves to its real (untouched) target.
    assert _post(client, alias=_AUTO_ALIAS, arguments={"period": "x"}, token=idp.mint()).status_code == 200


def test_register_skill_requires_admin_cap(client: TestClient, idp: _DemoIdP) -> None:
    """The register endpoint is capability-gated — no cap → opaque 403."""
    no_cap = idp.mint(tenant_id="tenant-acme", agent_id="agent-nocap-reg")
    resp = client.post(
        "/v1/admin/skills/register",
        json={"alias": "skill_x", "target": "rest.x"},
        headers={"Authorization": f"Bearer {no_cap}"},
    )
    assert resp.status_code == 403


def test_register_skill_with_service_and_access_persists(client: TestClient, idp: _DemoIdP) -> None:
    """The structured service/access display metadata persists with the skill: the
    operator projection returns both; /v1/catalog carries the access mode but NEVER
    the service label (a target hint stays off the agent wire)."""
    admin = _admin(idp)
    hdr = {"Authorization": f"Bearer {admin}"}
    alias = "skill_test_billing"
    reg = client.post(
        "/v1/admin/skills/register",
        json={
            "alias": alias,
            "target": "rest.billing.invoices.get",
            "risk_tier": "auto",
            "service": "Billing invoices",
            "access": "read",
        },
        headers=hdr,
    )
    assert reg.status_code == 200, reg.text
    listed = _json(client.get("/v1/admin/skills/registered", headers=hdr))
    row = next(e for e in listed["entries"] if e["alias"] == alias)
    assert row["service"] == "Billing invoices" and row["access"] == "read"
    # The agent-facing catalog carries the benign access mode only.
    cat = _json(client.get("/v1/catalog", headers={"Authorization": f"Bearer {idp.mint()}"}))
    item = next(i for i in cat["catalog"] if i["alias"] == alias)
    assert item["access"] == "read"
    assert "service" not in item
    # An unannotated operator row falls back to the risk-derived access in the listing.
    plain = "skill_test_plain_write"
    assert client.post(
        "/v1/admin/skills/register",
        json={"alias": plain, "target": "rest.plain.post", "risk_tier": "pin_required"},
        headers=hdr,
    ).status_code == 200
    listed = _json(client.get("/v1/admin/skills/registered", headers=hdr))
    plain_row = next(e for e in listed["entries"] if e["alias"] == plain)
    assert plain_row["access"] == "write" and plain_row["service"] == "test plain write"
    for a in (alias, plain):
        assert client.post(f"/v1/admin/skills/{a}/deregister", headers=hdr).status_code == 200


def test_register_skill_bad_access_enum_is_denied(client: TestClient, idp: _DemoIdP) -> None:
    """`access` is a closed enum — anything outside read/write is an opaque deny and
    nothing is registered."""
    admin = _admin(idp)
    hdr = {"Authorization": f"Bearer {admin}"}
    resp = client.post(
        "/v1/admin/skills/register",
        json={"alias": "skill_bad_access", "target": "rest.x", "access": "admin"},
        headers=hdr,
    )
    assert resp.status_code == 403
    assert set(_json(resp).keys()) == {"error", "correlation_id"}
    assert "skill_bad_access" not in _json(client.get("/v1/admin/skills/registered", headers=hdr))["registered"]


def test_overlay_fields_roundtrip_keeps_service_and_access(client: TestClient) -> None:
    """The persisted overlay field map carries service/access through to the hydrated
    AliasEntry; an invalid stored access value degrades to None (advisory metadata —
    the row itself is never refused for it)."""
    from app.main import _overlay_entry, _overlay_fields

    fields = _overlay_fields("rest.rt.example", "auto", "unclassified", service="AWS S3", access="read")
    entry = _overlay_entry("skill_rt_roundtrip", fields)
    assert entry is not None
    assert entry.service == "AWS S3" and entry.access == "read"
    # Unset fields are simply absent — hydration yields None (fallback applies).
    bare = _overlay_fields("rest.rt.example", "auto", "unclassified")
    assert "service" not in bare and "access" not in bare
    bare_entry = _overlay_entry("skill_rt_bare", bare)
    assert bare_entry is not None and bare_entry.service is None and bare_entry.access is None
    # A corrupt stored access value degrades to None, never a refused row.
    fields["access"] = "admin"
    degraded = _overlay_entry("skill_rt_roundtrip", fields)
    assert degraded is not None and degraded.access is None and degraded.service == "AWS S3"


def test_effective_access_fallback_and_display_service() -> None:
    """Unannotated entries display the risk-derived access (AUTO→read, PIN→write); an
    explicit annotation wins; display_service humanizes the alias when unset."""
    from interfaces import RiskTier
    from obfuscator import AliasEntry, display_service, effective_access

    auto = AliasEntry("skill_thing_status", "rest.t", "cloud_rest", RiskTier.AUTO)
    pin = AliasEntry("skill_thing_update", "rest.t2", "cloud_rest", RiskTier.PIN_REQUIRED)
    assert effective_access(auto) == "read"
    assert effective_access(pin) == "write"
    annotated = AliasEntry("skill_pii_export", "rest.p", "cloud_rest", RiskTier.PIN_REQUIRED, access="read")
    assert effective_access(annotated) == "read"
    assert display_service(auto) == "thing status"
    labeled = AliasEntry("skill_x", "rest.x", "cloud_rest", RiskTier.AUTO, service="Thing service")
    assert display_service(labeled) == "Thing service"


# ---------------------------------------------------------------------------
# Operator decision feed (/v1/admin/decisions/recent) — the live stream the console
# renders so REAL agent traffic shows up. Opaque, tenant-scoped, capability-gated.
# ---------------------------------------------------------------------------


def test_recent_decisions_feed_is_real_opaque_and_tenant_scoped(
    client: TestClient, idp: _DemoIdP
) -> None:
    """
    The feed surfaces REAL allow+deny decisions for the admin's OWN tenant, projected to
    a strict whitelist (the real target / payload NEVER appear) and tenant-scoped.
    """
    admin = _admin(idp)  # tenant-acme
    hdr = {"Authorization": f"Bearer {admin}"}

    # Drive real traffic: one ALLOW (config auto alias) + one DENY (unknown alias).
    assert _post(client, alias=_AUTO_ALIAS, arguments={"period": "x"}, token=idp.mint()).status_code == 200
    _assert_opaque_denial(_post(client, alias="skill_no_such_thing", arguments={}, token=idp.mint()))

    feed = client.get("/v1/admin/decisions/recent", headers=hdr)
    assert feed.status_code == 200, feed.text
    decisions = _json(feed)["decisions"]
    assert isinstance(decisions, list) and len(decisions) >= 2

    by_alias = {d["alias"]: d for d in decisions if d.get("alias")}
    assert by_alias[_AUTO_ALIAS]["decision"] == "allow"
    assert by_alias["skill_no_such_thing"]["decision"] == "deny"
    assert by_alias["skill_no_such_thing"]["deny_reason"] == "unknown_alias"

    allowed_keys = {
        "correlation_id", "agent_id", "alias", "decision", "deny_reason", "transport",
        "risk_tier", "classification", "source_format", "transaction_ref",
        "tenant_id", "worm_sequence", "timestamp_ns",
        # Deliberate whitelist extension: the WORM event_id — a random per-event
        # uuid4 handle for /v1/audit/proof/{event_id}, never topology or secret.
        "event_id",
    }
    for d in decisions:
        # Opacity: the real target / payload are NEVER in the projection.
        assert "target" not in d and "payload_hash" not in d and "arguments" not in d
        assert set(d.keys()) <= allowed_keys
        assert d["tenant_id"] == "tenant-acme"  # tenant-scoped to the caller.


def test_recent_decisions_feed_requires_admin_cap(client: TestClient, idp: _DemoIdP) -> None:
    """The decision feed is capability-gated — no CAP_DIRECTORY_ADMIN → opaque 403."""
    no_cap = idp.mint(tenant_id="tenant-acme", agent_id="agent-nocap-feed")
    resp = client.get(
        "/v1/admin/decisions/recent", headers={"Authorization": f"Bearer {no_cap}"}
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Cloud IAM broker (cloud_iam transport). Executing an authorized cloud_iam skill
# VENDS a short-lived scoped credential — per-call, compartment-scoped, and NEVER
# written to the WORM log. Demo tenant mcpip-inc / team-engineering is seeded in
# sandbox with the 'aws-eng-readonly' environment + skill_aws_s3.
# ---------------------------------------------------------------------------

_MCPIP_ENG = "e0900000-0000-4000-8000-e0900000e090"
_MCPIP_FIN = "f1a00000-0000-4000-8000-f1a00000f1a0"
_AWS_ALIAS = "skill_aws_s3"


def test_cloud_iam_vends_scoped_credential(client: TestClient, idp: _DemoIdP) -> None:
    """An Engineering agent invoking the cloud_iam skill gets a 200 receipt carrying a
    short-lived, scoped (sandbox) AWS credential — the deliverable."""
    eng = idp.mint(tenant_id="mcpip-inc", agent_id="agent-eng-cloud", compartment=_MCPIP_ENG)
    resp = _post(client, alias=_AWS_ALIAS, arguments={}, token=eng)
    assert resp.status_code == 200, resp.text
    body = _json(resp)
    assert body["executed_target_class"] == "cloud_iam"
    cred = body["vended_credential"]
    assert cred is not None
    assert cred["provider"] == "aws" and cred["simulated"] is True
    assert cred["expires_in"] == 900
    # The credential material is present for the agent to use.
    assert cred["credential"]["access_key_id"].startswith("ASIA_SANDBOX_")
    assert cred["credential"]["session_token"]


def test_cloud_iam_cross_compartment_denied(client: TestClient, idp: _DemoIdP) -> None:
    """A Finance agent cannot vend the Engineering-scoped cloud credential — opaque deny
    at the compartment gate (COMPARTMENT_DENIED in WORM), no credential returned."""
    fin = idp.mint(tenant_id="mcpip-inc", agent_id="agent-fin-cloud", compartment=_MCPIP_FIN)
    resp = _post(client, alias=_AWS_ALIAS, arguments={}, token=fin)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "compartment_denied"


def test_cloud_iam_credential_never_reaches_worm(client: TestClient, idp: _DemoIdP) -> None:
    """The vended secret material is the deliverable to the agent — it must NEVER be
    written to the audit log (dispatch runs after the ALLOW record)."""
    eng = idp.mint(tenant_id="mcpip-inc", agent_id="agent-eng-audit", compartment=_MCPIP_ENG)
    resp = _post(client, alias=_AWS_ALIAS, arguments={}, token=eng)
    assert resp.status_code == 200, resp.text
    secret = _json(resp)["vended_credential"]["credential"]["session_token"]
    # Scan the entire WORM event stream for any trace of the vended secret.
    raw = _worm_dump()
    assert secret not in raw
    assert "session_token" not in raw and "secret_access_key" not in raw


_DDB_ALIAS = "skill_aws_dynamodb"


def test_cloud_iam_write_requires_step_up_then_vends(client: TestClient, idp: _DemoIdP) -> None:
    """skill_aws_dynamodb is a WRITE (PIN_REQUIRED): the first call stages a payload-bound
    challenge (no credential yet); completing the step-up vends the write-scoped credential."""
    eng = idp.mint(tenant_id="mcpip-inc", agent_id="agent-eng-ddb", compartment=_MCPIP_ENG)
    args = {"table": "mcpip-live-fire", "item": {"pk": "agent-eng-ddb", "note": "hello"}}
    # 1) No pin → 202 StagedChallenge, and NOTHING is vended at the staging step.
    staged = _post(client, alias=_DDB_ALIAS, arguments=args, token=eng)
    assert staged.status_code == 202, staged.text
    assert "vended_credential" not in _json(staged)
    # 2) Complete the payload-bound step-up → 200 receipt carrying the vended credential.
    challenge_id, otp = _stage_and_otp(client, idp, eng, _DDB_ALIAS, args)
    done = _post(
        client, alias=_DDB_ALIAS, arguments=args, token=eng, pin=otp, challenge_id=challenge_id
    )
    assert done.status_code == 200, done.text
    body = _json(done)
    assert body["executed_target_class"] == "cloud_iam"
    cred = body["vended_credential"]
    assert cred is not None
    assert cred["provider"] == "aws" and cred["simulated"] is True
    assert cred["expires_in"] == 900
    # The write binding is a DISTINCT role from the read binding — the vend is scoped to it.
    assert "mcpip-eng-dynamodb-write" in cred["fingerprint"]
    assert cred["credential"]["access_key_id"].startswith("ASIA_SANDBOX_")
    assert cred["credential"]["session_token"]


def test_cloud_iam_write_cross_compartment_denied(client: TestClient, idp: _DemoIdP) -> None:
    """A Finance agent cannot vend the Engineering-scoped DynamoDB-write credential — the
    compartment gate denies opaquely BEFORE any step-up is offered."""
    fin = idp.mint(tenant_id="mcpip-inc", agent_id="agent-fin-ddb", compartment=_MCPIP_FIN)
    args = {"table": "mcpip-live-fire", "item": {"pk": "x"}}
    resp = _post(client, alias=_DDB_ALIAS, arguments=args, token=fin)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "compartment_denied"


def test_cloud_iam_write_credential_never_reaches_worm(client: TestClient, idp: _DemoIdP) -> None:
    """The write credential vended after step-up is the deliverable — its secret material
    must never appear in the WORM stream (dispatch runs after the ALLOW record)."""
    eng = idp.mint(tenant_id="mcpip-inc", agent_id="agent-eng-ddb-audit", compartment=_MCPIP_ENG)
    args = {"table": "mcpip-live-fire", "item": {"pk": "audit"}}
    challenge_id, otp = _stage_and_otp(client, idp, eng, _DDB_ALIAS, args)
    done = _post(
        client, alias=_DDB_ALIAS, arguments=args, token=eng, pin=otp, challenge_id=challenge_id
    )
    assert done.status_code == 200, done.text
    secret = _json(done)["vended_credential"]["credential"]["session_token"]
    raw = _worm_dump()
    assert secret not in raw
    assert "session_token" not in raw and "secret_access_key" not in raw


# ---------------------------------------------------------------------------
# Environment secret vault. Operator-stored broker credentials, encrypted at rest,
# write-only values: no endpoint returns a stored value; the single reader is the
# broker at vend time. Sandbox auto-provisions a persistent AES-256 master key.
# ---------------------------------------------------------------------------

_VAULT_SECRET_VALUE = "wJalrXUtnFEMI-verySecret-EXAMPLEKEY-do-not-log"


def test_vault_admin_crud_is_write_only(client: TestClient, idp: _DemoIdP) -> None:
    """Admin can store, list (METADATA only), and delete a broker credential; the stored
    value is never echoed by any endpoint, and a non-admin is opaquely denied."""
    admin = _admin(idp, tenant_id="mcpip-inc")
    body = {
        "secret_id": "aws-broker-key",
        "vendor": "aws",
        "description": "on-prem broker key for the DynamoDB write role",
        "material": {"access_key_id": "AKIAEXAMPLE", "secret_access_key": _VAULT_SECRET_VALUE},
    }
    put = client.put("/v1/admin/vault/secrets", json=body, headers={"Authorization": f"Bearer {admin}"})
    assert put.status_code == 200, put.text
    stored = _json(put)["secret"]
    # Response carries METADATA + a non-secret fingerprint — never the value.
    assert stored["secret_id"] == "aws-broker-key" and stored["vendor"] == "aws"
    assert stored["fingerprint"] and _VAULT_SECRET_VALUE not in json.dumps(_json(put))
    assert "material" not in stored and "secret_access_key" not in json.dumps(stored)
    # It is listed — still metadata only.
    lst = client.get("/v1/admin/vault/secrets", headers={"Authorization": f"Bearer {admin}"})
    data = _json(lst)
    assert data["vault_enabled"] is True
    entry = next(s for s in data["secrets"] if s["secret_id"] == "aws-broker-key")
    assert _VAULT_SECRET_VALUE not in json.dumps(data) and "material" not in entry
    # Non-admin cannot list.
    no_cap = idp.mint(tenant_id="mcpip-inc", agent_id="agent-nocap-vault")
    assert client.get("/v1/admin/vault/secrets", headers={"Authorization": f"Bearer {no_cap}"}).status_code == 403
    # Delete it.
    dele = client.post("/v1/admin/vault/secrets/aws-broker-key/delete", headers={"Authorization": f"Bearer {admin}"})
    assert dele.status_code == 200 and _json(dele)["removed"] is True


def test_vault_value_never_plaintext_at_rest_or_in_worm(client: TestClient, idp: _DemoIdP) -> None:
    """The stored secret is AES-GCM encrypted in Redis and its value never enters WORM —
    only metadata + a non-secret fingerprint are logged."""
    admin = _admin(idp, tenant_id="mcpip-inc")
    body = {
        "secret_id": "gcp-broker",
        "vendor": "gcp",
        "material": {"private_key": _VAULT_SECRET_VALUE, "client_email": "svc@example.iam"},
    }
    assert client.put("/v1/admin/vault/secrets", json=body, headers={"Authorization": f"Bearer {admin}"}).status_code == 200
    # Scan the raw vault hash in Redis — ciphertext only, no plaintext secret.
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        raw_vault = json.dumps(reader.hgetall("mcpip:vault:mcpip-inc"))
    finally:
        reader.close()
    assert _VAULT_SECRET_VALUE not in raw_vault
    assert "private_key" not in raw_vault  # the material keys are encrypted too.
    # And it never reached the audit log.
    assert _VAULT_SECRET_VALUE not in _worm_dump()


def test_vault_put_rejects_unknown_vendor_and_bad_material(client: TestClient, idp: _DemoIdP) -> None:
    """Shape gates fail closed: an unknown vendor or an empty material map is opaquely denied."""
    admin = _admin(idp, tenant_id="mcpip-inc")
    bad_vendor = {"secret_id": "x", "vendor": "sap", "material": {"k": "v"}}
    assert client.put("/v1/admin/vault/secrets", json=bad_vendor, headers={"Authorization": f"Bearer {admin}"}).status_code == 403
    empty_material = {"secret_id": "y", "vendor": "aws", "material": {}}
    r = client.put("/v1/admin/vault/secrets", json=empty_material, headers={"Authorization": f"Bearer {admin}"})
    assert r.status_code in (403, 422)  # empty dict fails validation (opaque deny or schema reject).


def test_cloud_env_rejects_dangling_vault_reference(client: TestClient, idp: _DemoIdP) -> None:
    """A cloud environment may only reference an EXISTING vault entry — a dangling
    pointer is refused at write time (fail closed), not discovered at vend time."""
    admin = _admin(idp, tenant_id="mcpip-inc")
    env = {
        "env_id": "aws-vault-env",
        "provider": "aws",
        "role": "arn:aws:iam::000000000000:role/test",
        "region": "us-east-1",
        "compartment": _MCPIP_ENG,
        "vault_secret_id": "does-not-exist",
    }
    assert client.put("/v1/admin/cloud/environments", json=env, headers={"Authorization": f"Bearer {admin}"}).status_code == 403
    # Store the referenced secret, then the SAME binding is accepted and carries the pointer.
    sec = {"secret_id": "aws-broker-key2", "vendor": "aws", "material": {"access_key_id": "AK", "secret_access_key": "s"}}
    assert client.put("/v1/admin/vault/secrets", json=sec, headers={"Authorization": f"Bearer {admin}"}).status_code == 200
    env["vault_secret_id"] = "aws-broker-key2"
    ok = client.put("/v1/admin/cloud/environments", json=env, headers={"Authorization": f"Bearer {admin}"})
    assert ok.status_code == 200, ok.text
    assert _json(ok)["environment"]["vault_secret_id"] == "aws-broker-key2"


def test_cloud_env_admin_crud(client: TestClient, idp: _DemoIdP) -> None:
    """CAP_DIRECTORY_ADMIN can create, list, and delete a cloud environment binding
    (which holds no cloud secret); a non-admin is opaquely denied."""
    admin = _admin(idp, tenant_id="mcpip-inc")
    body = {
        "env_id": "aws-test-env",
        "provider": "aws",
        "role": "arn:aws:iam::000000000000:role/test",
        "region": "eu-west-1",
        "compartment": _MCPIP_ENG,
        "session_ttl": 600,
    }
    put = client.put("/v1/admin/cloud/environments", json=body, headers={"Authorization": f"Bearer {admin}"})
    assert put.status_code == 200, put.text
    env = _json(put)["environment"]
    assert env["provider"] == "aws" and env["region"] == "eu-west-1" and env["session_ttl"] == 600
    # It is listed.
    lst = client.get("/v1/admin/cloud/environments", headers={"Authorization": f"Bearer {admin}"})
    assert any(e["env_id"] == "aws-test-env" for e in _json(lst)["environments"])
    # Non-admin cannot list.
    no_cap = idp.mint(tenant_id="mcpip-inc", agent_id="agent-nocap-cloud")
    assert client.get("/v1/admin/cloud/environments", headers={"Authorization": f"Bearer {no_cap}"}).status_code == 403
    # Delete it.
    dele = client.post("/v1/admin/cloud/environments/aws-test-env/delete", headers={"Authorization": f"Bearer {admin}"})
    assert dele.status_code == 200 and _json(dele)["removed"] is True


# ---------------------------------------------------------------------------
# Security-audit hardening — regression tests for the fixed findings.
# ---------------------------------------------------------------------------


def _bh(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_revoked_admin_is_denied_the_control_plane(client: TestClient, idp: _DemoIdP) -> None:
    """The revocation kill-switch is enforced on the ADMIN surface, not just the hot path:
    a revoked admin token can no longer touch the control plane — including reactivating
    itself — closing the compromised-admin self-rescue hole."""
    admin1 = _admin(idp, tenant_id="mcpip-inc")  # agent_id = _ADMIN_ID
    admin2_id = "agent-admin-2"
    admin2 = idp.mint(tenant_id="mcpip-inc", agent_id=admin2_id, capabilities=[CAP_DIRECTORY_ADMIN])
    # admin2 initially has the admin surface.
    assert client.get("/v1/admin/vault/secrets", headers=_bh(admin2)).status_code == 200
    # admin1 revokes admin2.
    rv = client.post(f"/v1/admin/principals/{admin2_id}/revoke", json={"reason": "compromised"}, headers=_bh(admin1))
    assert rv.status_code == 200, rv.text
    # admin2's admin token is now denied the control plane — and cannot self-reactivate.
    assert client.get("/v1/admin/vault/secrets", headers=_bh(admin2)).status_code == 403
    assert client.post(f"/v1/admin/principals/{admin2_id}/reactivate", headers=_bh(admin2)).status_code == 403
    # A NON-revoked admin can still reactivate admin2, restoring its access.
    assert client.post(f"/v1/admin/principals/{admin2_id}/reactivate", headers=_bh(admin1)).status_code == 200
    assert client.get("/v1/admin/vault/secrets", headers=_bh(admin2)).status_code == 200


def test_overlay_restricted_skill_must_be_pin_required(client: TestClient, idp: _DemoIdP) -> None:
    """A runtime-registered RESTRICTED skill that is AUTO would bypass the production
    sender-constraint boot-lint (overlay entries can't carry sender-constraint). It is
    refused; RESTRICTED+PIN_REQUIRED and UNCLASSIFIED+AUTO are accepted."""
    admin = _admin(idp, tenant_id="mcpip-inc")
    reg = lambda body: client.post("/v1/admin/skills/register", json=body, headers=_bh(admin))
    # restricted + auto → opaque deny (the exfil posture the boot lint rejects).
    assert reg({"alias": "skill_r_auto", "target": "rest.a", "risk_tier": "auto", "classification": "restricted"}).status_code == 403
    # restricted + pin_required → allowed (the PIN protects it, as the lint exempts).
    assert reg({"alias": "skill_r_pin", "target": "rest.b", "risk_tier": "pin_required", "classification": "restricted"}).status_code == 200
    # unclassified + auto → allowed (the ordinary case).
    assert reg({"alias": "skill_u_auto", "target": "rest.c", "risk_tier": "auto", "classification": "unclassified"}).status_code == 200


def test_worm_redacts_vendor_prefixed_secret_keys(client: TestClient, idp: _DemoIdP) -> None:
    """Redaction matches secret tokens as a whole/suffix, so a vendor-prefixed key
    (aws_secret_access_key, gcp_private_key) still scrubs — while the non-secret
    identifier secret_id is kept."""
    from audit.worm_logger import _redact

    out = _redact({
        "aws_secret_access_key": "AKIA-SECRET",
        "gcp_private_key": "-----BEGIN-----",
        "x-api-key": "k-123",
        "secret_id": "aws-broker",  # non-secret identifier — MUST be kept
        "vendor": "aws",
    })
    assert out["aws_secret_access_key"] == "[REDACTED]"
    assert out["gcp_private_key"] == "[REDACTED]"
    assert out["x-api-key"] == "[REDACTED]"
    assert out["secret_id"] == "aws-broker" and out["vendor"] == "aws"


def test_identity_shaped_key_with_bidi_mark_is_denied(client: TestClient, idp: _DemoIdP) -> None:
    """An identity-shaped argument key wearing a bidi format mark (which NFKC does not
    strip) is still a hard deny — the ingress string guard now rejects Cf/Zl/Zp."""
    token = idp.mint(tenant_id="tenant-acme", agent_id="agent-bidi")
    # "role" + U+200E (LEFT-TO-RIGHT MARK) as an argument key.
    resp = _post(client, alias=_AUTO_ALIAS, arguments={"role‎": "admin"}, token=token)
    _assert_opaque_denial(resp)


# ---------------------------------------------------------------------------
# Workspace Generate — brief → validated plan → review → apply via hardened endpoints.
# ---------------------------------------------------------------------------


def test_workspace_draft_validate_apply_roundtrip(client: TestClient, idp: _DemoIdP) -> None:
    """Draft a plan from a brief, validate it, apply it — the generated skills become
    real registered skills and the org chart persists. Apply is idempotent + WORM-logged."""
    admin = _admin(idp, tenant_id="tenant-globex")
    # 1) Draft (deterministic, inference-free).
    draft = client.post("/v1/admin/workspace/draft",
                        json={"brief": "engineering and finance teams", "company": "Globex", "tenant": "tenant-globex"},
                        headers=_bh(admin))
    assert draft.status_code == 200, draft.text
    plan = _json(draft)["plan"]
    assert plan["skills"] and plan["org_units"]
    # 2) Validate — clean plan is ok, no errors.
    val = client.post("/v1/admin/workspace/plan/validate", json={"plan": plan}, headers=_bh(admin))
    assert val.status_code == 200 and _json(val)["ok"] is True and _json(val)["errors"] == []
    # 3) Apply — creates every skill; the org chart is stored.
    ap = client.post("/v1/admin/workspace/plan/apply", json={"plan": plan}, headers=_bh(admin))
    assert ap.status_code == 200, ap.text
    created = _json(ap)["created"]
    assert set(created) == {s["alias"] for s in plan["skills"]}
    # The skills are now REAL registered skills.
    reg = client.get("/v1/admin/skills/registered", headers=_bh(admin))
    registered_aliases = set(_json(reg)["registered"])
    assert {s["alias"] for s in plan["skills"]} <= registered_aliases
    # The org chart persisted.
    dr = client.get("/v1/directory", headers=_bh(admin))
    assert _json(dr)["document"]["schema"] == "mcpip-directory/1"
    # 4) Re-apply is idempotent — everything skipped, nothing re-created.
    again = client.post("/v1/admin/workspace/plan/apply", json={"plan": plan}, headers=_bh(admin))
    assert again.status_code == 200
    assert _json(again)["created"] == [] and set(_json(again)["skipped"]) == set(created)
    # WORM carries the apply action.
    assert _last_deny_reason() is None  # the last event was an allow/admin_action, not a deny


def test_workspace_apply_rejects_policy_violating_plan(client: TestClient, idp: _DemoIdP) -> None:
    """A hand-crafted plan with a restricted+auto skill is refused fail-closed at apply —
    nothing is registered."""
    admin = _admin(idp, tenant_id="tenant-globex")
    bad_plan = {
        "company": "X", "tenant": "tenant-globex", "org_units": [],
        "skills": [{"alias": "skill_sneaky_restricted", "target": "rest.x", "risk_tier": "auto", "classification": "restricted"}],
    }
    # validate flags it…
    val = client.post("/v1/admin/workspace/plan/validate", json={"plan": bad_plan}, headers=_bh(admin))
    assert val.status_code == 200 and _json(val)["ok"] is False
    # …and apply refuses it opaquely (nothing registered).
    ap = client.post("/v1/admin/workspace/plan/apply", json={"plan": bad_plan}, headers=_bh(admin))
    assert ap.status_code == 403
    reg = client.get("/v1/admin/skills/registered", headers=_bh(admin))
    assert "skill_sneaky_restricted" not in _json(reg)["registered"]


def test_workspace_endpoints_require_admin(client: TestClient, idp: _DemoIdP) -> None:
    """All three workspace endpoints are CAP_DIRECTORY_ADMIN — a plain token is denied."""
    no_cap = idp.mint(tenant_id="tenant-globex", agent_id="agent-nocap-ws")
    assert client.post("/v1/admin/workspace/draft", json={"brief": "x"}, headers=_bh(no_cap)).status_code == 403
    assert client.post("/v1/admin/workspace/plan/validate", json={"plan": {}}, headers=_bh(no_cap)).status_code == 403
    assert client.post("/v1/admin/workspace/plan/apply", json={"plan": {}}, headers=_bh(no_cap)).status_code == 403


# ---------------------------------------------------------------------------
# WORM tamper detection (isolated db /10; independent of the live app).
# ---------------------------------------------------------------------------


async def _tamper_probe() -> tuple[bool, bool, bool]:
    """Emit → close → verify; then tamper an event and a root; return the 3 verdicts.

    Returns ``(intact_ok, event_tamper_detected, root_tamper_detected)``.
    """
    key = Ed25519PrivateKey.generate()

    async def _fresh() -> Any:
        client: Any = aioredis.from_url(  # type: ignore[no-untyped-call]
            _TAMPER_REDIS_URL, decode_responses=True
        )
        await client.flushdb()
        return client

    # --- Stage 1: honest chain verifies intact. --------------------------------
    r1 = await _fresh()
    worm1 = WormLogger(r1, key)
    for i in range(5):
        await worm1.emit({"decision": "allow", "n": i})
    await worm1.close_epoch()
    intact_ok = (await worm1.verify_chain()) == (True, None)
    await r1.aclose()

    # --- Stage 2: mutate one buffered event → Merkle root recompute fails. ------
    r2 = await _fresh()
    worm2 = WormLogger(r2, key)
    for i in range(5):
        await worm2.emit({"decision": "allow", "n": i})
    await worm2.close_epoch()
    entries: Any = await r2.xrange(_EVENTS_STREAM)
    _sid, fields = entries[0]
    mutated = dict(fields)
    rec = str(mutated["record"])
    mutated["record"] = rec[:-2] + ("00" if rec[-2:] != "00" else "11")
    # A later same-seq entry shadows the original in the seq->record view verify uses.
    await r2.xadd(_EVENTS_STREAM, mutated)
    ev_bad, _ = await worm2.verify_chain()
    event_tamper_detected = ev_bad is False
    await r2.aclose()

    # --- Stage 3: mutate the signed epoch header → signature verify fails. ------
    r3 = await _fresh()
    worm3 = WormLogger(r3, key)
    for i in range(5):
        await worm3.emit({"decision": "allow", "n": i})
    await worm3.close_epoch()
    headers: Any = await r3.xrange("mcpip:worm:epochs")
    _hsid, hfields = headers[0]
    forged = dict(hfields)
    sig = str(forged["signature"])
    forged["signature"] = sig[:-2] + ("00" if sig[-2:] != "00" else "11")
    await r3.delete("mcpip:worm:epochs")
    await r3.xadd("mcpip:worm:epochs", forged)
    rt_bad, _ = await worm3.verify_chain()
    root_tamper_detected = rt_bad is False
    await r3.aclose()

    return intact_ok, event_tamper_detected, root_tamper_detected


def test_worm_tamper_detection() -> None:
    """A mutated event AND a mutated signed root are both detected by verify_chain."""
    intact_ok, event_detected, root_detected = asyncio.run(_tamper_probe())
    assert intact_ok, "honest chain must verify intact"
    assert event_detected, "a mutated buffered event must fail Merkle-root recompute"
    assert root_detected, "a mutated signed root must fail the signature check"


async def _header_field_tamper_probe() -> tuple[bool, bool]:
    """Honest verify intact; mutating the now-signed ``last_stream_id`` is detected.

    Returns ``(intact_ok, last_stream_id_tamper_detected)``.
    """
    key = Ed25519PrivateKey.generate()
    client: Any = aioredis.from_url(  # type: ignore[no-untyped-call]
        _TAMPER_REDIS_URL, decode_responses=True
    )
    await client.flushdb()
    worm = WormLogger(client, key)
    for i in range(4):
        await worm.emit({"decision": "allow", "n": i})
    await worm.close_epoch()
    intact_ok = (await worm.verify_chain()) == (True, None)

    # Mutate the signed epoch header's last_stream_id (formerly an UNSIGNED field) in the
    # epochs stream. It is now part of the signed epoch_hash core, so verify recomputes a
    # different epoch_hash and the Ed25519 signature no longer matches.
    headers: Any = await client.xrange("mcpip:worm:epochs")
    _hsid, hfields = headers[0]
    forged = dict(hfields)
    forged["last_stream_id"] = "9999999999999-0"
    await client.delete("mcpip:worm:epochs")
    await client.xadd("mcpip:worm:epochs", forged)
    bad, _ = await worm.verify_chain()
    detected = bad is False
    await client.aclose()
    return intact_ok, detected


def test_worm_unsigned_header_field_detected() -> None:
    """Mutating last_stream_id (previously unsigned) is now tamper-evident."""
    intact_ok, detected = asyncio.run(_header_field_tamper_probe())
    assert intact_ok, "honest chain must verify intact"
    assert detected, "a mutated last_stream_id must be caught — the field is now signed"


async def _incremental_verify_probe() -> tuple[bool, bool, bool]:
    """
    Incremental verify from a trusted checkpoint agrees with full verify AND still
    catches a suffix tamper.

    Returns ``(both_intact, suffix_tamper_detected, prefix_untouched_intact)``.
    """
    from audit.worm_logger import _EVENTS_STREAM as EVSTREAM

    key = Ed25519PrivateKey.generate()
    client: Any = aioredis.from_url(  # type: ignore[no-untyped-call]
        _TAMPER_REDIS_URL, decode_responses=True
    )
    await client.flushdb()
    worm = WormLogger(client, key)

    async def _build_epoch(n: int) -> None:
        for i in range(3):
            await worm.emit({"decision": "allow", "epoch": n, "i": i})
        await worm.close_epoch()

    for n in range(3):  # epochs 0,1,2 (seqs 1..9).
        await _build_epoch(n)
    assert (await worm.verify_chain()) == (True, None)
    checkpoint = await worm.latest_checkpoint()  # (2, epoch2_hash)
    assert checkpoint is not None and checkpoint[0] == 2

    for n in range(3, 6):  # epochs 3,4,5 (seqs 10..18).
        await _build_epoch(n)

    both_intact = (
        (await worm.verify_chain()) == (True, None)
        and (await worm.verify_chain(checkpoint=checkpoint)) == (True, None)
    )

    # Tamper a SUFFIX epoch's event (seq 14 → epoch 4, after the checkpoint).
    entries: Any = await client.xrange(EVSTREAM)
    for sid, f in entries:
        if int(f["seq"]) == 14:
            mutated = dict(f)
            rec = str(mutated["record"])
            mutated["record"] = rec[:-2] + ("00" if rec[-2:] != "00" else "11")
            await client.xadd(EVSTREAM, mutated)
            break
    incr_bad, _ = await worm.verify_chain(checkpoint=checkpoint)
    suffix_detected = incr_bad is False

    await client.aclose()
    return both_intact, suffix_detected, True


def test_worm_incremental_verify() -> None:
    """Checkpoint-based incremental verify matches full verify and catches suffix tamper."""
    both_intact, suffix_detected, _ = asyncio.run(_incremental_verify_probe())
    assert both_intact, "incremental verify from a trusted checkpoint must agree intact"
    assert suffix_detected, "a tampered suffix epoch must be caught by incremental verify"


# ---------------------------------------------------------------------------
# WORM rollback / tail-truncation detection via the out-of-tamper-domain anchor
# (isolated db /11; independent of the live app).
# ---------------------------------------------------------------------------

_ROLLBACK_REDIS_URL = "redis://localhost:63790/11"


async def _rollback_probe() -> tuple[bool, bool, bool, bool, bool]:
    """
    Reproduce the W8/W9 rollback attacks with AND without the signed head anchor.

    Returns ``(honest_intact, w9_anchorless_intact, w9_anchor_detected,
    w8_anchor_detected, ahead_of_anchor_intact)``: the anchorless verify is BLIND to a
    tail-truncation (the finding), while the anchor-backed verify CATCHES both a
    rollback-to-a-prior-signed-epoch (W9) and a delete-all-headers erasure (W8), and
    still reports intact when the Redis chain legitimately runs AHEAD of the anchor
    (a crash between header-write and anchor-append).
    """
    from audit import AnchorStore  # local import: keeps the app-suite import surface lean.
    from audit.worm_logger import (
        _CURSOR_KEY,
        _EPOCH_HEAD_KEY,
        _EPOCH_INDEX_KEY,
        _EPOCH_LAST_SEQ_KEY,
        _EPOCH_NUM_KEY,
        _EPOCHS_STREAM,
        ALL_WORM_KEYS,
    )

    key = Ed25519PrivateKey.generate()

    async def _fresh() -> Any:
        c: Any = aioredis.from_url(  # type: ignore[no-untyped-call]
            _ROLLBACK_REDIS_URL, decode_responses=True
        )
        await c.delete(*ALL_WORM_KEYS)
        return c

    async def _build(worm: WormLogger) -> None:
        for ep in range(3):
            for i in range(3):
                await worm.emit({"decision": "allow", "epoch": ep, "n": i})
            await worm.close_epoch()

    async def _rollback_w9(r: Any) -> None:
        headers: Any = await r.xrange(_EPOCHS_STREAM)
        newest_sid, _newest = headers[-1]
        _prev_sid, prev = headers[-2]
        prev_epoch = int(prev["epoch"])
        await r.xdel(_EPOCHS_STREAM, newest_sid)
        await r.hdel(_EPOCH_INDEX_KEY, str(prev_epoch + 1))
        evs: Any = await r.xrange(_EVENTS_STREAM)
        for sid, f in evs:
            if int(f["seq"]) > int(prev["end_seq"]):
                await r.xdel(_EVENTS_STREAM, sid)
        # Rewrite the plaintext linkage counters to the prior still-valid signed epoch.
        await r.set(_EPOCH_NUM_KEY, prev["epoch"])
        await r.set(_EPOCH_HEAD_KEY, prev["epoch_hash"])
        await r.set(_EPOCH_LAST_SEQ_KEY, prev["end_seq"])
        await r.set(_CURSOR_KEY, prev["last_stream_id"])

    async def _erase_w8(r: Any) -> None:
        await r.delete(
            _EPOCHS_STREAM,
            _EPOCH_INDEX_KEY,
            _EPOCH_NUM_KEY,
            _EPOCH_HEAD_KEY,
            _EPOCH_LAST_SEQ_KEY,
            _CURSOR_KEY,
        )

    import os
    import tempfile

    # --- W9 WITHOUT anchor: the anchorless verify is blind (proves the finding). ----
    r = await _fresh()
    worm = WormLogger(r, key, path="/tmp/_wtest.jsonl")
    await _build(worm)
    honest_intact = (await worm.verify_chain()) == (True, None)
    await _rollback_w9(r)
    w9_anchorless_intact = (await worm.verify_chain()) == (True, None)
    await r.aclose()

    # --- W9 WITH anchor: rollback to a prior signed epoch is DETECTED. ----
    r = await _fresh()
    apath = tempfile.mktemp(suffix=".anchor")
    anchor = AnchorStore(key, apath)
    anchor.reset()
    worm = WormLogger(r, key, path="/tmp/_wtest.jsonl", anchor=anchor)
    await _build(worm)
    assert (await worm.verify_chain()) == (True, None)
    await _rollback_w9(r)
    w9_anchor_detected = (await worm.verify_chain())[0] is False
    os.remove(apath)
    await r.aclose()

    # --- W8 WITH anchor: delete-all-headers + reset-to-genesis is DETECTED. ----
    r = await _fresh()
    apath = tempfile.mktemp(suffix=".anchor")
    anchor = AnchorStore(key, apath)
    anchor.reset()
    worm = WormLogger(r, key, path="/tmp/_wtest.jsonl", anchor=anchor)
    await _build(worm)
    await _erase_w8(r)
    w8_anchor_detected = (await worm.verify_chain())[0] is False
    os.remove(apath)
    await r.aclose()

    # --- Chain AHEAD of anchor (crash after header, before anchor append): intact. ----
    r = await _fresh()
    apath = tempfile.mktemp(suffix=".anchor")
    anchor = AnchorStore(key, apath)
    anchor.reset()
    worm = WormLogger(r, key, path="/tmp/_wtest.jsonl", anchor=anchor)
    await _build(worm)
    # Seal one MORE epoch straight into Redis without recording its anchor line, so the
    # in-Redis head is one epoch ahead of the durable anchor watermark.
    plain_worm = WormLogger(r, key, path="/tmp/_wtest.jsonl")  # no anchor -> no record.
    await plain_worm.emit({"decision": "allow", "epoch": 3, "n": 0})
    await plain_worm.close_epoch()
    ahead_intact = (await worm.verify_chain()) == (True, None)
    os.remove(apath)
    await r.aclose()

    return (
        honest_intact,
        w9_anchorless_intact,
        w9_anchor_detected,
        w8_anchor_detected,
        ahead_intact,
    )


def test_worm_rollback_detection_via_anchor() -> None:
    """The signed head anchor makes W8/W9 tail-truncation/rollback tamper-evident."""
    (
        honest_intact,
        w9_anchorless_intact,
        w9_detected,
        w8_detected,
        ahead_intact,
    ) = asyncio.run(_rollback_probe())
    assert honest_intact, "an honest anchorless chain must verify intact"
    assert w9_anchorless_intact, (
        "the anchorless verify is BLIND to a tail-truncation (the finding under fix)"
    )
    assert w9_detected, "W9 rollback-to-prior-signed-epoch must be caught by the anchor"
    assert w8_detected, "W8 delete-all-headers erasure must be caught by the anchor"
    assert ahead_intact, (
        "a Redis chain legitimately AHEAD of the lagging anchor must stay intact"
    )


# ---------------------------------------------------------------------------
# WORM checkpoint-compaction + per-close leaf cap (isolated db /12).
# ---------------------------------------------------------------------------

_COMPACT_REDIS_URL = "redis://localhost:63790/12"


async def _compaction_probe() -> tuple[bool, ...]:
    """
    Compaction folds old epochs into a signed super-checkpoint; verify (full + both
    incremental variants) stays intact, storage is trimmed, and tamper is still caught.
    """
    import json
    import os
    import tempfile

    from audit import AnchorStore
    from audit.worm_logger import (
        _CURSOR_KEY,
        _EPOCH_HEAD_KEY,
        _EPOCH_INDEX_KEY,
        _EPOCH_LAST_SEQ_KEY,
        _EPOCH_NUM_KEY,
        _EPOCHS_STREAM,
        _SUPERCP_KEY,
        ALL_WORM_KEYS,
    )

    key = Ed25519PrivateKey.generate()
    r: Any = aioredis.from_url(  # type: ignore[no-untyped-call]
        _COMPACT_REDIS_URL, decode_responses=True
    )
    await r.delete(*ALL_WORM_KEYS)
    apath = tempfile.mktemp(suffix=".anchor")
    anchor = AnchorStore(key, apath)
    anchor.reset()
    worm = WormLogger(r, key, path="/tmp/_ctest.jsonl", anchor=anchor)

    for ep in range(20):
        for i in range(3):
            await worm.emit({"decision": "allow", "epoch": ep, "i": i})
        await worm.close_epoch()

    pre_intact = (await worm.verify_chain()) == (True, None)
    cp_before = await worm.latest_checkpoint()

    res = await worm.compact(keep_epochs=5, min_stride=1)
    target_ok = res is not None and res[0] == 14

    hdrs: Any = await r.xrange(_EPOCHS_STREAM)
    surviving = sorted(int(f["epoch"]) for _s, f in hdrs)
    trimmed_ok = surviving == [15, 16, 17, 18, 19]
    idx_keys: Any = await r.hkeys(_EPOCH_INDEX_KEY)
    idx_ok = sorted(int(e) for e in idx_keys) == [15, 16, 17, 18, 19]

    post_intact = (await worm.verify_chain()) == (True, None)
    assert cp_before is not None
    incr_pre_cp = (await worm.verify_chain(checkpoint=cp_before)) == (True, None)
    incr_subsumed = (
        await worm.verify_chain(checkpoint=(10, "deadbeef"))
    ) == (True, None)

    with open(apath, encoding="utf-8") as fh:
        anch = sorted(json.loads(line)["epoch"] for line in fh if line.strip())
    anchor_rotated = bool(anch) and min(anch) >= 14 and max(anch) == 19

    # Tamper: mutate the signed super-checkpoint -> caught.
    raw = await r.get(_SUPERCP_KEY)
    d = json.loads(raw)
    d["epoch_hash"] = d["epoch_hash"][:-2] + (
        "00" if d["epoch_hash"][-2:] != "00" else "11"
    )
    await r.set(_SUPERCP_KEY, json.dumps(d, separators=(",", ":")))
    supercp_tamper = (await worm.verify_chain())[0] is False
    await r.set(_SUPERCP_KEY, raw)

    # Tamper: delete the super-checkpoint (stream now starts at 15, not 0) -> caught.
    await r.delete(_SUPERCP_KEY)
    supercp_delete = (await worm.verify_chain())[0] is False
    await r.set(_SUPERCP_KEY, raw)

    # Rollback the suffix + rewrite counters -> caught by the anchor low-watermark.
    hdrs = await r.xrange(_EPOCHS_STREAM)
    newest_sid, newest = hdrs[-1]
    _psid, prev = hdrs[-2]
    await r.xdel(_EPOCHS_STREAM, newest_sid)
    await r.hdel(_EPOCH_INDEX_KEY, newest["epoch"])
    await r.set(_EPOCH_NUM_KEY, prev["epoch"])
    await r.set(_EPOCH_HEAD_KEY, prev["epoch_hash"])
    await r.set(_EPOCH_LAST_SEQ_KEY, prev["end_seq"])
    await r.set(_CURSOR_KEY, prev["last_stream_id"])
    rollback_caught = (await worm.verify_chain())[0] is False

    os.remove(apath)
    await r.aclose()
    return (
        pre_intact,
        target_ok,
        trimmed_ok,
        idx_ok,
        post_intact,
        incr_pre_cp,
        incr_subsumed,
        anchor_rotated,
        supercp_tamper,
        supercp_delete,
        rollback_caught,
    )


def test_worm_checkpoint_compaction() -> None:
    """Compaction bounds storage AND keeps verify intact + tamper-evident."""
    (
        pre_intact,
        target_ok,
        trimmed_ok,
        idx_ok,
        post_intact,
        incr_pre_cp,
        incr_subsumed,
        anchor_rotated,
        supercp_tamper,
        supercp_delete,
        rollback_caught,
    ) = asyncio.run(_compaction_probe())
    assert pre_intact, "chain must verify intact before compaction"
    assert target_ok, "compaction must checkpoint at last_epoch - keep_epochs"
    assert trimmed_ok, "compacted epoch headers must be trimmed from the stream"
    assert idx_ok, "compacted epoch index entries must be trimmed"
    assert post_intact, "full verify must stay intact anchored on the super-checkpoint"
    assert incr_pre_cp, "incremental verify from a pre-compaction checkpoint must hold"
    assert incr_subsumed, "a checkpoint compacted away must defer to the super-checkpoint"
    assert anchor_rotated, "the anchor file must be rotated to bounded length"
    assert supercp_tamper, "a mutated super-checkpoint must be caught"
    assert supercp_delete, "a deleted super-checkpoint over a trimmed stream must be caught"
    assert rollback_caught, "a post-compaction suffix rollback must be caught by the anchor"


async def _leaf_cap_probe() -> tuple[bool, bool, bool]:
    """A single close seals at most WORM_MAX_EPOCH_LEAVES; the rest drains + stays intact."""
    import audit.worm_logger as wl
    from audit.worm_logger import ALL_WORM_KEYS

    key = Ed25519PrivateKey.generate()
    r: Any = aioredis.from_url(  # type: ignore[no-untyped-call]
        _COMPACT_REDIS_URL, decode_responses=True
    )
    await r.delete(*ALL_WORM_KEYS)
    worm = WormLogger(r, key, path="/tmp/_ltest.jsonl")

    orig = wl.WORM_MAX_EPOCH_LEAVES
    wl.WORM_MAX_EPOCH_LEAVES = 10
    try:
        for i in range(25):
            await worm.emit({"decision": "allow", "i": i})
        h1 = await worm.close_epoch()
        h2 = await worm.close_epoch()
        h3 = await worm.close_epoch()
        h4 = await worm.close_epoch()
        capped_ok = (
            h1 is not None and h1.leaf_count == 10
            and h2 is not None and h2.leaf_count == 10
            and h3 is not None and h3.leaf_count == 5
            and h4 is None
        )
        intact_ok = (await worm.verify_chain()) == (True, None)
        incl_ok = True
        for eid in await worm.list_event_ids():
            pr = await worm.inclusion_proof(eid)
            incl_ok = incl_ok and (
                pr is not None
                and merkle.verify_inclusion(
                    merkle.leaf_digest(pr.record.encode("utf-8")),
                    pr.proof,
                    bytes.fromhex(pr.merkle_root),
                )
            )
    finally:
        wl.WORM_MAX_EPOCH_LEAVES = orig
    await r.aclose()
    return capped_ok, intact_ok, incl_ok


def test_worm_per_close_leaf_cap() -> None:
    """close_epoch seals bounded chunks; contiguous coverage + proofs survive."""
    capped_ok, intact_ok, incl_ok = asyncio.run(_leaf_cap_probe())
    assert capped_ok, "each close must seal at most the leaf cap, draining the rest"
    assert intact_ok, "a capped multi-epoch chain must verify intact"
    assert incl_ok, "every event must still have a valid inclusion proof under the cap"


# ---------------------------------------------------------------------------
# Sender-constrained tokens (proof-of-possession) end-to-end — the real
# pipeline + the durable Redis replay guard, driven through /v1/authorize.
#
# A JWT that carries a `cnf.jkt` binding is NOT a bearer token: the caller must
# ALSO present a DPoP-style proof of the matching private key, bound to THIS
# request. These assert the wiring holds end-to-end and that a captured
# sender-constrained token (proof reused / absent / for the wrong key / wrong
# resource) is unusable. Every deny is the SAME opaque envelope with jwt_invalid
# recorded only to WORM.
# ---------------------------------------------------------------------------

_AUTHZ_HTU = "http://testserver/v1/authorize"


def _proof_keypair() -> tuple[Ed25519PrivateKey, dict[str, Any], str]:
    """A fresh Ed25519 proof key + its public JWK + RFC-7638 thumbprint."""
    pk = Ed25519PrivateKey.generate()
    pub_jwk: dict[str, Any] = json.loads(OKPAlgorithm.to_jwk(pk.public_key()))
    return pk, pub_jwk, jwk_thumbprint(pub_jwk)


def _sc_token(
    idp: _DemoIdP,
    *,
    jkt: str,
    act_sub: Optional[str] = None,
    tenant_id: str = "tenant-acme",
    agent_id: str = "agent-orchestrator-1",
) -> str:
    """Mint a validly-signed, sender-constrained JWT (cnf.jkt; optional act.sub)."""
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
    if act_sub is not None:
        claims["act"] = {"sub": act_sub}
    return _sign(idp, claims)


def _ath(token: str) -> str:
    """RFC 9449 access-token hash: base64url(sha256(token)), no padding."""
    return (
        base64.urlsafe_b64encode(hashlib.sha256(token.encode("ascii")).digest())
        .rstrip(b"=")
        .decode()
    )


def _dpop_proof(
    private_key: Ed25519PrivateKey,
    pub_jwk: dict[str, Any],
    *,
    token: str,
    alias: str,
    arguments: dict[str, Any],
    htu: str = _AUTHZ_HTU,
    htm: str = "POST",
    jti: Optional[str] = None,
    tenant_id: str = "tenant-acme",
    agent_id: str = "agent-orchestrator-1",
) -> str:
    """A DPoP-style proof bound to THIS action: key + method + url + token (ath) + payload (pch).

    ``pch`` is the exact ``lock_payload_hash`` digest the gateway recomputes for the
    resolved (tenant, agent, alias, arguments), so a proof minted for one call cannot
    be substituted onto another.
    """
    header = {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": pub_jwk}
    payload = {
        "htm": htm,
        "htu": htu,
        "ath": _ath(token),
        "pch": lock_payload_hash(tenant_id, agent_id, alias, arguments),
        "iat": int(time.time()),
        "jti": jti or uuid.uuid4().hex,
    }
    return jwt.encode(payload, private_key, algorithm="EdDSA", headers=header)


def _post_sc(
    client: TestClient,
    *,
    alias: str,
    arguments: dict[str, Any],
    token: str,
    proof: Optional[str],
) -> Response:
    """POST /v1/authorize with a sender-constrained token + optional DPoP proof."""
    body: dict[str, Any] = {
        "source_format": "openai_tool_call",
        "tool_call": _openai_call(alias, arguments),
        "jwt": token,
    }
    headers: dict[str, str] = {}
    if proof is not None:
        headers["DPoP"] = proof
    resp: Response = client.post("/v1/authorize", json=body, headers=headers)
    return resp


def test_sc_valid_proof_allows(client: TestClient, idp: _DemoIdP) -> None:
    """cnf-bound token + a valid action-bound proof → 200 (possession is proven)."""
    pk, jwk, jkt = _proof_keypair()
    token = _sc_token(idp, jkt=jkt)
    args = {"period": "SC-1"}
    proof = _dpop_proof(pk, jwk, token=token, alias=_AUTO_ALIAS, arguments=args)
    resp = _post_sc(client, alias=_AUTO_ALIAS, arguments=args, token=token, proof=proof)
    assert resp.status_code == 200, resp.text
    assert _json(resp)["decision"] == "allow"


def test_sc_missing_proof_denied(client: TestClient, idp: _DemoIdP) -> None:
    """cnf-bound token with NO DPoP proof → opaque 403; WORM records jwt_invalid."""
    _pk, _jwk, jkt = _proof_keypair()
    token = _sc_token(idp, jkt=jkt)
    resp = _post_sc(
        client, alias=_AUTO_ALIAS, arguments={"period": "SC-2"}, token=token, proof=None
    )
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "jwt_invalid"


def test_sc_wrong_key_proof_denied(client: TestClient, idp: _DemoIdP) -> None:
    """A proof signed by a DIFFERENT key than cnf.jkt → thumbprint mismatch → deny."""
    _pk, _jwk, jkt = _proof_keypair()  # token is bound to THIS key…
    other_pk, other_jwk, _other_jkt = _proof_keypair()  # …proof presents a foreign one.
    token = _sc_token(idp, jkt=jkt)
    args = {"period": "SC-3"}
    proof = _dpop_proof(other_pk, other_jwk, token=token, alias=_AUTO_ALIAS, arguments=args)
    resp = _post_sc(client, alias=_AUTO_ALIAS, arguments=args, token=token, proof=proof)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "jwt_invalid"


def test_sc_replayed_proof_denied(client: TestClient, idp: _DemoIdP) -> None:
    """The SAME proof twice → first allows, replay is denied by the Redis guard."""
    pk, jwk, jkt = _proof_keypair()
    token = _sc_token(idp, jkt=jkt)
    args = {"period": "SC-4"}
    proof = _dpop_proof(
        pk, jwk, token=token, alias=_AUTO_ALIAS, arguments=args, jti="sc-replay-jti"
    )
    first = _post_sc(client, alias=_AUTO_ALIAS, arguments=args, token=token, proof=proof)
    assert first.status_code == 200, first.text
    replay = _post_sc(client, alias=_AUTO_ALIAS, arguments=args, token=token, proof=proof)
    _assert_opaque_denial(replay)
    assert _last_deny_reason() == "jwt_invalid"


def test_sc_htu_mismatch_denied(client: TestClient, idp: _DemoIdP) -> None:
    """A proof minted for a different resource (htu) cannot be relayed here → deny."""
    pk, jwk, jkt = _proof_keypair()
    token = _sc_token(idp, jkt=jkt)
    args = {"period": "SC-5"}
    proof = _dpop_proof(
        pk, jwk, token=token, alias=_AUTO_ALIAS, arguments=args,
        htu="http://testserver/v1/mcp",
    )
    resp = _post_sc(client, alias=_AUTO_ALIAS, arguments=args, token=token, proof=proof)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "jwt_invalid"


def test_sc_body_swap_denied(client: TestClient, idp: _DemoIdP) -> None:
    """A proof minted for payload A cannot be substituted onto payload B (pch binding)."""
    pk, jwk, jkt = _proof_keypair()
    token = _sc_token(idp, jkt=jkt)
    # Proof binds arguments A, but the request carries arguments B → pch mismatch.
    proof = _dpop_proof(
        pk, jwk, token=token, alias=_AUTO_ALIAS, arguments={"period": "SC-6-A"}
    )
    resp = _post_sc(
        client, alias=_AUTO_ALIAS, arguments={"period": "SC-6-B"}, token=token, proof=proof
    )
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "jwt_invalid"


def test_sc_delegation_act_sub_allows(client: TestClient, idp: _DemoIdP) -> None:
    """A delegated (act.sub) sender-constrained token + valid proof → 200."""
    pk, jwk, jkt = _proof_keypair()
    token = _sc_token(idp, jkt=jkt, act_sub="human:alice@acme")
    args = {"period": "SC-7"}
    proof = _dpop_proof(pk, jwk, token=token, alias=_AUTO_ALIAS, arguments=args)
    resp = _post_sc(client, alias=_AUTO_ALIAS, arguments=args, token=token, proof=proof)
    assert resp.status_code == 200, resp.text
    assert _json(resp)["decision"] == "allow"


def test_bearer_no_cnf_ignores_dpop(client: TestClient, idp: _DemoIdP) -> None:
    """A legacy bearer token (no cnf) is unaffected even if a stray DPoP header rides along."""
    pk, jwk, _jkt = _proof_keypair()
    token = idp.mint()  # plain 8-claim bearer, no cnf.
    args = {"period": "SC-8"}
    stray = _dpop_proof(pk, jwk, token=token, alias=_AUTO_ALIAS, arguments=args)
    body: dict[str, Any] = {
        "source_format": "openai_tool_call",
        "tool_call": _openai_call(_AUTO_ALIAS, args),
        "jwt": token,
    }
    resp = client.post("/v1/authorize", json=body, headers={"DPoP": stray})
    assert resp.status_code == 200, resp.text
    assert _json(resp)["decision"] == "allow"


# ---------------------------------------------------------------------------
# N3 — RFC 8693 full delegation chain + ID-JAG recognition, WORM-only.
#
# A delegated token carries a nested ``act`` chain (act -> act.act -> …). The
# gateway records the FULL ORDERED chain of subjects to WORM (never the agent
# wire), recognizes the ID-JAG token-type marker, and fails closed on any
# malformed nested actor. These drive the real pipeline + a direct WORM read.
# ---------------------------------------------------------------------------

_DELEG_ALIAS = _AUTO_ALIAS


def _nested_act(chain: list[str]) -> dict[str, Any]:
    """Build a nested RFC-8693 ``act`` object from an ordered subject list.

    ``["A", "B", "C"]`` → ``{"sub": "A", "act": {"sub": "B", "act": {"sub": "C"}}}``.
    """
    node: dict[str, Any] = {"sub": chain[-1]}
    for sub in reversed(chain[:-1]):
        node = {"sub": sub, "act": node}
    return node


def _delegated_token(
    idp: _DemoIdP,
    *,
    chain: Optional[list[str]] = None,
    id_jag: bool = False,
    act: Any = "__unset__",
    tenant_id: str = "tenant-acme",
    agent_id: str = "agent-orchestrator-1",
) -> str:
    """Mint a validly-signed JWT with an optional nested ``act`` chain / ID-JAG marker."""
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
    }
    if act != "__unset__":
        claims["act"] = act
    elif chain is not None:
        claims["act"] = _nested_act(chain)
    if id_jag:
        claims["token_type"] = "urn:ietf:params:oauth:token-type:id-jag"
    return _sign(idp, claims)


def _last_event() -> dict[str, Any]:
    """The most-recently buffered WORM event's redacted ctx dict."""
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=1)
    finally:
        reader.close()
    assert entries, "expected at least one buffered WORM event"
    _sid, fields = entries[0]
    record: Any = json.loads(fields["record"])
    event: Any = record["event"]
    assert isinstance(event, dict)
    return event


def test_deleg_multi_hop_chain_recorded_in_order(
    client: TestClient, idp: _DemoIdP
) -> None:
    """A multi-hop delegated token allows AND WORM records the ordered subject chain."""
    chain = ["svc:agent-a", "svc:agent-b", "human:alice@acme"]
    token = _delegated_token(idp, chain=chain)
    resp = _post(client, alias=_DELEG_ALIAS, arguments={"period": "N3-1"}, token=token)
    assert resp.status_code == 200, resp.text
    assert _json(resp)["decision"] == "allow"
    assert _last_event().get("delegation_chain") == chain


def test_deleg_single_hop_chain_recorded(client: TestClient, idp: _DemoIdP) -> None:
    """A single-hop delegated token records a one-element ordered chain."""
    token = _delegated_token(idp, chain=["human:solo@acme"])
    resp = _post(client, alias=_DELEG_ALIAS, arguments={"period": "N3-2"}, token=token)
    assert resp.status_code == 200, resp.text
    assert _last_event().get("delegation_chain") == ["human:solo@acme"]


def test_deleg_absent_act_is_legacy_no_chain(client: TestClient, idp: _DemoIdP) -> None:
    """A token with NO act records NEITHER delegation_chain NOR id_jag (legacy)."""
    resp = _post(
        client, alias=_DELEG_ALIAS, arguments={"period": "N3-3"}, token=idp.mint()
    )
    assert resp.status_code == 200, resp.text
    event = _last_event()
    assert "delegation_chain" not in event
    assert "id_jag" not in event


def test_id_jag_token_authorizes_and_records_marker(
    client: TestClient, idp: _DemoIdP
) -> None:
    """An ID-JAG token authorizes exactly as a plain JWT and WORM records id_jag=true."""
    token = _delegated_token(idp, chain=["human:alice@acme"], id_jag=True)
    resp = _post(client, alias=_DELEG_ALIAS, arguments={"period": "N3-4"}, token=token)
    assert resp.status_code == 200, resp.text
    assert _json(resp)["decision"] == "allow"
    event = _last_event()
    assert event.get("id_jag") is True
    assert event.get("delegation_chain") == ["human:alice@acme"]


def test_non_id_jag_token_records_no_marker(client: TestClient, idp: _DemoIdP) -> None:
    """A non-ID-JAG delegated token records the chain but no id_jag marker."""
    token = _delegated_token(idp, chain=["human:bob@acme"])
    resp = _post(client, alias=_DELEG_ALIAS, arguments={"period": "N3-5"}, token=token)
    assert resp.status_code == 200, resp.text
    assert "id_jag" not in _last_event()


def test_deleg_malformed_nested_act_fails_closed(
    client: TestClient, idp: _DemoIdP
) -> None:
    """A malformed NESTED act → opaque deny (jwt_invalid), never a silent first-hop pass."""
    token = _delegated_token(idp, act={"sub": "svc:a", "act": "garbage"})
    resp = _post(client, alias=_DELEG_ALIAS, arguments={"period": "N3-6"}, token=token)
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "jwt_invalid"


def test_deleg_chain_never_crosses_agent_wire(
    client: TestClient, idp: _DemoIdP
) -> None:
    """The delegation chain is WORM-only: absent from authorize/catalog/tools-list bodies."""
    chain = ["svc:agent-a", "human:carol@acme"]
    token = _delegated_token(idp, chain=chain, id_jag=True)
    # /v1/authorize response body carries NO chain/actor/marker.
    resp = _post(client, alias=_DELEG_ALIAS, arguments={"period": "N3-7"}, token=token)
    assert resp.status_code == 200, resp.text
    body_txt = resp.text
    for leaked in ("delegation_chain", "act_sub", "id_jag", "carol@acme"):
        assert leaked not in body_txt, leaked
    # /v1/catalog projection carries no chain/actor for any item.
    cat = client.get("/v1/catalog", headers={"Authorization": f"Bearer {token}"})
    assert cat.status_code == 200, cat.text
    cat_txt = cat.text
    for leaked in ("delegation_chain", "act_sub", "id_jag", "carol@acme"):
        assert leaked not in cat_txt, leaked
    # MCP tools/list result carries no chain/actor either.
    mcp = client.post(
        "/v1/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert mcp.status_code == 200, mcp.text
    mcp_txt = mcp.text
    for leaked in ("delegation_chain", "act_sub", "carol@acme"):
        assert leaked not in mcp_txt, leaked


def test_deleg_smuggled_act_in_arguments_is_hard_deny(
    client: TestClient, idp: _DemoIdP
) -> None:
    """Identity is ONLY from the JWT: a smuggled act/sub in arguments is IDENTITY_INJECTION."""
    resp = _post(
        client,
        alias=_DELEG_ALIAS,
        arguments={"act": {"sub": "human:evil@attacker"}},
        token=idp.mint(),
    )
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "identity_injection"


def test_deleg_chain_is_kept_not_redacted(client: TestClient, idp: _DemoIdP) -> None:
    """The chain is an identity, not a secret: the subject string survives in WORM."""
    marker = "human:kept-not-redacted@acme"
    token = _delegated_token(idp, chain=["svc:agent-a", marker])
    resp = _post(client, alias=_DELEG_ALIAS, arguments={"period": "N3-9"}, token=token)
    assert resp.status_code == 200, resp.text
    assert marker in _worm_dump()
    assert _last_event().get("delegation_chain") == ["svc:agent-a", marker]


# --- Resource-side requirement: an alias can DEMAND a sender-constrained token. ---
_SC_REQUIRED_ALIAS = "skill_sc_required_probe"


def _seed_sc_required_alias() -> None:
    """Register a throwaway AUTO alias flagged require_sender_constraint for tenant-acme."""
    _components.registry.register(
        "tenant-acme",
        AliasEntry(
            _SC_REQUIRED_ALIAS,
            "rest.probe.sc.get",
            "cloud_rest",
            RiskTier.AUTO,
            require_sender_constraint=True,
        ),
    )


def test_require_sc_denies_bare_bearer(client: TestClient, idp: _DemoIdP) -> None:
    """A require_sender_constraint alias denies a bare bearer token (no cnf) at the gate."""
    _seed_sc_required_alias()
    resp = _post_sc(
        client, alias=_SC_REQUIRED_ALIAS, arguments={"q": "x"}, token=idp.mint(), proof=None
    )
    _assert_opaque_denial(resp)
    assert _last_deny_reason() == "sender_constraint_required"


def test_require_sc_allows_proven_token(client: TestClient, idp: _DemoIdP) -> None:
    """The same require_sc alias admits a cnf-bound token with a valid action-bound proof."""
    _seed_sc_required_alias()
    pk, jwk, jkt = _proof_keypair()
    token = _sc_token(idp, jkt=jkt)
    args = {"q": "y"}
    proof = _dpop_proof(pk, jwk, token=token, alias=_SC_REQUIRED_ALIAS, arguments=args)
    resp = _post_sc(client, alias=_SC_REQUIRED_ALIAS, arguments=args, token=token, proof=proof)
    assert resp.status_code == 200, resp.text
    assert _json(resp)["decision"] == "allow"


def test_require_sc_denies_non_attested_cnf(client: TestClient, idp: _DemoIdP) -> None:
    """Weak-issuer downgrade lane closed: a cnf from a NON-attesting issuer does not
    satisfy a require_sender_constraint alias — even with a valid, correct proof.

    The token is a perfectly valid sender-constrained token and the proof verifies;
    the ONLY thing denying it is that its minting issuer is not designated attesting.
    """
    _seed_sc_required_alias()
    engine: Any = _components.auth
    original = engine._resolver
    # Re-verify the demo issuer as NON-attesting (a lower-assurance identity IdP).
    engine._resolver = MultiIssuerResolver(
        [
            TokenResolver(
                StaticPEMKeyProvider(idp.public_pem),
                issuer=_DemoIdP.ISSUER,
                audience=_DemoIdP.AUDIENCE,
                attesting=False,
            )
        ]
    )
    try:
        pk, jwk, jkt = _proof_keypair()
        token = _sc_token(idp, jkt=jkt)
        args = {"q": "non-attested"}
        proof = _dpop_proof(pk, jwk, token=token, alias=_SC_REQUIRED_ALIAS, arguments=args)
        resp = _post_sc(
            client, alias=_SC_REQUIRED_ALIAS, arguments=args, token=token, proof=proof
        )
        _assert_opaque_denial(resp)
        assert _last_deny_reason() == "sender_constraint_required"
    finally:
        engine._resolver = original


# --- Cross-edge metrics consistency (regression) ---------------------------------
#
# The console's "decisions since start" tile reads the Prometheus
# ``mcpip_authorize_decisions_total`` counter; Analytics/the WORM stream read the
# audit feed. They diverged (8 vs 13) because the ALLOW/STAGED increments lived in
# the POST /v1/authorize handler only — the MCP-native POST /v1/mcp edge ran the same
# pipeline (and wrote WORM) but never incremented the counter, so MCP decisions were
# invisible to /metrics. The counts now live in the SHARED pipeline. These assert the
# invariant per edge so the undercount can't silently return.


def _decisions_count(decision: str) -> float:
    from prometheus_client import REGISTRY

    return (
        REGISTRY.get_sample_value(
            "mcpip_authorize_decisions_total", {"decision": decision}
        )
        or 0.0
    )


def test_mcp_edge_increments_allow_decisions_counter(
    client: TestClient, idp: _DemoIdP
) -> None:
    """An ALLOW over the MCP-native edge increments the SAME counter as /v1/authorize."""
    before = _decisions_count("allow")
    resp = client.post(
        "/v1/mcp",
        json={
            "jsonrpc": "2.0",
            "id": uuid.uuid4().hex,
            "method": "tools/call",
            "params": {"name": _AUTO_ALIAS, "arguments": {"period": "2026-Q2"}},
        },
        headers={"Authorization": f"Bearer {idp.mint()}"},
    )
    assert resp.status_code == 200, resp.text
    assert _decisions_count("allow") == before + 1.0


def test_rest_and_mcp_count_an_allow_identically(
    client: TestClient, idp: _DemoIdP
) -> None:
    """Parity: one REST allow and one MCP allow each move the counter by exactly one."""
    start = _decisions_count("allow")
    rest = _post(client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=idp.mint())
    assert rest.status_code == 200, rest.text
    assert _decisions_count("allow") == start + 1.0
    mcp = client.post(
        "/v1/mcp",
        json={
            "jsonrpc": "2.0",
            "id": uuid.uuid4().hex,
            "method": "tools/call",
            "params": {"name": _AUTO_ALIAS, "arguments": {"period": "Q1"}},
        },
        headers={"Authorization": f"Bearer {idp.mint()}"},
    )
    assert mcp.status_code == 200, mcp.text
    assert _decisions_count("allow") == start + 2.0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
