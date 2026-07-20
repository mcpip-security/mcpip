"""
MCPIP V2 — Cross red-team: MULTIPLE simultaneous attacker personas, ONE gateway.

    ◐  "Every attacker fails closed + opaque + is WORM-logged with the real reason —
        and a legitimate agent interleaved among them ALWAYS still succeeds."

This is the flagship adversarial file. Where ``test_authorize_api.py`` proves each
individual boundary and ``test_redteam_fixes.py`` pins each fixed finding, THIS file
crosses them: distinct attacker personas — each attacking a DIFFERENT boundary
(cross-tenant, compartment escalation, PIN replay/theft, JWT forgery, role
privilege-escalation, identity/capability injection, alias enumeration, canary
tripwire, revocation) — are run interleaved / concurrently against a SINGLE live
gateway, and every crossing asserts the same four guarantees at once:

  1. every attacker gets the OPAQUE ``{error, correlation_id}`` envelope (never the reason);
  2. each concrete reason lands in the durable WORM buffer (looked up by correlation_id);
  3. a legitimate control agent interleaved throughout ALWAYS still gets its ALLOWs
     (no collateral deny, no cross-contamination);
  4. no attacker's action mutates another principal's state (quarantine/revoke/lock
     stay scoped to the offender).

Driven through Starlette's ``TestClient`` so the full pipeline (bridge → obfuscator →
auth → audit) and the FastAPI lifespan (Redis rebind + epoch daemon) run exactly as
production would. Every test mints UNIQUE ``uuid4`` agent ids so no test assumes a clean
db and no two tests can cross-contaminate; the WORM reason is read back per-correlation
from the durable buffer to prove the opaque-vs-logged split under crossfire.
"""

from __future__ import annotations

import os
import sys

# Make the repo root importable when run directly (pytest already adds it via rootdir).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# --- Namespaced sandbox environment MUST be set before importing app.main, whose
#     composition root reads the (lru_cached) settings once, at import. Per the cross
#     brief, use the /8 fallback db via setdefault so a full-suite run that already froze
#     another db (e.g. the API suite's /5) is honored and never fought. ----------------
os.environ.setdefault("MCPIP_REDIS_URL", "redis://localhost:63790/8")
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_cross_worm.jsonl"),
)
# The db app.main is ACTUALLY bound to (whatever won the setdefault race), so every WORM
# read below targets the same buffer the running app writes to.
_REDIS_URL = os.environ["MCPIP_REDIS_URL"]

import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Iterator, Optional

import jwt
import pytest
import redis as redis_sync
from fastapi.testclient import TestClient
from httpx import Response

from core.security import AGENT_FACING_DENY_MESSAGE
from interfaces import (
    CAP_COMPARTMENT_GRANT,
    CAP_DIRECTORY_ADMIN,
    grant_capability_for,
)
from obfuscator.tenant_catalog import (
    AEGIS,
    CANARY_TARGET,
    FALCON,
    MCPIP_ENGINEERING,
    MCPIP_FINANCE,
    SENTINEL,
)

from app.main import _components, app
from main import _DemoIdP, _forge_none_token, _tamper_signature

# --- Seeded tenants / compartments / aliases the personas attack (config, in-memory). --
_ACME = "tenant-acme"
_GLOBEX = "tenant-globex"
_AEGIS = "aegis-dynamics"
_MCPIP = "mcpip-inc"

_AUTO_ALIAS = "skill_spend_summary"          # acme AUTO, cloud_rest → rest.ledger.spend.summary
_AUTO_ALIAS2 = "skill_customer_lookup"       # acme AUTO
_PIN_ALIAS = "skill_payroll_run"             # acme PIN_REQUIRED, legacy_mainframe
_GRANT_ALIAS = "skill_compartment_grant"     # aegis governance alias (CAP_COMPARTMENT_GRANT)
_FALCON_ALIAS = "skill_falcon_telemetry"     # aegis FALCON, AUTO, require_sender_constraint
_AEGIS_ALIAS = "skill_aegis_radar_tune"      # aegis AEGIS, PIN
_SENTINEL_ALIAS = "skill_sentinel_recon_feed"  # aegis SENTINEL, AUTO, require_sender_constraint
_STATUS_ALIAS = "skill_status_probe"         # aegis + globex tenant-wide AUTO
_ENG_ALIAS = "skill_engineering_roadmap"     # mcpip-inc ENGINEERING AUTO
_FIN_ALIAS = "skill_financial_wage_sheet"    # mcpip-inc FINANCE AUTO
_AWS_ALIAS = "skill_aws_s3_read"             # mcpip-inc ENGINEERING cloud_iam AUTO
_COMPANY_ALIAS = "skill_company_overview"    # mcpip-inc tenant-wide AUTO
_CANARY_ALIAS = "skill_export_all_credentials"  # deception tripwire (AUTO, canary=True)

_REAL_TARGET = "rest.ledger.spend.summary"   # the real dotted target skill_spend_summary hides.
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
    """Module-scoped TestClient. Flush the dedicated db BEFORE the lifespan so the WORM
    buffer starts clean (cloud envs are re-hydrated by the lifespan startup) — but every
    test is still self-contained via unique uuid4 ids, never a clean-db assumption."""
    reset: Any = redis_sync.Redis.from_url(_REDIS_URL, decode_responses=True)
    reset.flushdb()
    reset.close()
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Helpers (self-contained — mirror the API-suite harness).
# ---------------------------------------------------------------------------


def _aid(prefix: str) -> str:
    """A globally-unique agent id, so no test can ever collide with another's state."""
    return f"{prefix}-{uuid.uuid4().hex}"


def _openai_call(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Wrap arguments in an OpenAI ``tool_call`` envelope (the bridge deep-validates)."""
    return {
        "id": "call_cross",
        "type": "function",
        "function": {"name": alias, "arguments": json.dumps(arguments)},
    }


def _post(
    client: TestClient,
    *,
    alias: str,
    arguments: dict[str, Any],
    token: Optional[str] = None,
    pin: Optional[str] = None,
    challenge_id: Optional[str] = None,
) -> Response:
    """POST ``/v1/authorize`` with an OpenAI envelope; identity via the body ``jwt``."""
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
    return client.post("/v1/authorize", json=body)


def _json(resp: Response) -> dict[str, Any]:
    data: Any = resp.json()
    assert isinstance(data, dict)
    return data


def _corr(resp: Response) -> str:
    """The opaque correlation id echoed on every response (== the WORM ctx handle)."""
    cid = resp.headers.get(_CORR_HEADER)
    assert cid is not None, "every response carries the correlation header"
    return cid


def _assert_opaque_denial(resp: Response) -> None:
    """A policy deny is EXACTLY ``{error, correlation_id}`` + an echoed header id, 403."""
    assert resp.status_code == 403, resp.text
    data = _json(resp)
    assert set(data.keys()) == {"error", "correlation_id"}, data
    assert data["error"] == AGENT_FACING_DENY_MESSAGE
    assert resp.headers.get(_CORR_HEADER) == data["correlation_id"]


def _worm_events(count: int = 3000) -> list[dict[str, Any]]:
    """Every buffered WORM event record (newest first), parsed from the durable stream."""
    reader: Any = redis_sync.Redis.from_url(_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=count)
    finally:
        reader.close()
    out: list[dict[str, Any]] = []
    for _sid, fields in entries:
        raw = fields.get("record")
        if not raw:
            continue
        try:
            record = json.loads(raw)
        except (ValueError, TypeError):
            continue
        event = record.get("event")
        if isinstance(event, dict):
            out.append(event)
    return out


def _worm_reason_for(correlation_id: str) -> Optional[str]:
    """The concrete ``deny_reason`` the WORM buffer recorded for this correlation id."""
    for event in _worm_events():
        if event.get("correlation_id") == correlation_id:
            reason = event.get("deny_reason")
            return reason if isinstance(reason, str) else None
    return None


def _worm_decision_for(correlation_id: str) -> Optional[str]:
    """The terminal ``decision`` (allow/deny) the WORM buffer recorded for this id."""
    for event in _worm_events():
        if event.get("correlation_id") == correlation_id:
            decision = event.get("decision")
            return decision if isinstance(decision, str) else None
    return None


def _last_deny_reason() -> Optional[str]:
    """The most-recently buffered event's concrete deny reason (tail read)."""
    events = _worm_events(count=1)
    if not events:
        return None
    reason = events[0].get("deny_reason")
    return reason if isinstance(reason, str) else None


def _sign(idp: _DemoIdP, claims: dict[str, Any]) -> str:
    """Sign arbitrary claims with the IdP's real key (a validly-SIGNED token)."""
    return jwt.encode(claims, idp._private_pem, algorithm="EdDSA")  # type: ignore[attr-defined]


def _base_claims(idp: _DemoIdP, *, tenant_id: str, agent_id: str, role: str = "ops") -> dict[str, Any]:
    """A full, currently-valid claim set (mutate a copy to craft each JWT persona)."""
    import time

    now = int(time.time())
    return {
        "iss": _DemoIdP.ISSUER,
        "aud": _DemoIdP.AUDIENCE,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "role": role,
        "exp": now + 300,
        "iat": now,
        "nbf": now,
        "jti": uuid.uuid4().hex,
    }


def _stage_and_otp(
    client: TestClient, token: str, alias: str, arguments: dict[str, Any]
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


def _admin(idp: _DemoIdP, tenant_id: str = _ACME) -> str:
    """Mint a JWT holding CAP_DIRECTORY_ADMIN in ``tenant_id`` (the operator kill-switch)."""
    return idp.mint(
        tenant_id=tenant_id, agent_id=_aid("admin"), capabilities=[CAP_DIRECTORY_ADMIN]
    )


def _legit_allows(client: TestClient, idp: _DemoIdP, *, agent_id: str, n: int) -> list[str]:
    """Fire ``n`` benign AUTO calls for one control agent; assert every one ALLOWs (200)
    and return their correlation ids so a caller can prove no collateral deny in WORM."""
    corrs: list[str] = []
    for i in range(n):
        resp = _post(
            client,
            alias=_AUTO_ALIAS,
            arguments={"period": f"legit-{i}-{uuid.uuid4().hex[:6]}"},
            token=idp.mint(tenant_id=_ACME, agent_id=agent_id),
        )
        assert resp.status_code == 200, resp.text
        assert _json(resp)["decision"] == "allow"
        corrs.append(_corr(resp))
    return corrs


# ===========================================================================
# PART A — individual attacker personas, each hitting a DISTINCT boundary.
# Every one asserts the two-part guarantee: opaque to the caller, concrete in WORM.
# ===========================================================================


# --- Persona: cross-tenant reach (tenant-B agent touching a tenant-A alias). ---------


def test_a01_cross_tenant_globex_to_acme_pin_alias(client: TestClient, idp: _DemoIdP) -> None:
    """A tenant-globex agent reaching an acme-only PIN alias → opaque 403; WORM cross_tenant."""
    tok = idp.mint(tenant_id=_GLOBEX, agent_id=_aid("globex"))
    resp = _post(client, alias=_PIN_ALIAS, arguments={"run_id": "x"}, token=tok)
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "cross_tenant"


def test_a02_cross_tenant_globex_to_acme_auto_alias(client: TestClient, idp: _DemoIdP) -> None:
    """A tenant-globex agent reaching an acme-only AUTO alias → opaque 403; WORM cross_tenant."""
    tok = idp.mint(tenant_id=_GLOBEX, agent_id=_aid("globex"))
    resp = _post(client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=tok)
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "cross_tenant"


def test_a03_cross_tenant_acme_to_aegis_grant_alias(client: TestClient, idp: _DemoIdP) -> None:
    """An acme agent reaching an aegis governance alias → opaque 403; WORM cross_tenant."""
    tok = idp.mint(tenant_id=_ACME, agent_id=_aid("acme"))
    resp = _post(
        client, alias=_GRANT_ALIAS, arguments={"grantee": "g", "compartment": FALCON}, token=tok
    )
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "cross_tenant"


def test_a04_cross_tenant_denial_leaks_no_owner(client: TestClient, idp: _DemoIdP) -> None:
    """A cross-tenant deny NEVER reveals who owns the alias — body is opaque, no topology."""
    tok = idp.mint(tenant_id=_GLOBEX, agent_id=_aid("globex"))
    resp = _post(client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=tok)
    _assert_opaque_denial(resp)
    assert _ACME not in resp.text and _REAL_TARGET not in resp.text and "ledger" not in resp.text


# --- Persona: compartment escalation (team-X agent reaching team-Y's alias). ----------


def test_a05_compartment_aegis_agent_to_falcon(client: TestClient, idp: _DemoIdP) -> None:
    """An AEGIS-team agent reaching a FALCON alias → opaque 403; WORM compartment_denied."""
    tok = idp.mint(tenant_id=_AEGIS, agent_id=_aid("aegis"), compartment=AEGIS)
    resp = _post(client, alias=_FALCON_ALIAS, arguments={}, token=tok)
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "compartment_denied"


def test_a06_compartment_falcon_agent_to_aegis(client: TestClient, idp: _DemoIdP) -> None:
    """A FALCON-team agent reaching an AEGIS alias → opaque 403; WORM compartment_denied."""
    tok = idp.mint(tenant_id=_AEGIS, agent_id=_aid("falcon"), compartment=FALCON)
    resp = _post(client, alias=_AEGIS_ALIAS, arguments={}, token=tok)
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "compartment_denied"


def test_a07_compartment_uncompartmented_agent_to_falcon(client: TestClient, idp: _DemoIdP) -> None:
    """An un-compartmented aegis agent reaching a FALCON alias → opaque compartment_denied."""
    tok = idp.mint(tenant_id=_AEGIS, agent_id=_aid("aegis-none"))
    resp = _post(client, alias=_FALCON_ALIAS, arguments={}, token=tok)
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "compartment_denied"


def test_a08_compartment_finance_to_engineering(client: TestClient, idp: _DemoIdP) -> None:
    """An mcpip-inc FINANCE agent reaching an ENGINEERING alias → opaque compartment_denied."""
    tok = idp.mint(tenant_id=_MCPIP, agent_id=_aid("fin"), compartment=MCPIP_FINANCE)
    resp = _post(client, alias=_ENG_ALIAS, arguments={}, token=tok)
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "compartment_denied"


def test_a09_compartment_engineering_to_finance(client: TestClient, idp: _DemoIdP) -> None:
    """An mcpip-inc ENGINEERING agent reaching a FINANCE wage sheet → opaque compartment_denied."""
    tok = idp.mint(tenant_id=_MCPIP, agent_id=_aid("eng"), compartment=MCPIP_ENGINEERING)
    resp = _post(client, alias=_FIN_ALIAS, arguments={}, token=tok)
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "compartment_denied"


def test_a10_compartment_cloud_iam_cross_vends_nothing(client: TestClient, idp: _DemoIdP) -> None:
    """A FINANCE agent cannot vend the ENGINEERING-scoped cloud credential — opaque
    compartment_denied at the gate, and NO credential material is ever returned."""
    tok = idp.mint(tenant_id=_MCPIP, agent_id=_aid("fin-cloud"), compartment=MCPIP_FINANCE)
    resp = _post(client, alias=_AWS_ALIAS, arguments={}, token=tok)
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "compartment_denied"
    assert "vended_credential" not in resp.text and "session_token" not in resp.text


# --- Persona: PIN replay / theft / drift. --------------------------------------------


def test_a11_pin_replay_spent_challenge(client: TestClient, idp: _DemoIdP) -> None:
    """Replaying an already-SPENT challenge → opaque 403; WORM records pin_not_found."""
    tok = idp.mint(tenant_id=_ACME, agent_id=_aid("payer"))
    args = {"run_id": "PR-a11", "cycle": "monthly"}
    challenge_id, otp = _stage_and_otp(client, tok, _PIN_ALIAS, args)
    first = _post(client, alias=_PIN_ALIAS, arguments=args, token=tok, pin=otp, challenge_id=challenge_id)
    assert first.status_code == 200, first.text
    replay = _post(client, alias=_PIN_ALIAS, arguments=args, token=tok, pin=otp, challenge_id=challenge_id)
    _assert_opaque_denial(replay)
    assert _worm_reason_for(_corr(replay)) == "pin_not_found"


def test_a12_pin_payload_drift_lock_survives(client: TestClient, idp: _DemoIdP) -> None:
    """One drifted byte at completion → payload_mismatch; the lock is NOT spent and a
    correct retry still succeeds (a payload mismatch must not consume an attempt-lock)."""
    tok = idp.mint(tenant_id=_ACME, agent_id=_aid("payer"))
    args = {"run_id": "PR-a12", "cycle": "monthly"}
    challenge_id, otp = _stage_and_otp(client, tok, _PIN_ALIAS, args)
    drifted = {"run_id": "PR-a12", "cycle": "monthlyX"}
    bad = _post(client, alias=_PIN_ALIAS, arguments=drifted, token=tok, pin=otp, challenge_id=challenge_id)
    _assert_opaque_denial(bad)
    assert _worm_reason_for(_corr(bad)) == "payload_mismatch"
    ok = _post(client, alias=_PIN_ALIAS, arguments=args, token=tok, pin=otp, challenge_id=challenge_id)
    assert ok.status_code == 200, ok.text


def test_a13_pin_stolen_reused_by_different_agent(client: TestClient, idp: _DemoIdP) -> None:
    """A stolen challenge+OTP replayed by a DIFFERENT agent of the same tenant →
    payload_mismatch (the lock hash binds the agent_id), and the legitimate OWNER can
    still spend its own lock afterwards — the theft mutated nothing."""
    owner_id = _aid("owner")
    owner = idp.mint(tenant_id=_ACME, agent_id=owner_id)
    args = {"run_id": "PR-a13", "cycle": "weekly"}
    challenge_id, otp = _stage_and_otp(client, owner, _PIN_ALIAS, args)

    thief = idp.mint(tenant_id=_ACME, agent_id=_aid("thief"))  # same tenant, other agent.
    stolen = _post(client, alias=_PIN_ALIAS, arguments=args, token=thief, pin=otp, challenge_id=challenge_id)
    _assert_opaque_denial(stolen)
    assert _worm_reason_for(_corr(stolen)) == "payload_mismatch"

    # The owner's lock was never consumed by the thief — the rightful agent still spends it.
    done = _post(client, alias=_PIN_ALIAS, arguments=args, token=owner, pin=otp, challenge_id=challenge_id)
    assert done.status_code == 200, done.text
    assert _json(done)["decision"] == "allow"


def test_a14_pin_replay_across_different_payload(client: TestClient, idp: _DemoIdP) -> None:
    """A challenge staged for one payload, spent against a DIFFERENT payload →
    payload_mismatch; the correct payload still completes (the lock survives the swap)."""
    tok = idp.mint(tenant_id=_ACME, agent_id=_aid("payer"))
    args = {"run_id": "PR-a14", "cycle": "monthly"}
    challenge_id, otp = _stage_and_otp(client, tok, _PIN_ALIAS, args)
    other = {"run_id": "PR-a14-EVIL", "cycle": "monthly"}
    swapped = _post(client, alias=_PIN_ALIAS, arguments=other, token=tok, pin=otp, challenge_id=challenge_id)
    _assert_opaque_denial(swapped)
    assert _worm_reason_for(_corr(swapped)) == "payload_mismatch"
    ok = _post(client, alias=_PIN_ALIAS, arguments=args, token=tok, pin=otp, challenge_id=challenge_id)
    assert ok.status_code == 200, ok.text


def test_a15_pin_wrong_otp_then_correct(client: TestClient, idp: _DemoIdP) -> None:
    """A wrong OTP → pin_mismatch (opaque); the correct OTP still completes afterwards."""
    tok = idp.mint(tenant_id=_ACME, agent_id=_aid("payer"))
    args = {"run_id": "PR-a15", "cycle": "annual"}
    challenge_id, otp = _stage_and_otp(client, tok, _PIN_ALIAS, args)
    wrong = "000000" if otp != "000000" else "111111"
    bad = _post(client, alias=_PIN_ALIAS, arguments=args, token=tok, pin=wrong, challenge_id=challenge_id)
    _assert_opaque_denial(bad)
    assert _worm_reason_for(_corr(bad)) == "pin_mismatch"
    ok = _post(client, alias=_PIN_ALIAS, arguments=args, token=tok, pin=otp, challenge_id=challenge_id)
    assert ok.status_code == 200, ok.text


# --- Persona: JWT forgery / expiry / wrong-issuer / wrong-audience / claim drops. -----


def test_a16_forged_jwt_signature(client: TestClient, idp: _DemoIdP) -> None:
    """A signature-tampered JWT → opaque 403; WORM records jwt_invalid."""
    resp = _post(
        client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=_tamper_signature(idp.mint())
    )
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "jwt_invalid"


def test_a17_alg_none_token(client: TestClient, idp: _DemoIdP) -> None:
    """An ``alg=none`` unsigned token → opaque 403; rejected at the header allow-list."""
    resp = _post(client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=_forge_none_token())
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "jwt_invalid"


def test_a18_expired_jwt(client: TestClient, idp: _DemoIdP) -> None:
    """A validly-signed but EXPIRED JWT → opaque 403; WORM records jwt_invalid."""
    claims = _base_claims(idp, tenant_id=_ACME, agent_id=_aid("expired"))
    claims["exp"] = claims["iat"] - 10
    claims["iat"] = claims["nbf"] = claims["exp"] - 120
    resp = _post(client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=_sign(idp, claims))
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "jwt_invalid"


def test_a19_wrong_issuer(client: TestClient, idp: _DemoIdP) -> None:
    """A validly-signed token asserting the WRONG issuer → opaque 403; WORM jwt_invalid."""
    claims = _base_claims(idp, tenant_id=_ACME, agent_id=_aid("iss"))
    claims["iss"] = "evil-idp"
    resp = _post(client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=_sign(idp, claims))
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "jwt_invalid"


def test_a20_wrong_audience(client: TestClient, idp: _DemoIdP) -> None:
    """A validly-signed token with the WRONG audience → opaque 403; WORM jwt_invalid."""
    claims = _base_claims(idp, tenant_id=_ACME, agent_id=_aid("aud"))
    claims["aud"] = "some-other-gateway"
    resp = _post(client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=_sign(idp, claims))
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "jwt_invalid"


def test_a21_missing_role_claim(client: TestClient, idp: _DemoIdP) -> None:
    """Dropping the required ``role`` claim → opaque 403; WORM records jwt_claims_missing."""
    resp = _post(
        client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=idp.mint(drop_claim="role")
    )
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "jwt_claims_missing"


def test_a22_missing_tenant_claim(client: TestClient, idp: _DemoIdP) -> None:
    """Dropping the required ``tenant_id`` claim → opaque 403; WORM jwt_claims_missing."""
    resp = _post(
        client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=idp.mint(drop_claim="tenant_id")
    )
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "jwt_claims_missing"


def test_a23_malformed_capabilities_claim(client: TestClient, idp: _DemoIdP) -> None:
    """A non-UUID ``capabilities`` claim → opaque 403; WORM records jwt_invalid."""
    resp = _post(
        client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=idp.mint(capabilities=["not-a-uuid"])
    )
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "jwt_invalid"


def test_a24_oversized_capabilities_claim(client: TestClient, idp: _DemoIdP) -> None:
    """An oversized ``capabilities`` list → opaque 403; WORM records jwt_invalid."""
    huge = [uuid.uuid4().hex for _ in range(33)]
    resp = _post(client, alias=_AUTO_ALIAS, arguments={"period": "Q1"}, token=idp.mint(capabilities=huge))
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "jwt_invalid"


# --- Persona: role-claim privilege escalation (the role claim authorizes NOTHING). ----


def test_a25_role_admin_cannot_issue_grant(client: TestClient, idp: _DemoIdP) -> None:
    """A token with role='admin' but NO capability UUID cannot issue a compartment grant
    → opaque 403; WORM capability_denied (the role string is inert for authorization)."""
    tok = idp.mint(tenant_id=_AEGIS, agent_id=_aid("role-admin"), role="admin")
    resp = _post(
        client, alias=_GRANT_ALIAS, arguments={"grantee": "g", "compartment": FALCON}, token=tok
    )
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "capability_denied"


def test_a26_role_root_cannot_reach_admin_endpoint(client: TestClient, idp: _DemoIdP) -> None:
    """A token with role='root' but no CAP_DIRECTORY_ADMIN is opaque-denied the admin
    control-plane — the role LABEL never confers the operator kill-switch."""
    tok = idp.mint(tenant_id=_ACME, agent_id=_aid("role-root"), role="root")
    resp = client.post(
        f"/v1/admin/principals/{_aid('victim')}/revoke",
        json={"reason": "x"},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert resp.status_code == 403


def test_a27_role_superuser_no_compartment_bypass(client: TestClient, idp: _DemoIdP) -> None:
    """A token with role='superuser' still cannot cross a compartment it is not scoped to
    → opaque 403; WORM compartment_denied (authorization gates on the JWT compartment)."""
    tok = idp.mint(tenant_id=_AEGIS, agent_id=_aid("role-super"), role="superuser", compartment=AEGIS)
    resp = _post(client, alias=_FALCON_ALIAS, arguments={}, token=tok)
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "compartment_denied"


# --- Persona: identity / capability injection in the tool-call payload (hard deny). ---


@pytest.mark.parametrize("key", ["tenant_id", "agent_id", "role", "sub", "principal", "actor"])
def test_a28_identity_injection_variants(client: TestClient, idp: _DemoIdP, key: str) -> None:
    """An identity-shaped argument key is a HARD deny (never a silent strip) → opaque 403;
    WORM records identity_injection, regardless of which identity-shaped key is smuggled."""
    resp = _post(client, alias=_AUTO_ALIAS, arguments={key: "evil"}, token=idp.mint())
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "identity_injection"


@pytest.mark.parametrize("key", ["capabilities", "capability", "entitlement", "grants"])
def test_a29_capability_injection_variants(client: TestClient, idp: _DemoIdP, key: str) -> None:
    """A smuggled capability/entitlement-shaped argument key is a HARD deny → opaque 403;
    WORM identity_injection (authorization is JWT-only; in-band claims are never trusted)."""
    resp = _post(client, alias=_AUTO_ALIAS, arguments={key: [CAP_COMPARTMENT_GRANT]}, token=idp.mint())
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "identity_injection"


# --- Persona: alias enumeration / oversize probing. ----------------------------------


def test_a30_unknown_alias_enumeration(client: TestClient, idp: _DemoIdP) -> None:
    """Every guessed/unregistered alias fails closed as unknown_alias — enumeration
    reveals nothing (opaque body, no existence oracle in the response)."""
    for _ in range(4):
        alias = f"skill_guess_{uuid.uuid4().hex}"
        resp = _post(client, alias=alias, arguments={}, token=idp.mint())
        _assert_opaque_denial(resp)
        assert _worm_reason_for(_corr(resp)) == "unknown_alias"
        assert alias not in resp.text or set(_json(resp)) == {"error", "correlation_id"}


def test_a31_oversize_arguments(client: TestClient, idp: _DemoIdP) -> None:
    """An argument object with too many keys → opaque 403; WORM records size_exceeded."""
    oversize = {f"key_{i}": "x" for i in range(200)}
    resp = _post(client, alias=_AUTO_ALIAS, arguments=oversize, token=idp.mint())
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "size_exceeded"


# --- Persona: sender-constraint downgrade (bare bearer at a PoP-demanding resource). --


def test_a32_bare_bearer_to_sender_constrained_falcon(client: TestClient, idp: _DemoIdP) -> None:
    """A FALCON-native BARE bearer reaching a require_sender_constraint alias passes the
    compartment gate but is denied for lacking a key-proof → opaque sender_constraint_required."""
    tok = idp.mint(tenant_id=_AEGIS, agent_id=_aid("falcon-bearer"), compartment=FALCON)
    resp = _post(client, alias=_FALCON_ALIAS, arguments={}, token=tok)
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "sender_constraint_required"


def test_a33_bare_bearer_to_sender_constrained_sentinel(client: TestClient, idp: _DemoIdP) -> None:
    """A SENTINEL-native bare bearer at a require_sender_constraint alias → opaque
    sender_constraint_required (a distinct reason from JWT_INVALID / COMPARTMENT_DENIED)."""
    tok = idp.mint(tenant_id=_AEGIS, agent_id=_aid("sentinel-bearer"), compartment=SENTINEL)
    resp = _post(client, alias=_SENTINEL_ALIAS, arguments={}, token=tok)
    _assert_opaque_denial(resp)
    assert _worm_reason_for(_corr(resp)) == "sender_constraint_required"


# --- Persona: de-obfuscation (the real target must never appear to the caller). -------


def test_a34_allow_response_never_reveals_target(client: TestClient, idp: _DemoIdP) -> None:
    """An ALLOW surfaces only a coarse transport CLASS — never the dotted real topology
    the Obfuscator hides (invariant #4)."""
    resp = _post(client, alias=_AUTO_ALIAS, arguments={"period": "Q2"}, token=idp.mint())
    assert resp.status_code == 200, resp.text
    data = _json(resp)
    assert data["executed_target_class"] == "cloud_rest"
    assert "." not in data["executed_target_class"]
    assert _REAL_TARGET not in resp.text and "ledger" not in resp.text
    assert CANARY_TARGET not in resp.text


def test_a35_deny_response_reveals_no_topology(client: TestClient, idp: _DemoIdP) -> None:
    """A de-obfuscation probe (unknown alias) returns EXACTLY the opaque envelope — no
    target, no transport, no reason ever crosses the boundary."""
    resp = _post(client, alias=f"skill_probe_{uuid.uuid4().hex}", arguments={}, token=idp.mint())
    _assert_opaque_denial(resp)
    body = _json(resp)
    assert "target" not in body and "transport" not in body and "deny_reason" not in body


# --- Persona: canary tripwire + auto-quarantine (blast radius is one agent). ----------


def test_a36_canary_trip_quarantines_only_self(client: TestClient, idp: _DemoIdP) -> None:
    """Selecting a canary alias → canary_tripped + the agent is frozen so its NEXT valid
    request denies agent_quarantined — while a SIBLING agent of the same tenant is
    entirely unaffected (the quarantine is scoped to the offender)."""
    attacker_id = _aid("canary")
    attacker = idp.mint(tenant_id=_ACME, agent_id=attacker_id)
    tripped = _post(client, alias=_CANARY_ALIAS, arguments={"scope": "all"}, token=attacker)
    _assert_opaque_denial(tripped)
    assert _worm_reason_for(_corr(tripped)) == "canary_tripped"

    frozen = _post(
        client, alias=_AUTO_ALIAS, arguments={"period": "post"},
        token=idp.mint(tenant_id=_ACME, agent_id=attacker_id),
    )
    _assert_opaque_denial(frozen)
    assert _worm_reason_for(_corr(frozen)) == "agent_quarantined"

    sibling = _post(client, alias=_AUTO_ALIAS, arguments={"period": "sib"}, token=idp.mint(tenant_id=_ACME, agent_id=_aid("sibling")))
    assert sibling.status_code == 200, sibling.text


# --- Persona: operator revocation kill-switch (a revoked principal races a valid one). -


def test_a37_revoked_principal_denied_sibling_unaffected(client: TestClient, idp: _DemoIdP) -> None:
    """An admin-revoked principal is denied principal_revoked on its next request (opaque),
    a never-revoked sibling keeps succeeding, and reactivate restores the victim."""
    admin = _admin(idp, _ACME)
    victim_id = _aid("victim")

    pre = _post(client, alias=_AUTO_ALIAS, arguments={"period": "pre"}, token=idp.mint(tenant_id=_ACME, agent_id=victim_id))
    assert pre.status_code == 200, pre.text

    rv = client.post(
        f"/v1/admin/principals/{victim_id}/revoke",
        json={"reason": "offboarded"},
        headers={"Authorization": f"Bearer {admin}"},
    )
    assert rv.status_code == 200, rv.text

    blocked = _post(client, alias=_AUTO_ALIAS, arguments={"period": "post"}, token=idp.mint(tenant_id=_ACME, agent_id=victim_id))
    _assert_opaque_denial(blocked)
    assert _worm_reason_for(_corr(blocked)) == "principal_revoked"

    # A never-revoked sibling is untouched by the revocation of the victim.
    sib = _post(client, alias=_AUTO_ALIAS, arguments={"period": "sib"}, token=idp.mint(tenant_id=_ACME, agent_id=_aid("sib")))
    assert sib.status_code == 200, sib.text

    ra = client.post(
        f"/v1/admin/principals/{victim_id}/reactivate",
        headers={"Authorization": f"Bearer {admin}"},
    )
    assert ra.status_code == 200, ra.text
    restored = _post(client, alias=_AUTO_ALIAS, arguments={"period": "after"}, token=idp.mint(tenant_id=_ACME, agent_id=victim_id))
    assert restored.status_code == 200, restored.text


def test_a38_cross_compartment_grant_mole_gains_nothing(client: TestClient, idp: _DemoIdP) -> None:
    """A FALCON-scoped grant holder trying to grant a DIFFERENT compartment (AEGIS) is
    refused capability_denied at the mandate gate, and the intended mole gains no AEGIS
    access (a classified AEGIS alias stays compartment_denied)."""
    mole_id = _aid("mole")
    officer = idp.mint(
        tenant_id=_AEGIS,
        agent_id=_aid("officer"),
        capabilities=[CAP_COMPARTMENT_GRANT, grant_capability_for(FALCON)],
    )
    cross = _post(
        client, alias=_GRANT_ALIAS,
        arguments={"grantee": mole_id, "compartment": AEGIS, "ttl_seconds": 3600},
        token=officer,
    )
    _assert_opaque_denial(cross)
    assert _worm_reason_for(_corr(cross)) == "capability_denied"

    denied = _post(client, alias=_AEGIS_ALIAS, arguments={}, token=idp.mint(tenant_id=_AEGIS, agent_id=mole_id))
    _assert_opaque_denial(denied)
    assert _worm_reason_for(_corr(denied)) == "compartment_denied"


# ===========================================================================
# PART B — CROSSING: N personas interleaved / concurrent against ONE gateway,
# a legit control agent threaded throughout, asserting no cross-contamination.
# ===========================================================================


def test_x01_five_personas_interleaved_with_legit_control(client: TestClient, idp: _DemoIdP) -> None:
    """Five distinct attacker personas, each interleaved between a legit control agent's
    ALLOWs. Assert: every attacker is opaque-denied with its OWN concrete WORM reason,
    and the control agent gets a 200 ALLOW at every interleaving step."""
    control = _aid("control")

    def legit() -> Response:
        r = _post(client, alias=_AUTO_ALIAS, arguments={"period": uuid.uuid4().hex[:8]}, token=idp.mint(tenant_id=_ACME, agent_id=control))
        assert r.status_code == 200, r.text
        return r

    legit()
    a1 = _post(client, alias=_AUTO_ALIAS, arguments={"period": "x"}, token=idp.mint(tenant_id=_GLOBEX, agent_id=_aid("globex")))
    legit()
    a2 = _post(client, alias=_FALCON_ALIAS, arguments={}, token=idp.mint(tenant_id=_AEGIS, agent_id=_aid("aegis"), compartment=AEGIS))
    legit()
    a3 = _post(client, alias=_AUTO_ALIAS, arguments={"tenant_id": "evil"}, token=idp.mint())
    legit()
    a4 = _post(client, alias=_AUTO_ALIAS, arguments={"period": "x"}, token=_tamper_signature(idp.mint()))
    legit()
    a5 = _post(client, alias=f"skill_{uuid.uuid4().hex}", arguments={}, token=idp.mint())
    legit()

    expected = {
        _corr(a1): "cross_tenant",
        _corr(a2): "compartment_denied",
        _corr(a3): "identity_injection",
        _corr(a4): "jwt_invalid",
        _corr(a5): "unknown_alias",
    }
    for resp in (a1, a2, a3, a4, a5):
        _assert_opaque_denial(resp)
    for corr, reason in expected.items():
        assert _worm_reason_for(corr) == reason, (corr, reason)


def test_x02_each_attacker_reason_lands_in_worm_opaque_to_caller(client: TestClient, idp: _DemoIdP) -> None:
    """A battery of six distinct-boundary attackers: each caller sees only the opaque
    envelope, yet each DISTINCT concrete reason is recoverable from the WORM buffer."""
    battery = [
        (_post(client, alias=_PIN_ALIAS, arguments={"run_id": "x"}, token=idp.mint(tenant_id=_GLOBEX, agent_id=_aid("g"))), "cross_tenant"),
        (_post(client, alias=_ENG_ALIAS, arguments={}, token=idp.mint(tenant_id=_MCPIP, agent_id=_aid("fin"), compartment=MCPIP_FINANCE)), "compartment_denied"),
        (_post(client, alias=_AUTO_ALIAS, arguments={"role": "root"}, token=idp.mint()), "identity_injection"),
        (_post(client, alias=_AUTO_ALIAS, arguments={"period": "x"}, token=_forge_none_token()), "jwt_invalid"),
        (_post(client, alias=_AUTO_ALIAS, arguments={f"k{i}": "v" for i in range(200)}, token=idp.mint()), "size_exceeded"),
        (_post(client, alias=_SENTINEL_ALIAS, arguments={}, token=idp.mint(tenant_id=_AEGIS, agent_id=_aid("s"), compartment=SENTINEL)), "sender_constraint_required"),
    ]
    for resp, reason in battery:
        _assert_opaque_denial(resp)
        assert _worm_reason_for(_corr(resp)) == reason, reason


def test_x03_concurrent_multi_attacker_legit_survives(client: TestClient, idp: _DemoIdP) -> None:
    """Fire many attacker personas AND several legit control agents CONCURRENTLY against
    one gateway. The legit agents all get 200; every attacker gets an opaque 403. A storm
    of denials on one boundary never starves a legitimate ALLOW on another."""
    legit_ids = [_aid("clegit") for _ in range(6)]

    def legit(agent_id: str) -> tuple[str, int]:
        r = _post(client, alias=_AUTO_ALIAS, arguments={"period": uuid.uuid4().hex[:8]}, token=idp.mint(tenant_id=_ACME, agent_id=agent_id))
        return ("legit", r.status_code)

    def attack_cross() -> tuple[str, int]:
        r = _post(client, alias=_AUTO_ALIAS, arguments={"period": "x"}, token=idp.mint(tenant_id=_GLOBEX, agent_id=_aid("g")))
        return ("attack", r.status_code)

    def attack_compartment() -> tuple[str, int]:
        r = _post(client, alias=_FALCON_ALIAS, arguments={}, token=idp.mint(tenant_id=_AEGIS, agent_id=_aid("a"), compartment=AEGIS))
        return ("attack", r.status_code)

    def attack_jwt() -> tuple[str, int]:
        r = _post(client, alias=_AUTO_ALIAS, arguments={"period": "x"}, token=_tamper_signature(idp.mint()))
        return ("attack", r.status_code)

    def attack_inject() -> tuple[str, int]:
        r = _post(client, alias=_AUTO_ALIAS, arguments={"agent_id": "evil"}, token=idp.mint())
        return ("attack", r.status_code)

    jobs: list[Any] = []
    for aid in legit_ids:
        jobs.append(lambda a=aid: legit(a))
    for _ in range(4):
        jobs.extend([attack_cross, attack_compartment, attack_jwt, attack_inject])

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda f: f(), jobs))

    legit_codes = [code for kind, code in results if kind == "legit"]
    attack_codes = [code for kind, code in results if kind == "attack"]
    assert legit_codes == [200] * len(legit_ids), legit_codes
    assert set(attack_codes) == {403}, attack_codes


def test_x04_canary_attacker_never_quarantines_legit_control(client: TestClient, idp: _DemoIdP) -> None:
    """One attacker trips a canary (and is quarantined) while a legit control agent runs
    interleaved throughout. The attacker's own next request denies agent_quarantined; the
    control agent's ALLOWs before AND after are entirely unaffected."""
    control = _aid("control")
    attacker_id = _aid("canary")

    pre = _legit_allows(client, idp, agent_id=control, n=2)

    trip = _post(client, alias=_CANARY_ALIAS, arguments={"scope": "all"}, token=idp.mint(tenant_id=_ACME, agent_id=attacker_id))
    _assert_opaque_denial(trip)
    assert _worm_reason_for(_corr(trip)) == "canary_tripped"

    mid = _legit_allows(client, idp, agent_id=control, n=2)

    frozen = _post(client, alias=_AUTO_ALIAS, arguments={"period": "z"}, token=idp.mint(tenant_id=_ACME, agent_id=attacker_id))
    _assert_opaque_denial(frozen)
    assert _worm_reason_for(_corr(frozen)) == "agent_quarantined"

    post = _legit_allows(client, idp, agent_id=control, n=2)

    # Every control correlation recorded an ALLOW — zero collateral denies.
    for corr in (*pre, *mid, *post):
        assert _worm_decision_for(corr) == "allow", corr


def test_x05_revoke_one_attacker_does_not_touch_the_others(client: TestClient, idp: _DemoIdP) -> None:
    """Revoking attacker A blocks ONLY A (principal_revoked). A second attacker B keeps
    failing with its OWN boundary reason (cross_tenant), and a legit control still ALLOWs
    — a kill-switch on one principal never mutates another's decision."""
    admin = _admin(idp, _ACME)
    a_id = _aid("attackerA")
    control = _aid("control")

    # A starts out as an ordinary (benign) acme agent — allowed.
    pre = _post(client, alias=_AUTO_ALIAS, arguments={"period": "pre"}, token=idp.mint(tenant_id=_ACME, agent_id=a_id))
    assert pre.status_code == 200, pre.text

    client.post(f"/v1/admin/principals/{a_id}/revoke", json={"reason": "x"}, headers={"Authorization": f"Bearer {admin}"})

    a_blocked = _post(client, alias=_AUTO_ALIAS, arguments={"period": "post"}, token=idp.mint(tenant_id=_ACME, agent_id=a_id))
    b_cross = _post(client, alias=_AUTO_ALIAS, arguments={"period": "x"}, token=idp.mint(tenant_id=_GLOBEX, agent_id=_aid("attackerB")))
    legit = _post(client, alias=_AUTO_ALIAS, arguments={"period": "c"}, token=idp.mint(tenant_id=_ACME, agent_id=control))

    _assert_opaque_denial(a_blocked)
    _assert_opaque_denial(b_cross)
    assert legit.status_code == 200, legit.text
    assert _worm_reason_for(_corr(a_blocked)) == "principal_revoked"
    assert _worm_reason_for(_corr(b_cross)) == "cross_tenant"

    client.post(f"/v1/admin/principals/{a_id}/reactivate", headers={"Authorization": f"Bearer {admin}"})


def test_x06_pin_theft_crossfire_owner_still_wins(client: TestClient, idp: _DemoIdP) -> None:
    """A legit owner stages a PIN. A thief agent (different agent) tries the stolen
    challenge → payload_mismatch; the owner then tries a drifted payload → payload_mismatch;
    finally the owner completes correctly → 200. No attacker mutated the lock."""
    owner_id = _aid("owner")
    owner = idp.mint(tenant_id=_ACME, agent_id=owner_id)
    args = {"run_id": "PR-x06", "cycle": "monthly"}
    challenge_id, otp = _stage_and_otp(client, owner, _PIN_ALIAS, args)

    thief = idp.mint(tenant_id=_ACME, agent_id=_aid("thief"))
    stolen = _post(client, alias=_PIN_ALIAS, arguments=args, token=thief, pin=otp, challenge_id=challenge_id)
    _assert_opaque_denial(stolen)
    assert _worm_reason_for(_corr(stolen)) == "payload_mismatch"

    drifted = _post(client, alias=_PIN_ALIAS, arguments={**args, "cycle": "weekly"}, token=owner, pin=otp, challenge_id=challenge_id)
    _assert_opaque_denial(drifted)
    assert _worm_reason_for(_corr(drifted)) == "payload_mismatch"

    done = _post(client, alias=_PIN_ALIAS, arguments=args, token=owner, pin=otp, challenge_id=challenge_id)
    assert done.status_code == 200, done.text


def test_x07_concurrent_pin_theft_exactly_once_owner_wins(client: TestClient, idp: _DemoIdP) -> None:
    """The owner's completion and a swarm of cross-agent thieves hit the SAME challenge
    concurrently. Exactly the owner's (agent-matched) submission succeeds; every thief is
    denied. The exactly-once lock and the agent-binding hold simultaneously under load."""
    owner_id = _aid("owner")
    owner = idp.mint(tenant_id=_ACME, agent_id=owner_id)
    args = {"run_id": "PR-x07", "cycle": "annual"}
    challenge_id, otp = _stage_and_otp(client, owner, _PIN_ALIAS, args)

    def owner_consume() -> tuple[str, int]:
        r = _post(client, alias=_PIN_ALIAS, arguments=args, token=owner, pin=otp, challenge_id=challenge_id)
        return ("owner", r.status_code)

    def thief_consume() -> tuple[str, int]:
        thief = idp.mint(tenant_id=_ACME, agent_id=_aid("thief"))
        r = _post(client, alias=_PIN_ALIAS, arguments=args, token=thief, pin=otp, challenge_id=challenge_id)
        return ("thief", r.status_code)

    jobs: list[Any] = [owner_consume] + [thief_consume for _ in range(10)]
    with ThreadPoolExecutor(max_workers=11) as pool:
        results = list(pool.map(lambda f: f(), jobs))

    owner_codes = [code for kind, code in results if kind == "owner"]
    thief_codes = [code for kind, code in results if kind == "thief"]
    assert owner_codes == [200], owner_codes  # the rightful agent always wins.
    assert set(thief_codes) == {403}, thief_codes


def test_x08_two_tenants_no_state_bleed(client: TestClient, idp: _DemoIdP) -> None:
    """A tenant-globex attacker (cross_tenant) and a tenant-acme legit agent run
    interleaved. Each tenant's WORM decision is tenant-scoped to itself; neither outcome
    depends on the other (no cross-tenant state bleed)."""
    legit = _post(client, alias=_AUTO_ALIAS, arguments={"period": "acme"}, token=idp.mint(tenant_id=_ACME, agent_id=_aid("acme")))
    attack = _post(client, alias=_AUTO_ALIAS, arguments={"period": "globex"}, token=idp.mint(tenant_id=_GLOBEX, agent_id=_aid("globex")))
    legit2 = _post(client, alias=_AUTO_ALIAS, arguments={"period": "acme2"}, token=idp.mint(tenant_id=_ACME, agent_id=_aid("acme")))

    assert legit.status_code == 200 and legit2.status_code == 200
    _assert_opaque_denial(attack)
    assert _worm_decision_for(_corr(legit)) == "allow"
    assert _worm_decision_for(_corr(legit2)) == "allow"
    assert _worm_reason_for(_corr(attack)) == "cross_tenant"


def test_x09_compartment_crossfire_status_probe_survives(client: TestClient, idp: _DemoIdP) -> None:
    """Within aegis-dynamics: an AEGIS agent (denied on a FALCON alias) and a SENTINEL
    agent (denied on an AEGIS alias) fire interleaved with a legit tenant-wide status
    probe — the un-compartmented probe always ALLOWs while both crossings deny."""
    probe1 = _post(client, alias=_STATUS_ALIAS, arguments={}, token=idp.mint(tenant_id=_AEGIS, agent_id=_aid("probe"), compartment=AEGIS))
    a1 = _post(client, alias=_FALCON_ALIAS, arguments={}, token=idp.mint(tenant_id=_AEGIS, agent_id=_aid("aegis"), compartment=AEGIS))
    a2 = _post(client, alias=_AEGIS_ALIAS, arguments={}, token=idp.mint(tenant_id=_AEGIS, agent_id=_aid("sentinel"), compartment=SENTINEL))
    probe2 = _post(client, alias=_STATUS_ALIAS, arguments={}, token=idp.mint(tenant_id=_AEGIS, agent_id=_aid("probe"), compartment=FALCON))

    assert probe1.status_code == 200 and probe2.status_code == 200
    _assert_opaque_denial(a1)
    _assert_opaque_denial(a2)
    assert _worm_reason_for(_corr(a1)) == "compartment_denied"
    assert _worm_reason_for(_corr(a2)) == "compartment_denied"


def test_x10_jwt_forgery_swarm_legit_survives(client: TestClient, idp: _DemoIdP) -> None:
    """Forged-signature, alg=none, expired, and wrong-issuer tokens all fire interleaved
    with a legit control. Every forgery variant denies jwt_invalid; the control ALLOWs."""
    control = _aid("control")
    expired = _base_claims(idp, tenant_id=_ACME, agent_id=_aid("exp"))
    expired["exp"] = expired["iat"] - 5
    expired["iat"] = expired["nbf"] = expired["exp"] - 60
    wrong_iss = _base_claims(idp, tenant_id=_ACME, agent_id=_aid("iss"))
    wrong_iss["iss"] = "rogue-idp"

    l1 = _post(client, alias=_AUTO_ALIAS, arguments={"period": "1"}, token=idp.mint(tenant_id=_ACME, agent_id=control))
    f1 = _post(client, alias=_AUTO_ALIAS, arguments={"period": "1"}, token=_tamper_signature(idp.mint()))
    f2 = _post(client, alias=_AUTO_ALIAS, arguments={"period": "1"}, token=_forge_none_token())
    l2 = _post(client, alias=_AUTO_ALIAS, arguments={"period": "2"}, token=idp.mint(tenant_id=_ACME, agent_id=control))
    f3 = _post(client, alias=_AUTO_ALIAS, arguments={"period": "1"}, token=_sign(idp, expired))
    f4 = _post(client, alias=_AUTO_ALIAS, arguments={"period": "1"}, token=_sign(idp, wrong_iss))
    l3 = _post(client, alias=_AUTO_ALIAS, arguments={"period": "3"}, token=idp.mint(tenant_id=_ACME, agent_id=control))

    assert l1.status_code == 200 and l2.status_code == 200 and l3.status_code == 200
    for f in (f1, f2, f3, f4):
        _assert_opaque_denial(f)
        assert _worm_reason_for(_corr(f)) == "jwt_invalid"


def test_x11_identity_injection_swarm_legit_survives(client: TestClient, idp: _DemoIdP) -> None:
    """A swarm of identity/capability injection variants interleaved with a legit control:
    every smuggled key hard-denies identity_injection; the clean control agent ALLOWs."""
    control = _aid("control")
    injected_keys = ["tenant_id", "agent_id", "role", "capabilities", "grants"]
    denies: list[Response] = []
    allows: list[Response] = []
    for key in injected_keys:
        allows.append(_post(client, alias=_AUTO_ALIAS, arguments={"period": uuid.uuid4().hex[:6]}, token=idp.mint(tenant_id=_ACME, agent_id=control)))
        denies.append(_post(client, alias=_AUTO_ALIAS, arguments={key: "evil"}, token=idp.mint()))

    for r in allows:
        assert r.status_code == 200, r.text
    for r in denies:
        _assert_opaque_denial(r)
        assert _worm_reason_for(_corr(r)) == "identity_injection"


def test_x12_all_correlation_ids_unique_under_crossfire(client: TestClient, idp: _DemoIdP) -> None:
    """Across a mixed crossfire, every response (allow OR deny) carries a DISTINCT
    correlation handle — no attacker can force a collision that aliases another's audit
    trail, and each id maps to its own expected outcome in WORM."""
    responses: list[tuple[Response, Optional[str], Optional[str]]] = [
        (_post(client, alias=_AUTO_ALIAS, arguments={"period": "ok"}, token=idp.mint(tenant_id=_ACME, agent_id=_aid("ok"))), "allow", None),
        (_post(client, alias=_AUTO_ALIAS, arguments={"period": "x"}, token=idp.mint(tenant_id=_GLOBEX, agent_id=_aid("g"))), "deny", "cross_tenant"),
        (_post(client, alias=_FALCON_ALIAS, arguments={}, token=idp.mint(tenant_id=_AEGIS, agent_id=_aid("a"), compartment=AEGIS)), "deny", "compartment_denied"),
        (_post(client, alias=_AUTO_ALIAS, arguments={"sub": "x"}, token=idp.mint()), "deny", "identity_injection"),
        (_post(client, alias=f"skill_{uuid.uuid4().hex}", arguments={}, token=idp.mint()), "deny", "unknown_alias"),
    ]
    corrs = [_corr(r) for r, _, _ in responses]
    assert len(set(corrs)) == len(corrs), "correlation ids must be globally distinct"
    for resp, decision, reason in responses:
        if decision == "allow":
            assert resp.status_code == 200, resp.text
        else:
            _assert_opaque_denial(resp)
            assert _worm_reason_for(_corr(resp)) == reason


def test_x13_legit_allow_count_preserved_among_attackers(client: TestClient, idp: _DemoIdP) -> None:
    """K legit requests for one control agent, each interleaved with a fresh attacker on a
    different boundary. Assert EXACTLY K allow decisions for the control (by correlation)
    and each attacker a deny — no collateral deny, no missed ALLOW."""
    control = _aid("control")
    k = 5
    control_corrs: list[str] = []
    attacker_corrs: list[str] = []
    boundaries = [
        (_GLOBEX, _AUTO_ALIAS, {}, None),          # cross_tenant
        (_AEGIS, _FALCON_ALIAS, {}, AEGIS),        # compartment_denied
        (_ACME, _AUTO_ALIAS, {"role": "x"}, None),  # identity_injection
        (None, _AUTO_ALIAS, {}, "TAMPER"),          # jwt_invalid
        (_ACME, f"skill_{uuid.uuid4().hex}", {}, None),  # unknown_alias
    ]
    for tenant, alias, args, comp in boundaries:
        ctrl = _post(client, alias=_AUTO_ALIAS, arguments={"period": uuid.uuid4().hex[:6]}, token=idp.mint(tenant_id=_ACME, agent_id=control))
        assert ctrl.status_code == 200, ctrl.text
        control_corrs.append(_corr(ctrl))

        if comp == "TAMPER":
            atk = _post(client, alias=alias, arguments=args, token=_tamper_signature(idp.mint()))
        elif comp is not None:
            atk = _post(client, alias=alias, arguments=args, token=idp.mint(tenant_id=tenant, agent_id=_aid("atk"), compartment=comp))
        else:
            atk = _post(client, alias=alias, arguments=args, token=idp.mint(tenant_id=tenant or _ACME, agent_id=_aid("atk")))
        _assert_opaque_denial(atk)
        attacker_corrs.append(_corr(atk))

    assert len(control_corrs) == k
    assert sum(1 for c in control_corrs if _worm_decision_for(c) == "allow") == k
    assert all(_worm_decision_for(c) == "deny" for c in attacker_corrs)


def test_x14_opacity_holds_for_every_attacker_body(client: TestClient, idp: _DemoIdP) -> None:
    """Under a diverse crossfire, EVERY attacker body is byte-for-byte the opaque
    ``{error, correlation_id}`` envelope — the concrete reason lives ONLY in WORM, never
    on the wire, no matter which boundary was attacked."""
    attackers = [
        _post(client, alias=_AUTO_ALIAS, arguments={"period": "x"}, token=idp.mint(tenant_id=_GLOBEX, agent_id=_aid("g"))),
        _post(client, alias=_ENG_ALIAS, arguments={}, token=idp.mint(tenant_id=_MCPIP, agent_id=_aid("f"), compartment=MCPIP_FINANCE)),
        _post(client, alias=_AUTO_ALIAS, arguments={"principal": "x"}, token=idp.mint()),
        _post(client, alias=_AUTO_ALIAS, arguments={"period": "x"}, token=_forge_none_token()),
        _post(client, alias=_CANARY_ALIAS, arguments={}, token=idp.mint(tenant_id=_ACME, agent_id=_aid("canary"))),
        _post(client, alias=_SENTINEL_ALIAS, arguments={}, token=idp.mint(tenant_id=_AEGIS, agent_id=_aid("s"), compartment=SENTINEL)),
    ]
    reasons = {"cross_tenant", "compartment_denied", "identity_injection", "jwt_invalid", "canary_tripped", "sender_constraint_required"}
    seen: set[str] = set()
    for resp in attackers:
        _assert_opaque_denial(resp)
        r = _worm_reason_for(_corr(resp))
        assert r is not None
        seen.add(r)
        # The concrete reason NEVER appears in the agent-facing body.
        assert r not in resp.text
    assert seen == reasons


def test_x15_no_real_target_leaks_anywhere_under_crossfire(client: TestClient, idp: _DemoIdP) -> None:
    """Across allows AND denials in one crossfire, NO response body ever contains a real
    dotted target or the canary sink label — de-obfuscation holds under multi-persona load."""
    forbidden = [
        _REAL_TARGET, "rest.falcon.telemetry.get", "mainframe.cics.PAYR",
        "rest.mcpip.eng.roadmap.get", CANARY_TARGET, "deception",
    ]
    bodies: list[str] = []
    bodies.append(_post(client, alias=_AUTO_ALIAS, arguments={"period": "ok"}, token=idp.mint(tenant_id=_ACME, agent_id=_aid("ok"))).text)
    bodies.append(_post(client, alias=_COMPANY_ALIAS, arguments={}, token=idp.mint(tenant_id=_MCPIP, agent_id=_aid("m"))).text)
    bodies.append(_post(client, alias=_FALCON_ALIAS, arguments={}, token=idp.mint(tenant_id=_AEGIS, agent_id=_aid("a"), compartment=AEGIS)).text)
    bodies.append(_post(client, alias=_CANARY_ALIAS, arguments={}, token=idp.mint(tenant_id=_ACME, agent_id=_aid("c"))).text)
    bodies.append(_post(client, alias=_ENG_ALIAS, arguments={}, token=idp.mint(tenant_id=_MCPIP, agent_id=_aid("f"), compartment=MCPIP_FINANCE)).text)

    for body in bodies:
        for needle in forbidden:
            assert needle not in body, needle


def test_x16_alias_enumeration_sweep_never_starves_legit(client: TestClient, idp: _DemoIdP) -> None:
    """An attacker sweeps a batch of guessed aliases (unknown_alias) while a legit control
    agent's REAL alias keeps returning 200 throughout — enumeration noise never degrades
    or leaks into the legitimate path."""
    control = _aid("control")
    for _ in range(6):
        good = _post(client, alias=_AUTO_ALIAS, arguments={"period": uuid.uuid4().hex[:6]}, token=idp.mint(tenant_id=_ACME, agent_id=control))
        assert good.status_code == 200, good.text
        guess = _post(client, alias=f"skill_enum_{uuid.uuid4().hex}", arguments={}, token=idp.mint(tenant_id=_ACME, agent_id=_aid("enum")))
        _assert_opaque_denial(guess)
        assert _worm_reason_for(_corr(guess)) == "unknown_alias"


def test_x17_quarantine_revoke_canary_and_cross_tenant_all_isolated(client: TestClient, idp: _DemoIdP) -> None:
    """Four lifecycle/boundary attackers at once — a canary-quarantined agent, an
    admin-revoked agent, a cross-tenant reacher, and a compartment escalator — each denies
    with its OWN reason and NONE affects a legit control agent's ALLOW."""
    admin = _admin(idp, _ACME)
    control = _aid("control")
    canary_id = _aid("canary")
    revoked_id = _aid("revoked")

    # Set up the two stateful attackers.
    trip = _post(client, alias=_CANARY_ALIAS, arguments={}, token=idp.mint(tenant_id=_ACME, agent_id=canary_id))
    _assert_opaque_denial(trip)
    assert _worm_reason_for(_corr(trip)) == "canary_tripped"

    assert _post(client, alias=_AUTO_ALIAS, arguments={"period": "pre"}, token=idp.mint(tenant_id=_ACME, agent_id=revoked_id)).status_code == 200
    client.post(f"/v1/admin/principals/{revoked_id}/revoke", json={}, headers={"Authorization": f"Bearer {admin}"})

    # Now cross all four boundaries plus a legit control, interleaved.
    quarantined = _post(client, alias=_AUTO_ALIAS, arguments={"period": "q"}, token=idp.mint(tenant_id=_ACME, agent_id=canary_id))
    legit1 = _post(client, alias=_AUTO_ALIAS, arguments={"period": "l1"}, token=idp.mint(tenant_id=_ACME, agent_id=control))
    revoked = _post(client, alias=_AUTO_ALIAS, arguments={"period": "r"}, token=idp.mint(tenant_id=_ACME, agent_id=revoked_id))
    legit2 = _post(client, alias=_AUTO_ALIAS, arguments={"period": "l2"}, token=idp.mint(tenant_id=_ACME, agent_id=control))
    cross = _post(client, alias=_AUTO_ALIAS, arguments={"period": "x"}, token=idp.mint(tenant_id=_GLOBEX, agent_id=_aid("g")))
    legit3 = _post(client, alias=_AUTO_ALIAS, arguments={"period": "l3"}, token=idp.mint(tenant_id=_ACME, agent_id=control))
    compartment = _post(client, alias=_FALCON_ALIAS, arguments={}, token=idp.mint(tenant_id=_AEGIS, agent_id=_aid("a"), compartment=AEGIS))

    for r in (quarantined, revoked, cross, compartment):
        _assert_opaque_denial(r)
    assert _worm_reason_for(_corr(quarantined)) == "agent_quarantined"
    assert _worm_reason_for(_corr(revoked)) == "principal_revoked"
    assert _worm_reason_for(_corr(cross)) == "cross_tenant"
    assert _worm_reason_for(_corr(compartment)) == "compartment_denied"
    for legit in (legit1, legit2, legit3):
        assert legit.status_code == 200, legit.text
        assert _json(legit)["decision"] == "allow"

    client.post(f"/v1/admin/principals/{revoked_id}/reactivate", headers={"Authorization": f"Bearer {admin}"})


def test_x18_worm_decision_split_allow_and_deny_coexist(client: TestClient, idp: _DemoIdP) -> None:
    """One legit ALLOW and one attacker DENY, both recovered from WORM by their own
    correlation: the durable audit log records BOTH the allow (with no deny_reason) and
    the deny (with its concrete reason) — the split is per-request, never conflated."""
    allow = _post(client, alias=_AUTO_ALIAS, arguments={"period": "split"}, token=idp.mint(tenant_id=_ACME, agent_id=_aid("ok")))
    deny = _post(client, alias=_AUTO_ALIAS, arguments={"period": "x"}, token=idp.mint(tenant_id=_GLOBEX, agent_id=_aid("g")))

    assert allow.status_code == 200, allow.text
    _assert_opaque_denial(deny)
    assert _worm_decision_for(_corr(allow)) == "allow"
    assert _worm_reason_for(_corr(allow)) is None  # an allow carries no deny reason.
    assert _worm_decision_for(_corr(deny)) == "deny"
    assert _worm_reason_for(_corr(deny)) == "cross_tenant"
