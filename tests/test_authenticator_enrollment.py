"""
Per-user authenticator (USER-BASED 2FA) tests — store, channel, and API surface.

Layer 1 (store): AES-256-GCM-at-rest TOTP enrollment lifecycle, replay guard,
attempt lockout, AAD transplant refusal — against a dedicated Redis db (``/13``).
Layer 2 (channel): the TOTP-gated encrypted OTP stash (seal / single-use reveal /
cross-tenant AAD refusal) + the fail-closed fanout.
Layer 3 (API, sandbox app): enroll → confirm → stage a PIN_REQUIRED action →
TOTP-gated reveal → complete with the payload-bound PIN; opaque denials for wrong
code / unenrolled; admin roster + lost-device removal; WORM ``otp_reveal`` record
with the raw code never embedded.

Requires a Redis on :63790 (the dev container), like the rest of the suite.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Same namespaced sandbox env as the API suite — set BEFORE importing app.main
# (idempotent when another API module imported it first).
_TEST_REDIS_URL = "redis://localhost:63790/5"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_worm.jsonl"),
)

import asyncio
import base64
import json
from typing import Any, Iterator, Optional

import pytest
import redis as redis_sync
import redis.asyncio as aioredis
from fastapi.testclient import TestClient

from interfaces import (
    MAX_TOTP_ATTEMPTS,
    PIN_TTL_SECONDS,
    RiskTier,
    AuthenticatorNotice,
)
from services.authenticator_enrollment import (
    AuthenticatorEnrollmentStore,
    _totp_at,
    current_timestep,
)
from services.authn_channel import (
    AuthenticatorDeliveryError,
    FanoutAuthenticatorChannel,
    TotpVaultAuthenticatorChannel,
)

from app.main import _components, app
from main import _DemoIdP

_STORE_REDIS_URL = "redis://localhost:63790/13"
_KEY_A = b"A" * 32
_KEY_B = b"B" * 32
_EVENTS_STREAM = "mcpip:worm:events"


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _code_from_b32(secret_b32: str, *, step_offset: int = 0) -> str:
    """Compute the app-side TOTP code from the provisioning secret."""
    padded = secret_b32 + "=" * (-len(secret_b32) % 8)
    secret = base64.b32decode(padded)
    return _totp_at(secret, current_timestep() + step_offset)


async def _fresh_store(
    master_key: bytes = _KEY_A,
) -> tuple[AuthenticatorEnrollmentStore, Any]:
    client: Any = aioredis.from_url(_STORE_REDIS_URL, decode_responses=False)
    await client.flushdb()
    return AuthenticatorEnrollmentStore(client, master_key), client


async def _enroll_active(
    store: AuthenticatorEnrollmentStore, tenant: str, agent: str
) -> bytes:
    """begin + confirm (with the previous-step code, leaving the current step unburned).
    Returns the RAW secret so tests can mint codes."""
    begin = await store.begin(tenant, agent)
    assert begin is not None
    padded = begin.secret_base32 + "=" * (-len(begin.secret_base32) % 8)
    secret = base64.b32decode(padded)
    ok = await store.confirm(tenant, agent, _totp_at(secret, current_timestep() - 1))
    assert ok, "confirm with a drift-window code must activate"
    return secret


# ---------------------------------------------------------------------------
# Layer 1 — enrollment store.
# ---------------------------------------------------------------------------


def test_master_key_must_be_32_bytes() -> None:
    client: Any = aioredis.from_url(_STORE_REDIS_URL, decode_responses=False)
    with pytest.raises(RuntimeError):
        AuthenticatorEnrollmentStore(client, b"short")


def test_lifecycle_begin_confirm_verify() -> None:
    async def scenario() -> None:
        store, client = await _fresh_store()
        try:
            begin = await store.begin("t1", "alice")
            assert begin is not None
            assert begin.provisioning_uri.startswith("otpauth://totp/MCPIP")
            assert begin.digits == 6 and begin.period_s == 30
            st = await store.status("t1", "alice")
            assert st.pending and not st.enrolled

            secret = base64.b32decode(
                begin.secret_base32 + "=" * (-len(begin.secret_base32) % 8)
            )
            # Wrong code does not activate.
            assert not await store.confirm("t1", "alice", "000000")
            # Previous-step code (drift window) activates; current step stays unburned.
            assert await store.confirm("t1", "alice", _totp_at(secret, current_timestep() - 1))
            st = await store.status("t1", "alice")
            assert st.enrolled and not st.pending and st.enrolled_at is not None

            # A live current-step code verifies once...
            code_now = _totp_at(secret, current_timestep())
            assert await store.verify("t1", "alice", code_now)
            # ...and replaying the SAME code is refused (one success per code).
            assert not await store.verify("t1", "alice", code_now)
        finally:
            await client.aclose()

    _run(scenario())


def test_wrong_codes_lock_out_even_a_later_correct_code() -> None:
    async def scenario() -> None:
        store, client = await _fresh_store()
        try:
            secret = await _enroll_active(store, "t1", "bob")
            for _ in range(MAX_TOTP_ATTEMPTS):
                assert not await store.verify("t1", "bob", "999999")
            # Budget exhausted: even the CORRECT code is refused (fail-closed lockout).
            good = _totp_at(secret, current_timestep())
            assert not await store.verify("t1", "bob", good)
        finally:
            await client.aclose()

    _run(scenario())


def test_secret_is_ciphertext_at_rest() -> None:
    async def scenario() -> None:
        store, client = await _fresh_store()
        try:
            begin = await store.begin("t1", "carol")
            assert begin is not None
            raw = await client.get("mcpip:authn:totp:t1:carol")
            assert raw is not None
            text = raw.decode("utf-8", errors="replace")
            # Neither the manual-entry key nor the raw secret bytes appear at rest.
            assert begin.secret_base32 not in text
            padded = begin.secret_base32 + "=" * (-len(begin.secret_base32) % 8)
            assert base64.b64encode(base64.b32decode(padded)).decode() not in text
        finally:
            await client.aclose()

    _run(scenario())


def test_begin_refused_while_active_until_disable() -> None:
    async def scenario() -> None:
        store, client = await _fresh_store()
        try:
            secret = await _enroll_active(store, "t1", "dave")
            # Re-enroll over a live authenticator is refused (bearer alone can't swap it).
            assert await store.begin("t1", "dave") is None
            # Self-disable needs a valid CURRENT code — wrong code refused.
            assert not await store.disable("t1", "dave", "000000")
            assert (await store.status("t1", "dave")).enrolled
            assert await store.disable("t1", "dave", _totp_at(secret, current_timestep()))
            assert not (await store.status("t1", "dave")).enrolled
            # Gone → begin is allowed again.
            assert await store.begin("t1", "dave") is not None
        finally:
            await client.aclose()

    _run(scenario())


def test_admin_disable_removes_without_code() -> None:
    async def scenario() -> None:
        store, client = await _fresh_store()
        try:
            await _enroll_active(store, "t1", "erin")
            assert await store.admin_disable("t1", "erin")
            assert not (await store.status("t1", "erin")).enrolled
            assert not await store.admin_disable("t1", "erin")  # already gone
        finally:
            await client.aclose()

    _run(scenario())


def test_transplanted_blob_does_not_verify() -> None:
    """A ciphertext blob copied to another principal's key must not decrypt (AAD)."""

    async def scenario() -> None:
        store, client = await _fresh_store()
        try:
            secret = await _enroll_active(store, "t1", "frank")
            blob = await client.get("mcpip:authn:totp:t1:frank")
            await client.set("mcpip:authn:totp:t1:mallory", blob)
            code = _totp_at(secret, current_timestep())
            assert not await store.verify("t1", "mallory", code)
        finally:
            await client.aclose()

    _run(scenario())


def test_roster_lists_enrollments_bounded_and_scoped() -> None:
    async def scenario() -> None:
        store, client = await _fresh_store()
        try:
            await _enroll_active(store, "t1", "gina")
            begin = await store.begin("t1", "half-done")
            assert begin is not None
            await _enroll_active(store, "OTHER", "outsider")
            rows = await store.list_enrolled("t1")
            by_id = {r["agent_id"]: r for r in rows}
            assert set(by_id) == {"gina", "half-done"}
            assert by_id["gina"]["state"] == "active"
            assert by_id["half-done"]["state"] == "pending"
        finally:
            await client.aclose()

    _run(scenario())


# ---------------------------------------------------------------------------
# Layer 2 — the TOTP-gated encrypted OTP stash channel + fanout.
# ---------------------------------------------------------------------------


def _notice(tenant: str, challenge: str, otp: str) -> AuthenticatorNotice:
    return AuthenticatorNotice(
        tenant_id=tenant,
        challenge_id=challenge,
        agent_id="agent-x",
        alias="skill_payroll_run",
        risk_tier=RiskTier.PIN_REQUIRED,
        expires_in_s=PIN_TTL_SECONDS,
        otp=otp,
    )


def test_stash_seals_reveals_once_and_binds_tenant() -> None:
    async def scenario() -> None:
        client: Any = aioredis.from_url(_STORE_REDIS_URL, decode_responses=False)
        await client.flushdb()
        try:
            channel = TotpVaultAuthenticatorChannel(client, _KEY_A)
            await channel.deliver(_notice("t1", "c" * 32, "123456"))
            raw = await client.get("mcpip:otpv:t1:" + "c" * 32)
            assert raw is not None and b"123456" not in raw  # ciphertext at rest
            # Cross-tenant read misses (AAD + key namespace).
            assert await channel.reveal("t2", "c" * 32) is None
            # Single-use: first reveal returns, second is spent.
            assert await channel.reveal("t1", "c" * 32) == "123456"
            assert await channel.reveal("t1", "c" * 32) is None
        finally:
            await client.aclose()

    _run(scenario())


def test_fanout_propagates_any_failure() -> None:
    class _Boom:
        async def deliver(self, notice: AuthenticatorNotice) -> None:
            raise AuthenticatorDeliveryError("down")

    class _Ok:
        def __init__(self) -> None:
            self.delivered = 0

        async def deliver(self, notice: AuthenticatorNotice) -> None:
            self.delivered += 1

    async def scenario() -> None:
        ok = _Ok()
        fan = FanoutAuthenticatorChannel((ok, _Boom()))  # type: ignore[arg-type]
        with pytest.raises(AuthenticatorDeliveryError):
            await fan.deliver(_notice("t1", "d" * 32, "654321"))
        assert ok.delivered == 1  # first leg ran; the unit still failed closed

    _run(scenario())


# ---------------------------------------------------------------------------
# Layer 3 — API surface (sandbox app; same harness as the API suite).
# ---------------------------------------------------------------------------

_PIN_ALIAS = "skill_payroll_run"


@pytest.fixture(scope="module")
def idp() -> _DemoIdP:
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


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _enroll_via_api(client: TestClient, token: str) -> str:
    """POST enroll + confirm; returns the base32 secret for later code minting."""
    resp = client.post("/v1/authenticator/enroll", headers=_auth(token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == {"secret", "provisioning_uri", "digits", "period_s"}
    confirm = client.post(
        "/v1/authenticator/enroll/confirm",
        headers=_auth(token),
        json={"code": _code_from_b32(body["secret"], step_offset=-1)},
    )
    assert confirm.status_code == 200, confirm.text
    secret: str = body["secret"]
    return secret


def _stage(client: TestClient, token: str, args: dict[str, Any]) -> str:
    resp = client.post(
        "/v1/authorize",
        json={
            "source_format": "openai_tool_call",
            "tool_call": {
                "id": "call_test",
                "type": "function",
                "function": {"name": _PIN_ALIAS, "arguments": json.dumps(args)},
            },
            "jwt": token,
        },
    )
    assert resp.status_code == 202, resp.text
    return str(resp.json()["challenge_id"])


def _worm_records(action: str) -> list[dict[str, Any]]:
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=300)
    finally:
        reader.close()
    out: list[dict[str, Any]] = []
    for _sid, fields in entries:
        record: Any = json.loads(fields["record"])
        event = record.get("event", {})
        if isinstance(event, dict) and event.get("admin_action") == action:
            out.append(event)
    return out


def test_api_status_enroll_confirm_flow(client: TestClient, idp: _DemoIdP) -> None:
    token = idp.mint(agent_id="operator-2fa-flow")
    st = client.get("/v1/authenticator", headers=_auth(token))
    assert st.status_code == 200 and st.json() == {
        "enrolled": False,
        "pending": False,
        "enrolled_at": None,
    }
    _enroll_via_api(client, token)
    st2 = client.get("/v1/authenticator", headers=_auth(token))
    assert st2.status_code == 200 and st2.json()["enrolled"] is True
    # Second enroll over a live authenticator: opaque deny.
    again = client.post("/v1/authenticator/enroll", headers=_auth(token))
    assert again.status_code == 403
    # Enroll/confirm actions are WORM-recorded, and no record embeds a secret.
    assert _worm_records("authenticator_enroll")
    assert _worm_records("authenticator_confirm")
    for ev in _worm_records("authenticator_enroll") + _worm_records("authenticator_confirm"):
        assert "secret" not in ev and "otp" not in ev


def test_api_user_2fa_reveal_completes_action(client: TestClient, idp: _DemoIdP) -> None:
    """The headline flow: enrolled human's TOTP releases the staged payload-bound PIN,
    which then completes the classic two-step. The lock itself is untouched."""
    token = idp.mint(agent_id="operator-2fa-e2e")
    secret = _enroll_via_api(client, token)
    args = {"run_id": "PR-2FA-1", "cycle": "monthly"}
    challenge_id = _stage(client, token, args)

    reveal = client.post(
        "/v1/authenticator/reveal",
        headers=_auth(token),
        json={"challenge_id": challenge_id, "code": _code_from_b32(secret)},
    )
    assert reveal.status_code == 200, reveal.text
    otp = reveal.json()["otp"]

    done = client.post(
        "/v1/authorize",
        json={
            "source_format": "openai_tool_call",
            "tool_call": {
                "id": "call_test",
                "type": "function",
                "function": {"name": _PIN_ALIAS, "arguments": json.dumps(args)},
            },
            "jwt": token,
            "pin": otp,
            "challenge_id": challenge_id,
        },
    )
    assert done.status_code == 200, done.text
    assert done.json()["decision"] == "allow"

    # Audit-before-disclosure: the reveal is WORM-recorded, found=True, and the raw
    # code is NEVER embedded in the record.
    reveals = _worm_records("otp_reveal")
    assert reveals and reveals[0]["found"] is True
    assert reveals[0]["challenge_id"] == challenge_id
    assert "otp" not in reveals[0]


def test_api_reveal_wrong_code_denied(client: TestClient, idp: _DemoIdP) -> None:
    token = idp.mint(agent_id="operator-2fa-wrong")
    _enroll_via_api(client, token)
    challenge_id = _stage(client, token, {"run_id": "PR-2FA-2", "cycle": "weekly"})
    resp = client.post(
        "/v1/authenticator/reveal",
        headers=_auth(token),
        json={"challenge_id": challenge_id, "code": "000000"},
    )
    assert resp.status_code == 403
    assert set(resp.json()) == {"error", "correlation_id"}


def test_api_unenrolled_reveal_denied(client: TestClient, idp: _DemoIdP) -> None:
    token = idp.mint(agent_id="operator-2fa-unenrolled")
    challenge_id = _stage(client, token, {"run_id": "PR-2FA-3", "cycle": "daily"})
    resp = client.post(
        "/v1/authenticator/reveal",
        headers=_auth(token),
        json={"challenge_id": challenge_id, "code": "123456"},
    )
    assert resp.status_code == 403


def test_api_admin_roster_and_lost_device(client: TestClient, idp: _DemoIdP) -> None:
    from interfaces import CAP_DIRECTORY_ADMIN

    principal = "operator-2fa-roster"
    token = idp.mint(agent_id=principal)
    _enroll_via_api(client, token)
    admin = idp.mint(agent_id="director-1", capabilities=[CAP_DIRECTORY_ADMIN])

    roster = client.get("/v1/admin/authenticator/enrollments", headers=_auth(admin))
    assert roster.status_code == 200, roster.text
    rows = {r["agent_id"]: r for r in roster.json()["enrollments"]}
    assert principal in rows and rows[principal]["state"] == "active"

    # Roster is admin-only: a plain principal is denied opaquely.
    assert (
        client.get("/v1/admin/authenticator/enrollments", headers=_auth(token)).status_code
        == 403
    )

    removed = client.delete(
        f"/v1/admin/authenticator/{principal}", headers=_auth(admin)
    )
    assert removed.status_code == 200 and removed.json()["removed"] is True
    st = client.get("/v1/authenticator", headers=_auth(token))
    assert st.json()["enrolled"] is False
    assert _worm_records("authenticator_admin_disable")
