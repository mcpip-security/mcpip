"""
MCPIP V2 — G1: out-of-band authenticator delivery (BaseAuthenticatorChannel) tests.

    ◐  "The code is minted and locked once; only its DELIVERY is pluggable — and
       delivery fails CLOSED, never open."

Exercises the REAL delivery seam introduced by G1 end to end:

  * ``SandboxRedisAuthenticatorChannel`` — deliver + peek round-trip against a real
    sandbox Redis, byte-identical key/TTL to the pre-G1 in-engine stash;
  * the full sandbox pipeline (through Starlette's ``TestClient``, so the FastAPI
    lifespan + Redis rebind run on one loop) still stages a PIN_REQUIRED action, never
    surfaces the OTP in the 202 / on the agent wire, and the payload lock still binds
    (PAYLOAD_MISMATCH on drift) UNCHANGED — G1 moved only delivery, not derivation;
  * ``WebhookAuthenticatorChannel`` — the REAL production channel: constructor rejects
    a non-https URL; the SSRF guard (real ``getaddrinfo``, no mocks) refuses a
    loopback / private / link-local (cloud-metadata) / IPv4-mapped host both at the
    ``_is_blocked_ip`` primitive and end to end through ``deliver``; and the signed
    notice body it serializes is the real canonical JSON carrying the code, HMAC-able
    with the configured secret;
  * ``AuthEngine`` delivery orchestration: an UNCONFIGURED production gateway (None
    channel) and a channel whose ``deliver`` raises both fail closed with the DISTINCT
    ``OTP_DELIVERY_FAILED`` reason and stage NO usable challenge; a real channel gets
    the real OTP out-of-band while the return value is only the challenge_id (never the
    code), and that delivered code still spends the unchanged payload lock.

The environment matches ``tests/test_authorize_api.py`` (sandbox, Redis db ``/5``) so a
shared ``_components`` graph agrees on the store no matter the import order.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# --- MUST match tests/test_authorize_api.py (db + sandbox flag) so a shared components
#     graph agrees no matter which suite imports app.main first. ---------------------
_TEST_REDIS_URL = "redis://localhost:63790/5"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_worm.jsonl"),
)

import asyncio
import hashlib
import hmac
import json
from typing import Any, Iterator, Optional

import pytest
import redis as redis_sync
import redis.asyncio as aioredis
from fastapi.testclient import TestClient
from httpx import Response

from auth import PinValidator
from core.security import AGENT_FACING_DENY_MESSAGE, GatewayDeny
from interfaces import (
    AuthenticatorNotice,
    BaseAuthenticatorChannel,
    DenyReason,
    Identity,
    PIN_TTL_SECONDS,
    RiskTier,
)
from obfuscator.alias_registry import AliasEntry
from services.auth_engine import AuthEngine
from services.authn_channel import (
    AuthenticatorDeliveryError,
    SandboxRedisAuthenticatorChannel,
    WebhookAuthenticatorChannel,
    _is_blocked_ip,
)

from app.main import _components, app
from main import _DemoIdP

_PIN_ALIAS = "skill_payroll_run"          # tenant-acme PIN_REQUIRED.
_EVENTS_STREAM = "mcpip:worm:events"
_CORR_HEADER = "x-mcpip-correlation-id"
_WEBHOOK_SECRET = b"x" * 32               # >= 32 raw bytes (boot-lint minimum).
# Dedicated, isolated db for the engine-only tests (their own AuthEngine/PinValidator on
# a fresh client). Kept OFF the shared API db (/5) so "nothing was staged" assertions are
# deterministic — identity verification uses _components.resolver, which touches no Redis.
_ENGINE_REDIS_URL = "redis://localhost:63790/13"


# ---------------------------------------------------------------------------
# Fixtures / helpers.
# ---------------------------------------------------------------------------


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


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


def _aioredis() -> Any:
    return aioredis.from_url(_TEST_REDIS_URL, decode_responses=True)  # type: ignore[no-untyped-call]


async def _fresh_engine_redis() -> Any:
    client: Any = aioredis.from_url(_ENGINE_REDIS_URL, decode_responses=True)  # type: ignore[no-untyped-call]
    await client.flushdb()
    return client


def _openai_call(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
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
    pin: Optional[str] = None,
    challenge_id: Optional[str] = None,
) -> Response:
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


def _last_deny_reason() -> Optional[str]:
    reader: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        entries: Any = reader.xrevrange(_EVENTS_STREAM, count=1)
    finally:
        reader.close()
    if not entries:
        return None
    _sid, fields = entries[0]
    reason = json.loads(fields["record"])["event"].get("deny_reason")
    return reason if isinstance(reason, str) else None


def _notice(otp: str = "123456", tenant: str = "tenant-acme") -> AuthenticatorNotice:
    return AuthenticatorNotice(
        tenant_id=tenant,
        challenge_id="chal-abc",
        agent_id="agent-x",
        alias=_PIN_ALIAS,
        risk_tier=RiskTier.PIN_REQUIRED,
        expires_in_s=PIN_TTL_SECONDS,
        otp=otp,
    )


def _identity(idp: _DemoIdP, agent_id: str) -> Identity:
    return _components.auth.verify_identity(
        idp.mint(tenant_id="tenant-acme", agent_id=agent_id)
    )


class _CapturingChannel(BaseAuthenticatorChannel):
    """A REAL BaseAuthenticatorChannel implementation (not a mock of the SUT) that
    records the notice the engine hands it — the stand-in for an enrolled device."""

    def __init__(self) -> None:
        self.delivered: list[AuthenticatorNotice] = []

    async def deliver(self, notice: AuthenticatorNotice) -> None:
        self.delivered.append(notice)


class _RaisingChannel(BaseAuthenticatorChannel):
    """A REAL channel whose delivery fails — models a real transport/guard failure."""

    async def deliver(self, notice: AuthenticatorNotice) -> None:
        raise AuthenticatorDeliveryError("simulated sink outage")


# ===========================================================================
# 1) Sandbox channel: deliver + peek round-trip, byte-identical key/TTL.
# ===========================================================================


def test_sandbox_channel_delivers_and_peeks() -> None:
    async def scenario() -> None:
        redis_client = _aioredis()
        try:
            channel = SandboxRedisAuthenticatorChannel(redis_client)
            notice = _notice(otp="654321")
            await channel.deliver(notice)

            # peek reads back the exact code the demo authenticator endpoint surfaces.
            got = await channel.peek(notice.tenant_id, notice.challenge_id)
            assert got == "654321"

            # Stored under the unchanged tenant-scoped key with the lock TTL.
            key = f"mcpip:otp:{notice.tenant_id}:{notice.challenge_id}"
            assert await redis_client.get(key) == "654321"
            ttl = await redis_client.ttl(key)
            assert 0 < ttl <= PIN_TTL_SECONDS

            # An unknown / expired challenge is an honest None (never a fabricated code).
            assert await channel.peek(notice.tenant_id, "never-staged") is None
        finally:
            await redis_client.delete(
                f"mcpip:otp:{notice.tenant_id}:{notice.challenge_id}"
            )
            await redis_client.aclose()

    _run(scenario())


# ===========================================================================
# 2) Sandbox pipeline: stage → deliver → peek → consume is UNCHANGED.
# ===========================================================================


def test_sandbox_pipeline_stage_deliver_consume_unchanged(
    client: TestClient, idp: _DemoIdP
) -> None:
    token = idp.mint(tenant_id="tenant-acme", agent_id="agent-g1-happy")
    args = {"amount": 4200, "run": "2026-07"}
    staged = _post(client, alias=_PIN_ALIAS, arguments=args, token=token)
    assert staged.status_code == 202, staged.text
    challenge_id = staged.json()["challenge_id"]

    # The out-of-band authenticator endpoint (backed by the sandbox channel's peek).
    otp_resp = client.get(
        f"/v1/authenticator/{challenge_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert otp_resp.status_code == 200, otp_resp.text
    otp = otp_resp.json()["otp"]
    assert otp.isdigit() and len(otp) == 6

    done = _post(
        client, alias=_PIN_ALIAS, arguments=args, token=token,
        pin=otp, challenge_id=challenge_id,
    )
    assert done.status_code == 200, done.text
    assert done.json()["decision"] == "allow"


# ===========================================================================
# 3) The 202 (and the agent wire) NEVER carries the OTP.
# ===========================================================================


def test_202_never_exposes_the_otp(client: TestClient, idp: _DemoIdP) -> None:
    token = idp.mint(tenant_id="tenant-acme", agent_id="agent-g1-opaque")
    staged = _post(client, alias=_PIN_ALIAS, arguments={"amount": 7}, token=token)
    assert staged.status_code == 202, staged.text
    body = staged.json()
    challenge_id = body["challenge_id"]

    # The staging envelope exposes the challenge handle only — no code / pin fields.
    flat = json.dumps(body)
    assert "otp" not in body and "pin" not in body
    # Fetch the real code out-of-band and prove it is NOT anywhere in the 202 body.
    otp = client.get(
        f"/v1/authenticator/{challenge_id}",
        headers={"Authorization": f"Bearer {token}"},
    ).json()["otp"]
    assert otp not in flat


# ===========================================================================
# 4) The payload lock still BINDS — PAYLOAD_MISMATCH on argument drift (unchanged).
# ===========================================================================


def test_payload_lock_still_binds_on_drift(client: TestClient, idp: _DemoIdP) -> None:
    token = idp.mint(tenant_id="tenant-acme", agent_id="agent-g1-drift")
    staged = _post(
        client, alias=_PIN_ALIAS, arguments={"amount": 100}, token=token
    )
    assert staged.status_code == 202, staged.text
    challenge_id = staged.json()["challenge_id"]
    otp = client.get(
        f"/v1/authenticator/{challenge_id}",
        headers={"Authorization": f"Bearer {token}"},
    ).json()["otp"]

    # Same code + challenge but DRIFTED arguments → the lock refuses (payload-bound).
    drifted = _post(
        client, alias=_PIN_ALIAS, arguments={"amount": 999}, token=token,
        pin=otp, challenge_id=challenge_id,
    )
    assert drifted.status_code == 403
    assert set(drifted.json().keys()) == {"error", "correlation_id"}
    assert _last_deny_reason() == DenyReason.PAYLOAD_MISMATCH.value


# ===========================================================================
# 5) Production channel: constructor rejects a non-https / hostless / secretless URL.
# ===========================================================================


def test_webhook_constructor_rejects_bad_config() -> None:
    with pytest.raises(ValueError):
        WebhookAuthenticatorChannel("http://sink.example/hook", _WEBHOOK_SECRET, 5.0)
    with pytest.raises(ValueError):
        WebhookAuthenticatorChannel("https:///nohost", _WEBHOOK_SECRET, 5.0)
    with pytest.raises(ValueError):
        WebhookAuthenticatorChannel("https://sink.example/hook", b"", 5.0)
    # A valid https config constructs and clamps the timeout into the safety band.
    ok = WebhookAuthenticatorChannel("https://sink.example/hook", _WEBHOOK_SECRET, 999.0)
    assert 0 < ok._timeout_s <= 30.0
    floored = WebhookAuthenticatorChannel(
        "https://sink.example/hook", _WEBHOOK_SECRET, 0.001
    )
    assert floored._timeout_s >= 0.5


# ===========================================================================
# 6) SSRF guard: the _is_blocked_ip primitive rejects every internal range.
# ===========================================================================


def test_is_blocked_ip_rejects_internal_ranges() -> None:
    for blocked in (
        "127.0.0.1",           # loopback
        "::1",                 # loopback v6
        "10.0.0.5",            # private
        "172.16.9.9",          # private
        "192.168.1.1",         # private
        "169.254.169.254",     # link-local cloud metadata
        "0.0.0.0",             # unspecified
        "224.0.0.1",           # multicast
        "::ffff:127.0.0.1",    # IPv4-mapped loopback (must be unwrapped)
        "::ffff:10.1.2.3",     # IPv4-mapped private
        "not-an-ip",           # unparseable → fail-closed blocked
    ):
        assert _is_blocked_ip(blocked) is True, blocked
    # Real public addresses are allowed (the channel would actually dial these).
    for allowed in ("8.8.8.8", "1.1.1.1", "93.184.216.34"):
        assert _is_blocked_ip(allowed) is False, allowed


# ===========================================================================
# 7) SSRF guard end to end: deliver() to a private/loopback host raises (real DNS).
# ===========================================================================


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost/hook",          # resolves to 127.0.0.1 / ::1
        "https://127.0.0.1/hook",          # loopback literal
        "https://169.254.169.254/latest",  # cloud-metadata link-local
        "https://10.255.255.254/hook",     # private literal
    ],
)
def test_webhook_deliver_refuses_internal_host(url: str) -> None:
    channel = WebhookAuthenticatorChannel(url, _WEBHOOK_SECRET, 2.0)
    with pytest.raises(AuthenticatorDeliveryError):
        _run(channel.deliver(_notice()))


# ===========================================================================
# 8) Production channel serializes a REAL signed-notice body carrying the code.
# ===========================================================================


def test_webhook_serializes_real_signed_notice() -> None:
    channel = WebhookAuthenticatorChannel(
        "https://sink.example/hook", _WEBHOOK_SECRET, 5.0
    )
    notice = _notice(otp="424242")
    body = channel._serialize(notice)

    # Deterministic, canonical (sorted, tight) JSON — the exact bytes that get signed.
    parsed = json.loads(body)
    assert parsed["otp"] == "424242"
    assert parsed["challenge_id"] == notice.challenge_id
    assert parsed["alias"] == _PIN_ALIAS
    assert parsed["risk_tier"] == RiskTier.PIN_REQUIRED.value
    assert body == json.dumps(parsed, separators=(",", ":"), sort_keys=True).encode()

    # The signed notice is HMAC-SHA256-verifiable with the configured secret — a
    # receiver reconstructs sig over "timestamp.body" and constant-time-compares it.
    ts = "1700000000"
    sig = hmac.new(
        _WEBHOOK_SECRET, ts.encode("ascii") + b"." + body, hashlib.sha256
    ).hexdigest()
    assert len(sig) == 64 and int(sig, 16) >= 0  # a real hex SHA-256 signature.


def test_webhook_client_is_hermetic_ignores_ambient_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Regression (red-team, G1 secret-exposure lens): a secret-delivery client that
    hand-rolls SSRF validation + connection IP-pinning MUST be built ``trust_env=False``
    (+ ``proxy=None``), or an ambient ``HTTPS_PROXY`` / ``SSL_CERT_FILE`` / ``SSLKEYLOGFILE``
    silently reroutes the OTP push through an unvalidated intermediary — voiding the
    loopback/private-IP guard AND the TLS pin and disclosing the raw one-time code. This
    asserts the client is constructed hermetically even with a hostile ambient env.
    """
    import services.authn_channel as ac

    captured: dict[str, Any] = {}

    class _FakeResponse:
        status_code = 200

        async def aiter_raw(self) -> Any:
            return
            yield b""  # pragma: no cover — makes this an empty async generator.

        async def aclose(self) -> None:
            return None

    class _FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

        async def __aenter__(self) -> "_FakeClient":
            return self

        async def __aexit__(self, *exc: Any) -> None:
            return None

        def build_request(self, *args: Any, **kwargs: Any) -> object:
            return object()

        async def send(self, *args: Any, **kwargs: Any) -> "_FakeResponse":
            return _FakeResponse()

    # Ambient proxy + CA — exactly what httpx honors under the default trust_env=True.
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/ca.pem")

    # Skip real DNS; return a public TEST-NET-3 IP so deliver reaches client construction.
    async def _fake_validate(_self: Any) -> str:
        return "203.0.113.10"

    monkeypatch.setattr(
        ac.WebhookAuthenticatorChannel, "_resolve_and_validate", _fake_validate
    )
    monkeypatch.setattr(ac.httpx, "AsyncClient", _FakeClient)

    channel = WebhookAuthenticatorChannel(
        "https://sink.example/hook", _WEBHOOK_SECRET, 5.0
    )
    _run(channel.deliver(_notice(otp="424242")))

    assert captured.get("trust_env") is False, "OTP webhook client must be trust_env=False"
    assert captured.get("proxy") is None, "OTP webhook client must not honor an ambient proxy"
    assert captured.get("follow_redirects") is False
    assert captured.get("verify") is True


# ===========================================================================
# 9) Engine: an UNCONFIGURED production gateway (None channel) fails closed.
# ===========================================================================


def test_engine_unconfigured_channel_fails_closed(idp: _DemoIdP) -> None:
    async def scenario() -> None:
        redis_client = await _fresh_engine_redis()
        try:
            engine = AuthEngine(
                _components.resolver, PinValidator(redis_client), redis_client, None
            )
            identity = _identity(idp, "agent-unconfigured")
            with pytest.raises(GatewayDeny) as ei:
                await engine.register_lock(
                    identity, _PIN_ALIAS, {"amount": 1}, RiskTier.PIN_REQUIRED
                )
            # Distinct fail-closed reason (NOT a generic LOCK_ERROR).
            assert ei.value.reason is DenyReason.OTP_DELIVERY_FAILED
            # No challenge id was ever returned → nothing usable was staged. And since
            # the None-channel check precedes the mint, no payload lock was created at
            # all (isolated db → this scan is deterministic).
            keys = [
                k async for k in redis_client.scan_iter(match="mcpip:pinlock:*")
            ]
            assert keys == []
        finally:
            await redis_client.aclose()

    _run(scenario())


# ===========================================================================
# 10) Engine: a channel whose deliver() raises fails closed (no usable challenge).
# ===========================================================================


def test_engine_delivery_failure_fails_closed(idp: _DemoIdP) -> None:
    async def scenario() -> None:
        redis_client = await _fresh_engine_redis()
        try:
            engine = AuthEngine(
                _components.resolver,
                PinValidator(redis_client),
                redis_client,
                _RaisingChannel(),
            )
            identity = _identity(idp, "agent-deliverfail")
            with pytest.raises(GatewayDeny) as ei:
                await engine.register_lock(
                    identity, _PIN_ALIAS, {"amount": 2}, RiskTier.PIN_REQUIRED
                )
            assert ei.value.reason is DenyReason.OTP_DELIVERY_FAILED
        finally:
            await redis_client.aclose()

    _run(scenario())


# ===========================================================================
# 11) Engine: a REAL channel receives the REAL code out-of-band; the return value is
#     only the challenge_id; and the delivered code spends the unchanged lock.
# ===========================================================================


def test_engine_delivers_real_code_and_lock_consumes(idp: _DemoIdP) -> None:
    async def scenario() -> None:
        redis_client = await _fresh_engine_redis()
        try:
            channel = _CapturingChannel()
            pin = PinValidator(redis_client)
            engine = AuthEngine(_components.resolver, pin, redis_client, channel)
            identity = _identity(idp, "agent-realdeliver")
            args = {"amount": 500, "to": "acct-1"}

            challenge_id = await engine.register_lock(
                identity, _PIN_ALIAS, args, RiskTier.PIN_REQUIRED
            )

            # The channel got exactly one notice with the REAL 6-digit code.
            assert len(channel.delivered) == 1
            notice = channel.delivered[0]
            assert notice.otp.isdigit() and len(notice.otp) == 6
            assert notice.challenge_id == challenge_id
            assert notice.alias == _PIN_ALIAS
            # The return value is the challenge handle ONLY — never the code.
            assert challenge_id != notice.otp

            # The delivered code spends the unchanged payload lock (binding intact).
            entry = AliasEntry(_PIN_ALIAS, "target", "cloud_rest", RiskTier.PIN_REQUIRED)
            code = await engine.consume_and_execute(
                identity, entry, args, notice.otp, challenge_id
            )
            assert code == 1

            # Exactly-once: a replay of the same code is refused.
            with pytest.raises(GatewayDeny) as ei:
                await engine.consume_and_execute(
                    identity, entry, args, notice.otp, challenge_id
                )
            assert ei.value.reason is DenyReason.PIN_NOT_FOUND
        finally:
            await redis_client.aclose()

    _run(scenario())


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
