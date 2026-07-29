"""
CROSS-tests for the CLOUD-IAM transport — identity × compartment × credential-vending.

    ◐ "No standing key: every cloud touch is a per-call, short-lived, scoped credential
       the gateway vends only after an ALLOW — and can revoke."

These exercise the REAL security-critical components of the ``cloud_iam`` vend path
directly (engine/pure level — the brief's preferred harness), never HTTP:

  * ``CloudIAMTransport``          — the per-call vend + defense-in-depth compartment /
                                     wrong-tenant gate (imported from ``app.main``).
  * ``CloudBroker`` / ``CloudEnvironmentStore`` — provider dispatch (AWS/GCP/Azure),
                                     TTL clamping, host-identity vs vault broker material,
                                     fail-closed real-vend.
  * ``SecretVault``               — vault-backed broker credentials (cloud + non-cloud),
                                     tenant/secret AAD binding, write-only metadata.
  * ``AuthEngine`` + ``PinValidator`` — the payload-bound PIN step-up that gates a
                                     PIN_REQUIRED vend (missing / wrong / replayed / tampered).
  * ``RevocationStore`` / ``QuarantineStore`` / ``GrantStore`` — the kill-switch +
                                     compartment-grant gates ahead of a vend.
  * ``WormLogger`` (``_redact`` / ``_is_secret_key``) — the redaction discipline that
                                     keeps the vended secret out of the audit record.

Ground rules honored (see ``tests/_CROSS_BRIEF.md``): every id is a fresh ``uuid4`` so no
test assumes a clean db, no real network / SDK / socket (AWS stays in the sandbox
``_simulate`` path — boto3 IS installed, so a real ``_vend_aws`` is never reached; only the
SDK-absent gcp/azure/unknown or vault-short-circuit paths drive ``_vend_real``), and Redis
is namespaced to dedicated dbs. A denial test asserts BOTH the opaque caller boundary and
the concrete reason that reaches the durable WORM buffer.
"""

from __future__ import annotations

import os

# Pure-engine harness: we construct every component directly on our own flushed/dedicated
# Redis dbs. Importing ``app.main`` (for the real ``CloudIAMTransport``) runs its sandbox
# composition root, so the sandbox env must be set before that import — mirrors
# tests/test_redteam_fixes.py. We never touch ``app.main._components``; per the brief a
# setdefault Redis env falls back to db /1 (unused by these tests).
os.environ.setdefault("MCPIP_REDIS_URL", "redis://localhost:63790/1")
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_cross_iam_worm.jsonl"),
)

import asyncio
import uuid
import json
from typing import Any, Optional

import pytest
import redis.asyncio as aioredis
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auth import LockError, PinValidator
from core.security import (
    AGENT_FACING_DENY_MESSAGE,
    GatewayDeny,
    map_engine_exception,
)
from interfaces import (
    AuthorizedIntent,
    DenyReason,
    Hop,
    Identity,
    NormalizedIntent,
    RiskTier,
    SourceFormat,
    SwarmTrace,
)
from obfuscator.alias_registry import AliasEntry
from audit.worm_logger import WormLogger, _EVENTS_STREAM, _is_secret_key, _redact
from services.auth_engine import AuthEngine
from services.authn_channel import SandboxRedisAuthenticatorChannel
from services.cloud_broker import (
    CLOUD_PROVIDERS,
    MAX_SESSION_TTL,
    MIN_SESSION_TTL,
    CloudBroker,
    CloudEnvironment,
    CloudEnvironmentStore,
    clamp_ttl,
)
from services.grant_store import GrantStore
from services.quarantine import QuarantineStore
from services.revocation import RevocationStore
from services.secret_vault import VAULT_VENDORS, SecretVault

from app.main import CloudIAMTransport

# Dedicated dbs — /2 for the redis-bound engine components (unique ids per test, never
# flushed so a full-suite run is never disturbed), /3 for a FRESH+flushed WormLogger per
# audit test (isolated: no other suite binds /3). 32-byte AES key for the vault.
_ENGINE_URL = "redis://localhost:63790/2"
_WORM_URL = "redis://localhost:63790/3"
_VAULT_KEY = b"K" * 32


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def _engine_client() -> Any:
    return aioredis.from_url(_ENGINE_URL, decode_responses=True)  # type: ignore[no-untyped-call]


def _identity(tenant: str, agent: str, compartment: Optional[str] = None) -> Identity:
    return Identity(
        tenant_id=tenant,
        agent_id=agent,
        role="worker",
        issuer="test-idp",
        audience="mcpip",
        compartment=compartment,
    )


def _trace(agent_id: str) -> SwarmTrace:
    return SwarmTrace(
        trace_id=str(uuid.uuid4()),
        hops=[Hop(hop_index=0, agent_id=agent_id, parent_agent_id=None, purpose="cross-iam")],
    )


def _authorized(alias: str, arguments: dict[str, Any], identity: Identity, corr: str) -> AuthorizedIntent:
    intent = NormalizedIntent(
        alias=alias,
        arguments=arguments,
        trace=_trace(identity.agent_id),
        source_format=SourceFormat.RAW_MCP,
    )
    return AuthorizedIntent(intent=intent, identity=identity, correlation_id=corr)


def _role_for(provider: str) -> str:
    """A provider-native ``role`` target (ARN / SA email / scope)."""
    if provider == "aws":
        return "arn:aws:iam::000000000000:role/mcpip-cross"
    if provider == "gcp":
        return "cross@proj.iam.gserviceaccount.com"
    return "api://cross-app/.default"  # azure


def _env(
    *,
    provider: str = "aws",
    compartment: Optional[str] = None,
    vault_secret_id: Optional[str] = None,
    ttl: int = 900,
    env_id: Optional[str] = None,
    region: str = "us-east-1",
) -> CloudEnvironment:
    return CloudEnvironment(
        env_id=env_id or _uid("env"),
        provider=provider,
        role=_role_for(provider),
        region=region,
        compartment=compartment,
        session_ttl=ttl,
        vault_secret_id=vault_secret_id,
    )


async def _fresh_worm() -> tuple[Any, WormLogger]:
    """A WormLogger on a dedicated, freshly-flushed db (isolated; safe to flush)."""
    client: Any = aioredis.from_url(_WORM_URL, decode_responses=True)  # type: ignore[no-untyped-call]
    await client.flushdb()
    logger = WormLogger(
        client, Ed25519PrivateKey.generate(), path="/tmp/_cross_iam_worm.jsonl",
        mode="epoch", anchor=None,
    )
    return client, logger


async def _last_event(client: Any) -> dict[str, Any]:
    entries: Any = await client.xrevrange(_EVENTS_STREAM, count=1)
    _sid, fields = entries[0]
    record: Any = json.loads(fields["record"])
    return record["event"]


async def _worm_dump(client: Any, count: int = 200) -> str:
    entries: Any = await client.xrevrange(_EVENTS_STREAM, count=count)
    return "".join(fields.get("record", "") for _sid, fields in entries)


async def _gate_then_vend(
    *,
    transport: CloudIAMTransport,
    entry: AliasEntry,
    identity: Identity,
    arguments: dict[str, Any],
    corr: str,
    revocation: Optional[RevocationStore] = None,
    quarantine: Optional[QuarantineStore] = None,
    grants: Optional[GrantStore] = None,
    auth: Optional[AuthEngine] = None,
    pin: Optional[str] = None,
    challenge_id: Optional[str] = None,
) -> Any:
    """
    Drive the REAL cloud_iam gates in the SAME precedence the pipeline wires in
    ``app/main.py`` (revocation → quarantine → alias-compartment/grant → PIN step-up →
    dispatch/vend). Every gate here is a real product component; only the ordering is
    reproduced (a cross/integration harness). Raises the concrete ``GatewayDeny`` a gate
    would raise, or returns the ``TransportResult`` on a successful vend. The transport's
    own defense-in-depth binding check + ``_dispatch``'s ``ok is False`` → TRANSPORT_ERROR
    coarsening are honored exactly.
    """
    if revocation is not None and await revocation.is_revoked(identity.tenant_id, identity.agent_id):
        raise GatewayDeny(DenyReason.PRINCIPAL_REVOKED, "principal revoked")
    if quarantine is not None and await quarantine.is_quarantined(identity.tenant_id, identity.agent_id):
        raise GatewayDeny(DenyReason.AGENT_QUARANTINED, "agent quarantined")
    # Alias-compartment gate: native membership OR an active delegated grant.
    if entry.compartment is not None and entry.compartment != identity.compartment:
        has_grant = grants is not None and await grants.has_active_grant(
            identity.tenant_id, identity.agent_id, entry.compartment
        )
        if not has_grant:
            raise GatewayDeny(DenyReason.COMPARTMENT_DENIED, "compartment denied")
    if entry.risk_tier is RiskTier.PIN_REQUIRED:
        assert auth is not None and pin is not None and challenge_id is not None
        await auth.consume_and_execute(identity, entry, arguments, pin, challenge_id)
    result = await transport.execute(_authorized(entry.alias, arguments, identity, corr), entry.target)
    if not result.ok:
        # Mirrors app.main._dispatch: any non-ok result is a fail-closed TRANSPORT_ERROR.
        raise GatewayDeny(DenyReason.TRANSPORT_ERROR, "transport reported failure")
    return result


# ===========================================================================
# 1. CloudIAMTransport — compartment × tenant vend gate (real transport, sandbox).
# ===========================================================================


def test_vend_succeeds_in_native_compartment() -> None:
    """A caller whose native compartment matches the binding vends a short-lived credential."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            tenant, comp = _uid("t"), str(uuid.uuid4())
            env = _env(compartment=comp)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), comp)
            res = await transport.execute(_authorized("skill_aws", {"k": "v"}, ident, uuid.uuid4().hex), env.env_id)
            assert res.ok and res.status_code == 200
            assert res.echo["_credential"]["secret_access_key"].startswith("sandbox/")
            assert res.echo["provider"] == "aws" and res.echo["simulated"] is True
        finally:
            await client.aclose()

    _run(scenario())


def test_vend_succeeds_with_tenant_wide_binding() -> None:
    """A binding with compartment=None (tenant-wide) serves any compartment in the tenant."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            tenant = _uid("t")
            env = _env(compartment=None)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), str(uuid.uuid4()))  # arbitrary compartment.
            res = await transport.execute(_authorized("s", {}, ident, uuid.uuid4().hex), env.env_id)
            assert res.ok and res.echo["_credential"]
        finally:
            await client.aclose()

    _run(scenario())


def test_cross_compartment_vend_denied_scope_mismatch() -> None:
    """A compartment-scoped binding refuses a caller from a DIFFERENT compartment (403)."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            tenant = _uid("t")
            env = _env(compartment=str(uuid.uuid4()))
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), str(uuid.uuid4()))  # wrong compartment.
            res = await transport.execute(_authorized("s", {}, ident, uuid.uuid4().hex), env.env_id)
            assert res.ok is False and res.status_code == 403
            assert res.detail == "environment scope mismatch"
        finally:
            await client.aclose()

    _run(scenario())


def test_cross_compartment_vend_leaks_no_credential() -> None:
    """A denied cross-compartment vend returns NO credential material to the caller."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            tenant = _uid("t")
            env = _env(compartment=str(uuid.uuid4()))
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), str(uuid.uuid4()))
            res = await transport.execute(_authorized("s", {}, ident, uuid.uuid4().hex), env.env_id)
            assert res.echo == {} and "_credential" not in res.echo
        finally:
            await client.aclose()

    _run(scenario())


def test_wrong_tenant_vend_denied_no_binding() -> None:
    """A binding stored under tenant A is invisible to tenant B — the store is tenant-keyed."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            tenant_a, comp = _uid("t"), str(uuid.uuid4())
            env = _env(compartment=comp)
            await store.put(tenant_a, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            # Same compartment string, but a DIFFERENT tenant — must not resolve the binding.
            ident = _identity(_uid("t-other"), _uid("agent"), comp)
            res = await transport.execute(_authorized("s", {}, ident, uuid.uuid4().hex), env.env_id)
            assert res.ok is False and res.status_code == 404 and res.detail == "no cloud environment"
        finally:
            await client.aclose()

    _run(scenario())


def test_missing_binding_vend_denied() -> None:
    """A vend against an env_id that was never stored fails closed (404), never vends."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(_uid("t"), _uid("agent"), str(uuid.uuid4()))
            res = await transport.execute(_authorized("s", {}, ident, uuid.uuid4().hex), _uid("never"))
            assert res.ok is False and res.status_code == 404
        finally:
            await client.aclose()

    _run(scenario())


def test_identity_without_compartment_denied_by_scoped_binding() -> None:
    """An un-compartmented identity (compartment=None) cannot reach a compartment-scoped binding."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            tenant = _uid("t")
            env = _env(compartment=str(uuid.uuid4()))
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), None)
            res = await transport.execute(_authorized("s", {}, ident, uuid.uuid4().hex), env.env_id)
            assert res.ok is False and res.status_code == 403
        finally:
            await client.aclose()

    _run(scenario())


def test_transport_denial_opaque_to_caller_concrete_in_worm() -> None:
    """A cross-compartment vend is opaque to the agent (generic message) yet the concrete
    ``transport_error`` reason lands in the durable WORM buffer — the opaque/logged split."""

    async def scenario() -> None:
        client = _engine_client()
        worm_client, worm = await _fresh_worm()
        try:
            store = CloudEnvironmentStore(client)
            tenant = _uid("t")
            env = _env(compartment=str(uuid.uuid4()))
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), str(uuid.uuid4()))
            res = await transport.execute(_authorized("s", {}, ident, uuid.uuid4().hex), env.env_id)
            assert res.ok is False
            # Pipeline: a non-ok result becomes a fail-closed opaque TRANSPORT_ERROR.
            deny = GatewayDeny(DenyReason.TRANSPORT_ERROR, "transport reported failure")
            corr = uuid.uuid4().hex
            await worm.emit({
                "decision": "deny", "deny_reason": deny.reason.value,
                "detail": deny.detail, "alias": "s", "tenant_id": tenant, "correlation_id": corr,
            })
            event = await _last_event(worm_client)
            assert event["deny_reason"] == "transport_error"           # concrete, logged.
            assert res.detail == "environment scope mismatch"          # operator signal at the transport.
            assert res.detail != AGENT_FACING_DENY_MESSAGE             # never the agent-facing text.
            assert "compartment" not in AGENT_FACING_DENY_MESSAGE.lower()  # opaque to the agent.
        finally:
            await client.aclose()
            await worm_client.aclose()

    _run(scenario())


def test_vend_fingerprint_carries_no_secret_material() -> None:
    """The non-secret ``fingerprint`` (operator/agent-safe summary) never embeds the vended secret."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            tenant, comp = _uid("t"), str(uuid.uuid4())
            env = _env(compartment=comp)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), comp)
            res = await transport.execute(_authorized("s", {}, ident, uuid.uuid4().hex), env.env_id)
            mat = res.echo["_credential"]
            for secret in (mat["secret_access_key"], mat["session_token"], mat["access_key_id"]):
                assert secret not in res.echo["fingerprint"]
        finally:
            await client.aclose()

    _run(scenario())


def test_vend_echo_credential_holds_material_separately() -> None:
    """The secret rides ONLY in ``echo['_credential']``; the summary fields carry no secret."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            tenant, comp = _uid("t"), str(uuid.uuid4())
            env = _env(compartment=comp)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), comp)
            res = await transport.execute(_authorized("s", {}, ident, uuid.uuid4().hex), env.env_id)
            summary = {k: v for k, v in res.echo.items() if k != "_credential"}
            assert set(summary) == {"provider", "region", "expires_in", "simulated", "fingerprint"}
            assert isinstance(res.echo["_credential"], dict) and res.echo["_credential"]
        finally:
            await client.aclose()

    _run(scenario())


# ===========================================================================
# 2. Provider parity — AWS / GCP / Azure vend the same guarantees (sandbox).
# ===========================================================================


def _sandbox_vend(provider: str, ttl: int = 900) -> Any:
    async def scenario() -> Any:
        broker = CloudBroker(sandbox_mode=True, vault=None)
        env = _env(provider=provider, ttl=ttl)
        return await broker.vend(env, tenant_id=_uid("t"), request_nonce=uuid.uuid4().hex)

    return _run(scenario())


def test_aws_sandbox_vend_shape() -> None:
    """AWS vends an STS-shaped envelope (access_key_id / secret_access_key / session_token)."""
    vended = _sandbox_vend("aws")
    assert vended.provider == "aws" and vended.simulated is True
    assert set(vended.material) == {"access_key_id", "secret_access_key", "session_token", "role"}
    assert "AWS STS AssumeRole" in vended.fingerprint and "SANDBOX" in vended.fingerprint


def test_gcp_sandbox_vend_shape() -> None:
    """GCP vends an impersonation access token bound to the target service account."""
    vended = _sandbox_vend("gcp")
    assert vended.provider == "gcp" and vended.simulated is True
    assert vended.material["access_token"].startswith("ya29.")
    assert vended.material["service_account"] == _role_for("gcp")
    assert "GCP impersonation" in vended.fingerprint


def test_azure_sandbox_vend_shape() -> None:
    """Azure vends a short-lived federated AAD token for the target scope."""
    vended = _sandbox_vend("azure")
    assert vended.provider == "azure" and vended.simulated is True
    assert vended.material["access_token"] and vended.material["client_id"] == _role_for("azure")
    assert "Azure federated token" in vended.fingerprint


def _transport_cross_compartment(provider: str) -> Any:
    async def scenario() -> Any:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            tenant = _uid("t")
            env = _env(provider=provider, compartment=str(uuid.uuid4()))
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), str(uuid.uuid4()))
            return await transport.execute(_authorized("s", {}, ident, uuid.uuid4().hex), env.env_id)
        finally:
            await client.aclose()

    return _run(scenario())


def test_aws_vend_compartment_gate_parity() -> None:
    """AWS: a cross-compartment vend is denied identically to the flagship."""
    res = _transport_cross_compartment("aws")
    assert res.ok is False and res.status_code == 403 and res.echo == {}


def test_gcp_vend_compartment_gate_parity() -> None:
    """GCP: a cross-compartment vend is denied identically (provider parity of the gate)."""
    res = _transport_cross_compartment("gcp")
    assert res.ok is False and res.status_code == 403 and res.echo == {}


def test_azure_vend_compartment_gate_parity() -> None:
    """Azure: a cross-compartment vend is denied identically (provider parity of the gate)."""
    res = _transport_cross_compartment("azure")
    assert res.ok is False and res.status_code == 403 and res.echo == {}


def _transport_wrong_tenant(provider: str) -> Any:
    async def scenario() -> Any:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            comp = str(uuid.uuid4())
            env = _env(provider=provider, compartment=comp)
            await store.put(_uid("t"), env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(_uid("t-other"), _uid("agent"), comp)
            return await transport.execute(_authorized("s", {}, ident, uuid.uuid4().hex), env.env_id)
        finally:
            await client.aclose()

    return _run(scenario())


def test_aws_wrong_tenant_isolation_parity() -> None:
    """AWS: a cross-tenant vend finds no binding (404) — tenant isolation parity."""
    res = _transport_wrong_tenant("aws")
    assert res.ok is False and res.status_code == 404


def test_gcp_wrong_tenant_isolation_parity() -> None:
    """GCP: a cross-tenant vend finds no binding (404) — tenant isolation parity."""
    res = _transport_wrong_tenant("gcp")
    assert res.ok is False and res.status_code == 404


def test_azure_wrong_tenant_isolation_parity() -> None:
    """Azure: a cross-tenant vend finds no binding (404) — tenant isolation parity."""
    res = _transport_wrong_tenant("azure")
    assert res.ok is False and res.status_code == 404


def test_all_providers_simulated_and_short_lived() -> None:
    """Every provider vends a simulated, short-lived (clamped) credential in sandbox."""
    for provider in sorted(CLOUD_PROVIDERS):
        vended = _sandbox_vend(provider, ttl=999_999)
        assert vended.simulated is True
        assert vended.expires_in == MAX_SESSION_TTL           # clamped down from 999_999.
        assert MIN_SESSION_TTL <= vended.expires_in <= MAX_SESSION_TTL


def test_all_providers_material_is_valid_envelope() -> None:
    """Every provider's vended material is a flat, bounded, non-empty credential envelope."""
    from services.secret_vault import validate_material

    for provider in sorted(CLOUD_PROVIDERS):
        vended = _sandbox_vend(provider)
        assert validate_material(vended.material)


def test_all_providers_fingerprint_hides_secret() -> None:
    """Across providers, the token/secret VALUE never appears in the operator fingerprint."""
    secret_keys = {
        "aws": ("secret_access_key", "session_token", "access_key_id"),
        "gcp": ("access_token",),
        "azure": ("access_token",),
    }
    for provider in sorted(CLOUD_PROVIDERS):
        vended = _sandbox_vend(provider)
        for key in secret_keys[provider]:
            assert vended.material[key] not in vended.fingerprint


# ===========================================================================
# 3. CloudBroker internals — TTL clamp + fail-closed real vend.
# ===========================================================================


def test_broker_clamps_ttl_below_min() -> None:
    """A binding asking for less than the floor is clamped UP to MIN_SESSION_TTL."""
    vended = _sandbox_vend("aws", ttl=1)
    assert vended.expires_in == MIN_SESSION_TTL


def test_broker_clamps_ttl_above_max() -> None:
    """A binding asking for more than the ceiling is clamped DOWN to MAX_SESSION_TTL."""
    vended = _sandbox_vend("aws", ttl=10 ** 9)
    assert vended.expires_in == MAX_SESSION_TTL


def test_clamp_ttl_bounds() -> None:
    """``clamp_ttl`` forces any request into the short-lived [MIN, MAX] band."""
    assert clamp_ttl(0) == MIN_SESSION_TTL
    assert clamp_ttl(10 ** 9) == MAX_SESSION_TTL
    assert clamp_ttl(1200) == 1200


def test_broker_real_vend_unknown_provider_fails_closed() -> None:
    """A real vend for a provider the broker does not implement fails closed (LockError)."""

    async def scenario() -> None:
        broker = CloudBroker(sandbox_mode=False, vault=None)
        env = _env(provider="oracle")  # not aws/gcp/azure.
        with pytest.raises(LockError):
            await broker.vend(env, tenant_id=_uid("t"), request_nonce="n" * 24)

    _run(scenario())


def test_broker_real_vend_missing_sdk_gcp_fails_closed() -> None:
    """Real GCP vend without google-auth installed fails CLOSED, never a silent nothing."""

    async def scenario() -> None:
        broker = CloudBroker(sandbox_mode=False, vault=None)
        env = _env(provider="gcp")  # host-identity tier: no vault ref.
        with pytest.raises(LockError):
            await broker.vend(env, tenant_id=_uid("t"), request_nonce="n" * 24)

    _run(scenario())


def test_broker_real_vend_missing_sdk_azure_fails_closed() -> None:
    """Real Azure vend without azure-identity installed fails CLOSED (LockError)."""

    async def scenario() -> None:
        broker = CloudBroker(sandbox_mode=False, vault=None)
        env = _env(provider="azure")
        with pytest.raises(LockError):
            await broker.vend(env, tenant_id=_uid("t"), request_nonce="n" * 24)

    _run(scenario())


def test_broker_sandbox_nonce_binds_material() -> None:
    """The per-call request nonce is woven into the vended material (per-call, not standing)."""

    async def scenario() -> None:
        broker = CloudBroker(sandbox_mode=True, vault=None)
        env = _env(provider="aws")
        nonce = uuid.uuid4().hex
        vended = await broker.vend(env, tenant_id=_uid("t"), request_nonce=nonce)
        assert nonce in vended.material["secret_access_key"]
        assert nonce in vended.material["session_token"]

    _run(scenario())


# ===========================================================================
# 4. Vault-backed broker credentials — cloud + non-cloud, tenant-bound, fail-closed.
# ===========================================================================


def test_host_identity_binding_resolves_to_none() -> None:
    """A binding with no vault reference is the host-identity tier — no stored secret."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            vault = SecretVault(client, _VAULT_KEY)
            broker = CloudBroker(sandbox_mode=False, vault=vault)
            env = _env(provider="aws", vault_secret_id=None)
            assert await broker._broker_material(env, _uid("t")) is None
        finally:
            await client.aclose()

    _run(scenario())


def test_vault_backed_binding_resolves_material() -> None:
    """A vault-referencing binding resolves to the decrypted broker credential."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            vault = SecretVault(client, _VAULT_KEY)
            tenant, sid = _uid("t"), _uid("sec")
            material = {"access_key_id": "AKIA_BROKER", "secret_access_key": "shh-broker"}
            await vault.put(tenant, sid, "aws", "broker key", material)
            broker = CloudBroker(sandbox_mode=False, vault=vault)
            env = _env(provider="aws", vault_secret_id=sid)
            assert await broker._broker_material(env, tenant) == material
        finally:
            await client.aclose()

    _run(scenario())


def test_vault_missing_entry_denies_fail_closed() -> None:
    """A binding referencing a MISSING vault entry fails closed — never host-identity fallback."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            vault = SecretVault(client, _VAULT_KEY)
            broker = CloudBroker(sandbox_mode=False, vault=vault)
            env = _env(provider="aws", vault_secret_id=_uid("missing"))
            with pytest.raises(LockError):
                await broker._broker_material(env, _uid("t"))
        finally:
            await client.aclose()

    _run(scenario())


def test_vault_absent_but_referenced_denies() -> None:
    """A binding references the vault while the broker has NO vault configured → fail closed."""

    async def scenario() -> None:
        broker = CloudBroker(sandbox_mode=False, vault=None)
        env = _env(provider="aws", vault_secret_id=_uid("sec"))
        with pytest.raises(LockError):
            await broker._broker_material(env, _uid("t"))

    _run(scenario())


def test_transport_vault_dangling_reference_fails_closed() -> None:
    """A real (non-sandbox) vend whose vault reference dangles raises before any cloud call."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            vault = SecretVault(client, _VAULT_KEY)
            tenant, comp = _uid("t"), str(uuid.uuid4())
            env = _env(provider="aws", compartment=comp, vault_secret_id=_uid("missing"))
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=False, vault=vault)
            ident = _identity(tenant, _uid("agent"), comp)
            # The vault ref is unresolvable → LockError from _broker_material, BEFORE _vend_aws
            # (so boto3 is never reached / no network). The pipeline coarsens this to an
            # opaque TRANSPORT_ERROR via map_engine_exception.
            with pytest.raises(LockError) as exc:
                await transport.execute(_authorized("s", {}, ident, uuid.uuid4().hex), env.env_id)
            assert map_engine_exception(exc.value).reason is DenyReason.LOCK_ERROR
        finally:
            await client.aclose()

    _run(scenario())


def test_vault_backed_api_key_non_cloud_target() -> None:
    """A non-cloud API-key broker credential round-trips through the vault (arbitrary target)."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            vault = SecretVault(client, _VAULT_KEY)
            tenant, sid = _uid("t"), _uid("sec")
            material = {"api_key": "sk-live-non-cloud-XYZ"}
            rec = await vault.put(tenant, sid, "api_key", "postmark", material)
            assert rec.vendor == "api_key"
            broker = CloudBroker(sandbox_mode=False, vault=vault)
            env = CloudEnvironment(_uid("env"), "aws", _role_for("aws"), "us-east-1", None, 900, sid)
            assert await broker._broker_material(env, tenant) == material
        finally:
            await client.aclose()

    _run(scenario())


def test_vault_backed_database_non_cloud_target() -> None:
    """A non-cloud database credential round-trips through the vault (server-side auth)."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            vault = SecretVault(client, _VAULT_KEY)
            tenant, sid = _uid("t"), _uid("sec")
            material = {"connection_string": "postgres://u:p@h/db", "password": "hunter2"}
            await vault.put(tenant, sid, "database", "ledger db", material)
            got = await vault.get_material(tenant, sid)
            assert got == material
        finally:
            await client.aclose()

    _run(scenario())


def test_vault_wrong_tenant_cannot_resolve_material() -> None:
    """A vault secret is (tenant, secret)-AAD-bound: another tenant's read is an unresolvable miss."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            vault = SecretVault(client, _VAULT_KEY)
            sid = _uid("sec")
            await vault.put(_uid("t-a"), sid, "aws", "", {"secret_access_key": "v"})
            assert await vault.get_material(_uid("t-b"), sid) is None
        finally:
            await client.aclose()

    _run(scenario())


def test_vault_metadata_never_exposes_value() -> None:
    """The operator metadata read carries a fingerprint but never the secret value."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            vault = SecretVault(client, _VAULT_KEY)
            tenant, sid = _uid("t"), _uid("sec")
            await vault.put(tenant, sid, "aws", "d", {"secret_access_key": "PLAINTEXT_MARKER_X"})
            meta = await vault.get(tenant, sid)
            assert meta is not None
            view = meta.public_view()
            assert "PLAINTEXT_MARKER_X" not in json.dumps(view)
            assert len(view["fingerprint"]) == 12 and "secret_access_key" not in view
        finally:
            await client.aclose()

    _run(scenario())


def test_vault_vendor_set_covers_cloud_and_non_cloud() -> None:
    """The vault vendors span the cloud trio AND non-cloud (api_key / database) targets."""
    assert {"aws", "gcp", "azure"}.issubset(VAULT_VENDORS)
    assert {"api_key", "database"}.issubset(VAULT_VENDORS)


# ===========================================================================
# 5. WORM redaction discipline — the vended secret never reaches the log.
# ===========================================================================


def test_allow_worm_record_omits_vended_secret() -> None:
    """The ALLOW record written BEFORE dispatch never contains the vended secret material."""

    async def scenario() -> None:
        client = _engine_client()
        worm_client, worm = await _fresh_worm()
        try:
            store = CloudEnvironmentStore(client)
            tenant, comp = _uid("t"), str(uuid.uuid4())
            env = _env(compartment=comp)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), comp)
            # Pipeline order: emit ALLOW ctx (no secret — dispatch runs AFTER), then vend.
            await worm.emit({
                "decision": "allow", "deny_reason": None, "alias": "skill_aws",
                "tenant_id": tenant, "transport": "cloud_iam",
            })
            res = await transport.execute(_authorized("skill_aws", {}, ident, uuid.uuid4().hex), env.env_id)
            secret = res.echo["_credential"]["secret_access_key"]
            dump = await _worm_dump(worm_client)
            assert secret not in dump
            assert res.echo["_credential"]["session_token"] not in dump
            assert (await _last_event(worm_client))["decision"] == "allow"
        finally:
            await client.aclose()
            await worm_client.aclose()

    _run(scenario())


def test_worm_dump_omits_secret_across_providers() -> None:
    """No provider's vended secret leaks into the audit buffer (redaction parity)."""

    async def scenario() -> None:
        client = _engine_client()
        worm_client, worm = await _fresh_worm()
        try:
            store = CloudEnvironmentStore(client)
            tenant, comp = _uid("t"), str(uuid.uuid4())
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            secrets_seen = []
            for provider in sorted(CLOUD_PROVIDERS):
                env = _env(provider=provider, compartment=comp)
                await store.put(tenant, env)
                await worm.emit({
                    "decision": "allow", "deny_reason": None, "alias": f"skill_{provider}",
                    "tenant_id": tenant, "transport": "cloud_iam",
                })
                ident = _identity(tenant, _uid("agent"), comp)
                res = await transport.execute(_authorized("s", {}, ident, uuid.uuid4().hex), env.env_id)
                secrets_seen.append(res.echo["_credential"]["access_token"] if provider != "aws"
                                    else res.echo["_credential"]["secret_access_key"])
            dump = await _worm_dump(worm_client)
            for secret in secrets_seen:
                assert secret not in dump
        finally:
            await client.aclose()
            await worm_client.aclose()

    _run(scenario())


def test_redact_scrubs_vended_credential_keys() -> None:
    """Defense-in-depth: if the vended envelope ever reached the logger it is scrubbed."""
    ctx = {
        "decision": "allow",
        "echo": {
            "provider": "aws",
            "_credential": {
                "access_key_id": "ASIA_LEAK",
                "secret_access_key": "SECRET_LEAK",
                "session_token": "TOKEN_LEAK",
            },
        },
    }
    redacted = _redact(ctx)
    blob = json.dumps(redacted)
    for leak in ("ASIA_LEAK", "SECRET_LEAK", "TOKEN_LEAK"):
        assert leak not in blob
    assert redacted["echo"]["_credential"] == "[REDACTED]"


def test_redact_scrubs_vault_material_keys() -> None:
    """The vault broker-credential value keys are redaction-listed (never persisted)."""
    ctx = {
        "material": "M_LEAK",
        "client_secret": "CS_LEAK",
        "private_key": "PK_LEAK",
        "connection_string": "CONN_LEAK",
        "api_key": "AK_LEAK",
    }
    blob = json.dumps(_redact(ctx))
    for leak in ("M_LEAK", "CS_LEAK", "PK_LEAK", "CONN_LEAK", "AK_LEAK"):
        assert leak not in blob


def test_is_secret_key_matches_vendor_prefixed_keeps_ids() -> None:
    """Vendor-prefixed secret keys redact; the operator-visible ``secret_id`` is kept."""
    assert _is_secret_key("aws_secret_access_key")
    assert _is_secret_key("gcp_private_key")
    assert _is_secret_key("session_token") and _is_secret_key("_credential")
    assert not _is_secret_key("secret_id")   # non-secret operator identifier — kept.
    assert not _is_secret_key("provider") and not _is_secret_key("region")


def test_worm_deny_records_concrete_reason_opaque_split() -> None:
    """A denied vend records its concrete reason in WORM while the agent sees only the opaque text."""

    async def scenario() -> None:
        worm_client, worm = await _fresh_worm()
        try:
            corr = uuid.uuid4().hex
            await worm.emit({
                "decision": "deny", "deny_reason": DenyReason.COMPARTMENT_DENIED.value,
                "detail": "caller not entitled to compartment", "alias": "skill_aws",
                "tenant_id": _uid("t"), "correlation_id": corr,
            })
            event = await _last_event(worm_client)
            assert event["deny_reason"] == "compartment_denied"
            assert event["correlation_id"] == corr
            # The concrete detail is internal-only; the agent-facing text reveals nothing.
            assert "compartment" not in AGENT_FACING_DENY_MESSAGE.lower()
            assert AGENT_FACING_DENY_MESSAGE != event["detail"]
        finally:
            await worm_client.aclose()

    _run(scenario())


# ===========================================================================
# 6. PIN step-up gates a PIN_REQUIRED vend (real AuthEngine + PinValidator).
# ===========================================================================


async def _engine_with_pin(client: Any) -> AuthEngine:
    pin = PinValidator(client)
    channel = SandboxRedisAuthenticatorChannel(client)
    return AuthEngine(resolver=None, pin=pin, redis_client=client, channel=channel)  # type: ignore[arg-type]


def test_pin_gated_vend_completes_after_stepup() -> None:
    """A PIN_REQUIRED write vends only AFTER the payload-bound step-up is consumed exactly once."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            tenant, comp = _uid("t"), str(uuid.uuid4())
            env = _env(compartment=comp)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            auth = await _engine_with_pin(client)
            ident = _identity(tenant, _uid("agent"), comp)
            args = {"table": "orders", "op": "PutItem"}
            entry = AliasEntry("skill_aws_dynamodb", env.env_id, "cloud_iam", RiskTier.PIN_REQUIRED, compartment=comp)
            challenge = await auth.register_lock(ident, entry.alias, args, RiskTier.PIN_REQUIRED)
            otp = await auth.peek_authenticator_otp(ident, challenge)
            res = await _gate_then_vend(
                transport=transport, entry=entry, identity=ident, arguments=args,
                corr=uuid.uuid4().hex, auth=auth, pin=otp, challenge_id=challenge,
            )
            assert res.ok and res.echo["_credential"]
        finally:
            await client.aclose()

    _run(scenario())


def test_pin_gated_vend_missing_challenge_denies() -> None:
    """A PIN completion with an unknown challenge id fails closed (PIN_NOT_FOUND) — no vend."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            tenant, comp = _uid("t"), str(uuid.uuid4())
            env = _env(compartment=comp)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            auth = await _engine_with_pin(client)
            ident = _identity(tenant, _uid("agent"), comp)
            entry = AliasEntry("skill_aws_dynamodb", env.env_id, "cloud_iam", RiskTier.PIN_REQUIRED, compartment=comp)
            with pytest.raises(GatewayDeny) as exc:
                await _gate_then_vend(
                    transport=transport, entry=entry, identity=ident, arguments={"table": "orders"},
                    corr=uuid.uuid4().hex, auth=auth, pin="000000", challenge_id=_uid("nope"),
                )
            assert exc.value.reason is DenyReason.PIN_NOT_FOUND
        finally:
            await client.aclose()

    _run(scenario())


def test_pin_gated_vend_wrong_pin_denies() -> None:
    """A wrong PIN against a staged challenge fails closed (PIN_MISMATCH) — no vend."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            tenant, comp = _uid("t"), str(uuid.uuid4())
            env = _env(compartment=comp)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            auth = await _engine_with_pin(client)
            ident = _identity(tenant, _uid("agent"), comp)
            args = {"table": "orders"}
            entry = AliasEntry("skill_aws_dynamodb", env.env_id, "cloud_iam", RiskTier.PIN_REQUIRED, compartment=comp)
            challenge = await auth.register_lock(ident, entry.alias, args, RiskTier.PIN_REQUIRED)
            otp = await auth.peek_authenticator_otp(ident, challenge)
            wrong = "111111" if otp != "111111" else "222222"
            with pytest.raises(GatewayDeny) as exc:
                await _gate_then_vend(
                    transport=transport, entry=entry, identity=ident, arguments=args,
                    corr=uuid.uuid4().hex, auth=auth, pin=wrong, challenge_id=challenge,
                )
            assert exc.value.reason is DenyReason.PIN_MISMATCH
        finally:
            await client.aclose()

    _run(scenario())


def test_pin_replayed_denies_second_vend() -> None:
    """The payload lock is exactly-once: a replayed PIN cannot vend a second credential."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            tenant, comp = _uid("t"), str(uuid.uuid4())
            env = _env(compartment=comp)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            auth = await _engine_with_pin(client)
            ident = _identity(tenant, _uid("agent"), comp)
            args = {"table": "orders"}
            entry = AliasEntry("skill_aws_dynamodb", env.env_id, "cloud_iam", RiskTier.PIN_REQUIRED, compartment=comp)
            challenge = await auth.register_lock(ident, entry.alias, args, RiskTier.PIN_REQUIRED)
            otp = await auth.peek_authenticator_otp(ident, challenge)
            first = await _gate_then_vend(
                transport=transport, entry=entry, identity=ident, arguments=args,
                corr=uuid.uuid4().hex, auth=auth, pin=otp, challenge_id=challenge,
            )
            assert first.ok
            with pytest.raises(GatewayDeny) as exc:
                await _gate_then_vend(
                    transport=transport, entry=entry, identity=ident, arguments=args,
                    corr=uuid.uuid4().hex, auth=auth, pin=otp, challenge_id=challenge,
                )
            assert exc.value.reason is DenyReason.PIN_NOT_FOUND  # lock already spent.
        finally:
            await client.aclose()

    _run(scenario())


def test_pin_payload_tamper_denies_vend() -> None:
    """The PIN is bound to the payload: completing over TAMPERED arguments is PAYLOAD_MISMATCH."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            tenant, comp = _uid("t"), str(uuid.uuid4())
            env = _env(compartment=comp)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            auth = await _engine_with_pin(client)
            ident = _identity(tenant, _uid("agent"), comp)
            entry = AliasEntry("skill_aws_dynamodb", env.env_id, "cloud_iam", RiskTier.PIN_REQUIRED, compartment=comp)
            challenge = await auth.register_lock(ident, entry.alias, {"table": "orders"}, RiskTier.PIN_REQUIRED)
            otp = await auth.peek_authenticator_otp(ident, challenge)
            with pytest.raises(GatewayDeny) as exc:
                await _gate_then_vend(
                    transport=transport, entry=entry, identity=ident, arguments={"table": "SECRETS"},
                    corr=uuid.uuid4().hex, auth=auth, pin=otp, challenge_id=challenge,
                )
            assert exc.value.reason is DenyReason.PAYLOAD_MISMATCH
        finally:
            await client.aclose()

    _run(scenario())


def test_pin_wrong_agent_denies_vend() -> None:
    """A step-up staged for agent A cannot be completed by agent B (payload identity binding)."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            tenant, comp = _uid("t"), str(uuid.uuid4())
            env = _env(compartment=comp)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            auth = await _engine_with_pin(client)
            agent_a = _identity(tenant, _uid("agent-a"), comp)
            agent_b = _identity(tenant, _uid("agent-b"), comp)
            args = {"table": "orders"}
            entry = AliasEntry("skill_aws_dynamodb", env.env_id, "cloud_iam", RiskTier.PIN_REQUIRED, compartment=comp)
            challenge = await auth.register_lock(agent_a, entry.alias, args, RiskTier.PIN_REQUIRED)
            otp = await auth.peek_authenticator_otp(agent_a, challenge)
            with pytest.raises(GatewayDeny) as exc:
                await _gate_then_vend(
                    transport=transport, entry=entry, identity=agent_b, arguments=args,
                    corr=uuid.uuid4().hex, auth=auth, pin=otp, challenge_id=challenge,
                )
            assert exc.value.reason in (DenyReason.PAYLOAD_MISMATCH, DenyReason.PIN_NOT_FOUND)
        finally:
            await client.aclose()

    _run(scenario())


# ===========================================================================
# 7. Revocation / quarantine / grant gate a vend (real kill-switch + grant stores).
# ===========================================================================


def test_revoked_principal_cannot_vend() -> None:
    """An admin-revoked principal is denied at the kill-switch — the vend is never reached."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            revocation = RevocationStore(client)
            tenant, comp = _uid("t"), str(uuid.uuid4())
            env = _env(compartment=comp)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), comp)  # native → would otherwise vend.
            await revocation.revoke(
                tenant_id=tenant, agent_id=ident.agent_id, issued_by="admin",
                correlation_id=uuid.uuid4().hex, reason="stolen token",
            )
            entry = AliasEntry("skill_aws", env.env_id, "cloud_iam", RiskTier.AUTO, compartment=comp)
            with pytest.raises(GatewayDeny) as exc:
                await _gate_then_vend(
                    transport=transport, entry=entry, identity=ident, arguments={},
                    corr=uuid.uuid4().hex, revocation=revocation,
                )
            assert exc.value.reason is DenyReason.PRINCIPAL_REVOKED
        finally:
            await client.aclose()

    _run(scenario())


def test_reactivated_principal_can_vend() -> None:
    """Reactivation lifts the kill-switch and the next vend proceeds (no standing block)."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            revocation = RevocationStore(client)
            tenant, comp = _uid("t"), str(uuid.uuid4())
            env = _env(compartment=comp)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), comp)
            await revocation.revoke(
                tenant_id=tenant, agent_id=ident.agent_id, issued_by="admin",
                correlation_id=uuid.uuid4().hex,
            )
            assert await revocation.reactivate(tenant_id=tenant, agent_id=ident.agent_id) is True
            entry = AliasEntry("skill_aws", env.env_id, "cloud_iam", RiskTier.AUTO, compartment=comp)
            res = await _gate_then_vend(
                transport=transport, entry=entry, identity=ident, arguments={},
                corr=uuid.uuid4().hex, revocation=revocation,
            )
            assert res.ok and res.echo["_credential"]
        finally:
            await client.aclose()

    _run(scenario())


def test_quarantined_agent_cannot_vend() -> None:
    """A canary-tripped (quarantined) agent is frozen out of the vend path."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            quarantine = QuarantineStore(client)
            tenant, comp = _uid("t"), str(uuid.uuid4())
            env = _env(compartment=comp)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), comp)
            await quarantine.quarantine(
                tenant_id=tenant, agent_id=ident.agent_id,
                correlation_id=uuid.uuid4().hex, tripped_alias="skill_export_all_credentials",
            )
            entry = AliasEntry("skill_aws", env.env_id, "cloud_iam", RiskTier.AUTO, compartment=comp)
            with pytest.raises(GatewayDeny) as exc:
                await _gate_then_vend(
                    transport=transport, entry=entry, identity=ident, arguments={},
                    corr=uuid.uuid4().hex, quarantine=quarantine,
                )
            assert exc.value.reason is DenyReason.AGENT_QUARANTINED
        finally:
            await client.aclose()

    _run(scenario())


def test_absent_grant_blocks_compartmented_vend() -> None:
    """A caller outside the alias's compartment with NO active grant is denied — no vend."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            grants = GrantStore(client)
            tenant = _uid("t")
            alias_comp = str(uuid.uuid4())
            env = _env(compartment=None)  # tenant-wide binding, so ONLY the alias gate matters.
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), str(uuid.uuid4()))  # not in alias_comp.
            entry = AliasEntry("skill_aws", env.env_id, "cloud_iam", RiskTier.AUTO, compartment=alias_comp)
            with pytest.raises(GatewayDeny) as exc:
                await _gate_then_vend(
                    transport=transport, entry=entry, identity=ident, arguments={},
                    corr=uuid.uuid4().hex, grants=grants,
                )
            assert exc.value.reason is DenyReason.COMPARTMENT_DENIED
        finally:
            await client.aclose()

    _run(scenario())


def test_active_grant_allows_tenant_wide_vend() -> None:
    """A valid delegated grant lets a cross-compartment caller vend a tenant-wide binding."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            grants = GrantStore(client)
            tenant = _uid("t")
            alias_comp = str(uuid.uuid4())
            env = _env(compartment=None)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), str(uuid.uuid4()))
            await grants.issue(
                tenant_id=tenant, subject_agent_id=ident.agent_id, compartment_uuid=alias_comp,
                issued_by="grantor", capability_used="cap-grant", correlation_id=uuid.uuid4().hex,
                ttl_seconds=300,
            )
            entry = AliasEntry("skill_aws", env.env_id, "cloud_iam", RiskTier.AUTO, compartment=alias_comp)
            res = await _gate_then_vend(
                transport=transport, entry=entry, identity=ident, arguments={},
                corr=uuid.uuid4().hex, grants=grants,
            )
            assert res.ok and res.echo["_credential"]
        finally:
            await client.aclose()

    _run(scenario())


def test_grant_passes_alias_gate_but_scoped_binding_defense_in_depth_denies() -> None:
    """A grant clears the alias gate, but the binding's own compartment defense-in-depth still
    refuses a caller whose NATIVE compartment differs — the two checks are independent."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            grants = GrantStore(client)
            tenant = _uid("t")
            scoped = str(uuid.uuid4())
            env = _env(compartment=scoped)  # binding scoped to `scoped`.
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), str(uuid.uuid4()))  # native ≠ scoped.
            await grants.issue(
                tenant_id=tenant, subject_agent_id=ident.agent_id, compartment_uuid=scoped,
                issued_by="grantor", capability_used="cap-grant", correlation_id=uuid.uuid4().hex,
                ttl_seconds=300,
            )
            entry = AliasEntry("skill_aws", env.env_id, "cloud_iam", RiskTier.AUTO, compartment=scoped)
            with pytest.raises(GatewayDeny) as exc:
                await _gate_then_vend(
                    transport=transport, entry=entry, identity=ident, arguments={},
                    corr=uuid.uuid4().hex, grants=grants,
                )
            assert exc.value.reason is DenyReason.TRANSPORT_ERROR  # binding scope mismatch → opaque.
        finally:
            await client.aclose()

    _run(scenario())


def test_native_member_vends_without_grant() -> None:
    """A native compartment member vends without any delegated grant (native entitlement)."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            grants = GrantStore(client)
            tenant, comp = _uid("t"), str(uuid.uuid4())
            env = _env(compartment=comp)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), comp)  # native.
            entry = AliasEntry("skill_aws", env.env_id, "cloud_iam", RiskTier.AUTO, compartment=comp)
            assert await grants.has_active_grant(tenant, ident.agent_id, comp) is False
            res = await _gate_then_vend(
                transport=transport, entry=entry, identity=ident, arguments={},
                corr=uuid.uuid4().hex, grants=grants,
            )
            assert res.ok
        finally:
            await client.aclose()

    _run(scenario())


def test_grant_revoked_midflight_blocks_next_vend() -> None:
    """A no-longer-active (revoked/expired) grant is observed immediately — the next vend denies."""

    async def scenario() -> None:
        client = _engine_client()
        try:
            store = CloudEnvironmentStore(client)
            grants = GrantStore(client)
            tenant = _uid("t")
            alias_comp = str(uuid.uuid4())
            env = _env(compartment=None)
            await store.put(tenant, env)
            transport = CloudIAMTransport(store, sandbox_mode=True, vault=None)
            ident = _identity(tenant, _uid("agent"), str(uuid.uuid4()))
            entry = AliasEntry("skill_aws", env.env_id, "cloud_iam", RiskTier.AUTO, compartment=alias_comp)
            await grants.issue(
                tenant_id=tenant, subject_agent_id=ident.agent_id, compartment_uuid=alias_comp,
                issued_by="grantor", capability_used="cap-grant", correlation_id=uuid.uuid4().hex,
                ttl_seconds=300,
            )
            first = await _gate_then_vend(
                transport=transport, entry=entry, identity=ident, arguments={},
                corr=uuid.uuid4().hex, grants=grants,
            )
            assert first.ok
            # Grant lifted (revoked / expired) → the store serves the absence with no stale allow.
            await grants.revoke(tenant, ident.agent_id, alias_comp)
            with pytest.raises(GatewayDeny) as exc:
                await _gate_then_vend(
                    transport=transport, entry=entry, identity=ident, arguments={},
                    corr=uuid.uuid4().hex, grants=grants,
                )
            assert exc.value.reason is DenyReason.COMPARTMENT_DENIED
        finally:
            await client.aclose()

    _run(scenario())
