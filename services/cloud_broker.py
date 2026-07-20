"""
MCPIP V2 — Service: cloud IAM credential broker (the ``cloud_iam`` transport core).

    ◐ "The agent never holds a cloud key. Every cloud touch is a per-call,
       short-lived, scoped credential the gateway vends — and can revoke."

The monetizable control plane: instead of handing an autonomous agent a standing
AWS/GCP/Azure credential (a permanent blast radius), executing an authorized skill
VENDS a short-lived, scope-reduced session credential for exactly that call. The
agent proves only its MCPIP license; the gateway proves ITSELF to the cloud (its
host workload identity) and mints the ephemeral credential. Every vend is:

  * per-call authorized through the full pipeline (compartment + mandate + PIN),
  * scoped down to the environment's role (and, for writes, a session policy),
  * short-lived (minutes, not forever),
  * WORM-logged — and the vended secret is redacted from the log,
  * killable — stop the skill or revoke the principal and the next vend is denied.

NO STANDING SECRETS AT REST. A ``CloudEnvironment`` stores only a BINDING: which
role to assume, the region, the owning compartment, the session TTL — never an
access key. In production the gateway assumes the role with its own host identity
(instance profile / IRSA / workload-identity federation). In sandbox the broker
returns a clearly-marked FAKE credential envelope so the flow is demonstrable
end-to-end without real cloud.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

import redis.asyncio as redis
from redis.exceptions import RedisError

from auth import LockError
from services.secret_vault import SecretVault

_KEY_PREFIX = "mcpip:cloud_env:"
# Bound the number of cloud environments per tenant (binding config, not bulk).
MAX_ENVIRONMENTS = 128
# Providers the broker understands. AWS is the flagship; the others are declared so
# the binding model is provider-general (the console offers them, prod adds SDKs).
CLOUD_PROVIDERS = frozenset({"aws", "gcp", "azure"})
# Clamp a vended session's lifetime (seconds) — short-lived by construction.
MIN_SESSION_TTL = 300
MAX_SESSION_TTL = 3600


@dataclass(frozen=True)
class CloudEnvironment:
    """A binding — how a compartment reaches a cloud role. NEVER holds a secret."""

    env_id: str
    provider: str
    # The role/identity the gateway assumes for this environment. For AWS this is a
    # role ARN; for GCP a service-account email; for Azure a managed-identity client id.
    role: str
    region: str
    # The compartment UUID entitled to use this environment (None = tenant-wide).
    compartment: Optional[str]
    session_ttl: int
    # OPTIONAL reference (never a value) to a SecretVault entry the broker spends to
    # authenticate ITSELF for this environment's vend. None = the gateway's own host
    # workload identity (the recommended tier). The referenced material stays inside
    # the broker — it never crosses to an agent and never enters WORM.
    vault_secret_id: Optional[str] = None

    def public_view(self) -> dict[str, Any]:
        """Operator-visible fields — all non-secret (the vault field is a POINTER)."""
        return {
            "env_id": self.env_id,
            "provider": self.provider,
            "role": self.role,
            "region": self.region,
            "compartment": self.compartment,
            "session_ttl": self.session_ttl,
            "vault_secret_id": self.vault_secret_id,
        }


def clamp_ttl(ttl: int) -> int:
    """Force a session TTL into the short-lived band."""
    return max(MIN_SESSION_TTL, min(MAX_SESSION_TTL, ttl))


class CloudEnvironmentStore:
    """Redis-backed per-tenant cloud-environment bindings. Holds NO cloud secrets."""

    def __init__(self, redis_client: "redis.Redis") -> None:
        self._redis = redis_client

    @staticmethod
    def _key(tenant_id: str) -> str:
        return f"{_KEY_PREFIX}{tenant_id}"

    async def count(self, tenant_id: str) -> int:
        try:
            return int(await self._redis.hlen(self._key(tenant_id)))
        except RedisError:
            return 0

    async def put(self, tenant_id: str, env: CloudEnvironment) -> None:
        """Persist one binding. Fail-closed on transport error (never silent)."""
        payload = json.dumps(env.public_view(), separators=(",", ":"))
        try:
            await self._redis.hset(self._key(tenant_id), env.env_id, payload)
        except RedisError as exc:
            raise LockError("cloud-env transport failure during put") from exc

    async def remove(self, tenant_id: str, env_id: str) -> bool:
        try:
            removed: Any = await self._redis.hdel(self._key(tenant_id), env_id)
        except RedisError as exc:
            raise LockError("cloud-env transport failure during remove") from exc
        return int(removed) > 0

    async def get(self, tenant_id: str, env_id: str) -> Optional[CloudEnvironment]:
        try:
            raw: Any = await self._redis.hget(self._key(tenant_id), env_id)
        except RedisError:
            return None
        return _decode_env(env_id, raw)

    async def list_for_tenant(self, tenant_id: str) -> list[CloudEnvironment]:
        try:
            raw: Any = await self._redis.hgetall(self._key(tenant_id))
        except RedisError:
            return []
        out: list[CloudEnvironment] = []
        for k, v in (raw or {}).items():
            env_id = k.decode() if isinstance(k, bytes) else str(k)
            env = _decode_env(env_id, v)
            if env is not None:
                out.append(env)
        return out


def _decode_env(env_id: str, raw: Any) -> Optional[CloudEnvironment]:
    if raw is None:
        return None
    try:
        fields = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(fields, dict):
        return None
    provider = fields.get("provider")
    role = fields.get("role")
    region = fields.get("region")
    if provider not in CLOUD_PROVIDERS or not isinstance(role, str) or not isinstance(region, str):
        return None
    compartment = fields.get("compartment")
    vault_secret_id = fields.get("vault_secret_id")
    return CloudEnvironment(
        env_id=env_id,
        provider=provider,
        role=role,
        region=region,
        compartment=compartment if isinstance(compartment, str) else None,
        session_ttl=clamp_ttl(int(fields.get("session_ttl", MAX_SESSION_TTL))),
        vault_secret_id=vault_secret_id if isinstance(vault_secret_id, str) else None,
    )


@dataclass(frozen=True)
class VendedCredential:
    """A short-lived cloud credential envelope vended for ONE authorized call.

    The secret fields (``secret_access_key``, ``session_token``) are returned to the
    caller but MUST be redacted before WORM persistence (they carry the power). The
    non-secret summary (``fingerprint``) is what the operator sees.
    """

    provider: str
    region: str
    expires_in: int
    # Provider-native short-lived credential material (secret — redacted from WORM).
    material: dict[str, str]
    # Non-secret operator/agent-safe summary of what was vended.
    fingerprint: str
    # True when the material is a sandbox stand-in, not a real cloud credential.
    simulated: bool


class CloudBroker:
    """
    Vends a short-lived, scoped credential for an authorized cloud_iam call.

    SANDBOX: returns a clearly-marked FAKE envelope (``simulated=True``) so the whole
    per-call-vend flow is demonstrable without touching a real cloud. PRODUCTION:
    assumes the environment's role using the GATEWAY's own host workload identity
    (never a stored secret) via the provider SDK; if the SDK is unavailable the vend
    fails closed (TRANSPORT_ERROR), never silently returns nothing.
    """

    def __init__(self, *, sandbox_mode: bool, vault: Optional[SecretVault] = None) -> None:
        self._sandbox = sandbox_mode
        self._vault = vault

    async def vend(
        self, env: CloudEnvironment, *, tenant_id: str, request_nonce: str
    ) -> VendedCredential:
        ttl = clamp_ttl(env.session_ttl)
        if self._sandbox:
            return self._simulate(env, ttl, request_nonce)
        return await self._vend_real(env, ttl, request_nonce, tenant_id)

    async def _broker_material(self, env: CloudEnvironment, tenant_id: str) -> Optional[dict[str, str]]:
        """
        Resolve the OPTIONAL vault-stored broker credential for this environment.

        None when the binding carries no reference (host-identity tier). A reference
        that cannot be resolved — vault not configured, entry missing, decrypt failure
        — is a fail-closed ``LockError``: never silently fall back to host identity,
        because the operator explicitly chose the vault tier for this binding.
        """
        if env.vault_secret_id is None:
            return None
        if self._vault is None:
            raise LockError("environment references a vault secret but no vault is configured")
        material = await self._vault.get_material(tenant_id, env.vault_secret_id)
        if material is None:
            raise LockError("vault broker credential unresolvable for this environment")
        return material

    def _simulate(self, env: CloudEnvironment, ttl: int, nonce: str) -> VendedCredential:
        """A shaped, obviously-fake credential — safe to show end-to-end in sandbox."""
        suffix = nonce[:16]
        if env.provider == "aws":
            material = {
                "access_key_id": f"ASIA_SANDBOX_{suffix.upper()}",
                "secret_access_key": f"sandbox/{nonce}",
                "session_token": f"FAKE.{nonce}.session",
                "role": env.role,
            }
            fp = f"AWS STS AssumeRole → {_arn_tail(env.role)} · {env.region} · {ttl}s (SANDBOX)"
        elif env.provider == "gcp":
            material = {"access_token": f"ya29.SANDBOX.{nonce}", "service_account": env.role}
            fp = f"GCP impersonation → {env.role} · {ttl}s (SANDBOX)"
        else:  # azure
            material = {"access_token": f"eyJSANDBOX.{nonce}", "client_id": env.role}
            fp = f"Azure federated token → {env.role} · {ttl}s (SANDBOX)"
        return VendedCredential(
            provider=env.provider,
            region=env.region,
            expires_in=ttl,
            material=material,
            fingerprint=fp,
            simulated=True,
        )

    async def _vend_real(
        self, env: CloudEnvironment, ttl: int, nonce: str, tenant_id: str
    ) -> VendedCredential:
        """
        Vend a short-lived session credential for the environment's role. The broker
        authenticates ITSELF either with the gateway's host identity (default credential
        chain — no stored secret) or, when the binding references one, a vault-stored
        broker credential (decrypted here, spent here, never surfaced). Each provider is
        symmetric: an OPTIONAL SDK import done in its ``_vend_*`` method (never at module
        load, so connector-purity scans and no-SDK deploys are unaffected), a
        host-identity path and a vault-broker-key path, a short-lived token, and a
        non-secret fingerprint. A missing SDK, unknown provider, or upstream error fails
        closed (``LockError`` → TRANSPORT_ERROR), never a silent nothing.
        """
        # The broker credential (host identity vs. vault key) is resolved here but its
        # TIER is NOT annotated onto the vended fingerprint: the fingerprint is the
        # AGENT-facing deliverable, and which broker identity the gateway used is an
        # operator/console signal (the binding's vault_secret_id badge), not something
        # the agent should learn. Keeping it out preserves the opacity boundary.
        broker_cred = await self._broker_material(env, tenant_id)
        if env.provider == "aws":
            return self._vend_aws(env, ttl, nonce, broker_cred)
        if env.provider == "gcp":
            return self._vend_gcp(env, ttl, nonce, broker_cred)
        if env.provider == "azure":
            return self._vend_azure(env, ttl, nonce, broker_cred)
        raise LockError(f"real vending for provider '{env.provider}' is not configured")

    def _vend_aws(
        self, env: CloudEnvironment, ttl: int, nonce: str,
        broker_cred: Optional[dict[str, str]],
    ) -> VendedCredential:
        """AWS: STS AssumeRole into the environment's role ARN (host identity or vault key)."""
        try:
            import boto3  # type: ignore[import-untyped]  # optional, prod-only.
        except ImportError as exc:
            raise LockError("aws broker requires boto3 (not installed)") from exc
        if broker_cred is None:
            # Host-identity tier: instance profile / IRSA / OIDC default chain.
            sts = boto3.client("sts", region_name=env.region)
        else:
            # Vault tier: the operator-stored broker key, spent gateway-side only.
            sts = boto3.client(
                "sts",
                region_name=env.region,
                aws_access_key_id=broker_cred.get("access_key_id", ""),
                aws_secret_access_key=broker_cred.get("secret_access_key", ""),
                aws_session_token=broker_cred.get("session_token") or None,
            )
        resp = sts.assume_role(
            RoleArn=env.role,
            RoleSessionName=f"mcpip-{nonce[:24]}",
            DurationSeconds=ttl,
        )
        creds = resp["Credentials"]
        material = {
            "access_key_id": creds["AccessKeyId"],
            "secret_access_key": creds["SecretAccessKey"],
            "session_token": creds["SessionToken"],
            "role": env.role,
        }
        return VendedCredential(
            provider="aws",
            region=env.region,
            expires_in=ttl,
            material=material,
            fingerprint=f"AWS STS AssumeRole → {_arn_tail(env.role)} · {env.region} · {ttl}s",
            simulated=False,
        )

    def _vend_gcp(
        self, env: CloudEnvironment, ttl: int, nonce: str,
        broker_cred: Optional[dict[str, str]],
    ) -> VendedCredential:
        """
        GCP: impersonate the environment's service account (``env.role`` = SA email) and
        mint a short-lived OAuth2 access token via the IAM Credentials API. The source
        identity is either Application Default Credentials (host: GKE Workload Identity /
        GCE metadata) or a vault-stored service-account key (``service_account_json``).
        """
        try:
            from google.auth import default as _google_default  # type: ignore[import-untyped]
            from google.auth.transport.requests import Request as _GoogleRequest  # type: ignore[import-untyped]
            from google.auth import impersonated_credentials as _impersonated  # type: ignore[import-untyped]
            from google.oauth2 import service_account as _sa  # type: ignore[import-untyped]
        except ImportError as exc:
            raise LockError("gcp broker requires google-auth (not installed)") from exc
        scopes = ["https://www.googleapis.com/auth/cloud-platform"]
        if broker_cred is None:
            source, _ = _google_default(scopes=scopes)
        else:
            info = _service_account_info(broker_cred)
            if info is None:
                raise LockError("gcp vault broker credential is not a valid service-account key")
            source = _sa.Credentials.from_service_account_info(info, scopes=scopes)
        target = _impersonated.Credentials(
            source_credentials=source,
            target_principal=env.role,
            target_scopes=scopes,
            lifetime=min(ttl, MAX_SESSION_TTL),
        )
        target.refresh(_GoogleRequest())
        material = {
            "access_token": str(target.token),
            "service_account": env.role,
            "token_type": "Bearer",
        }
        return VendedCredential(
            provider="gcp",
            region=env.region,
            expires_in=ttl,
            material=material,
            fingerprint=f"GCP impersonation → {env.role} · {ttl}s",
            simulated=False,
        )

    def _vend_azure(
        self, env: CloudEnvironment, ttl: int, nonce: str,
        broker_cred: Optional[dict[str, str]],
    ) -> VendedCredential:
        """
        Azure: acquire a short-lived AAD access token for the environment's target scope
        (``env.role`` = the resource scope, defaulting to ARM). The broker authenticates
        either via the managed/workload identity chain (host) or a vault-stored client
        secret (``tenant_id`` + ``client_id`` + ``client_secret``). Azure has no
        AssumeRole; the least-privilege boundary is the identity's RBAC assignment.
        """
        try:
            from azure.identity import (  # type: ignore[import-untyped]
                DefaultAzureCredential as _DefaultCred,
                ClientSecretCredential as _ClientSecretCred,
            )
        except ImportError as exc:
            raise LockError("azure broker requires azure-identity (not installed)") from exc
        # env.role carries the target scope for a resource token; default to ARM control-plane.
        scope = env.role if "://" in env.role else "https://management.azure.com/.default"
        if broker_cred is None:
            cred = _DefaultCred()
        else:
            tenant = broker_cred.get("tenant_id", "")
            client_id = broker_cred.get("client_id", "")
            secret = broker_cred.get("client_secret", "")
            if not (tenant and client_id and secret):
                raise LockError("azure vault broker credential missing tenant/client/secret")
            cred = _ClientSecretCred(tenant_id=tenant, client_id=client_id, client_secret=secret)
        token = cred.get_token(scope)
        material = {
            "access_token": str(token.token),
            "scope": scope,
            "token_type": "Bearer",
        }
        return VendedCredential(
            provider="azure",
            region=env.region,
            expires_in=ttl,
            material=material,
            fingerprint=f"Azure federated token → {env.role} · {ttl}s",
            simulated=False,
        )


def _arn_tail(role: str) -> str:
    """The role name from an ARN (or the whole string) — non-secret, log-safe."""
    return role.rsplit("/", 1)[-1] if "/" in role else role


def _service_account_info(broker_cred: dict[str, str]) -> Optional[dict[str, Any]]:
    """
    Coerce a vault-stored GCP broker credential into a service-account info dict for
    ``from_service_account_info``. Two accepted shapes: a single ``service_account_json``
    field holding the whole key JSON, or the individual key fields stored directly.
    Returns None if neither yields the minimum a private-key credential needs.
    """
    raw = broker_cred.get("service_account_json")
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            return None
        info = parsed if isinstance(parsed, dict) else None
    else:
        info = dict(broker_cred)
    if info is None:
        return None
    if not (info.get("client_email") and info.get("private_key")):
        return None
    return info


__all__ = [
    "CloudEnvironment",
    "CloudEnvironmentStore",
    "CloudBroker",
    "VendedCredential",
    "CLOUD_PROVIDERS",
    "MAX_ENVIRONMENTS",
    "MIN_SESSION_TTL",
    "MAX_SESSION_TTL",
    "clamp_ttl",
]
