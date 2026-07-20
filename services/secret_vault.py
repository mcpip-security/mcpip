"""
MCPIP V2 — Service: environment secret vault (operator-stored broker credentials).

    ◐ "The vault feeds the broker, the broker feeds the vend —
       the agent never holds anything worth stealing."

An OPERATOR convenience tier for deployments without cloud-native workload identity
(on-prem, laptops, non-cloud hosts): store a broker credential ONCE — an AWS key, a
GCP service-account JSON, an Azure client secret, a plain API token, a database
password — encrypted at rest, and reference it from a ``CloudEnvironment`` binding.
At vend time the GATEWAY decrypts and spends it (e.g. as the STS ``AssumeRole``
caller); the value itself NEVER crosses to an agent, never enters the WORM log, and
is never returned by any endpoint after the initial write (write-only semantics).

Trust tiers, made explicit rather than silent:

  * ``host identity``      — no stored secret anywhere; the cloud injects rotating
                             credentials into the gateway's runtime. RECOMMENDED.
  * ``vault broker key``   — this module: a stored, encrypted, gateway-only secret.
                             Weaker posture, deliberately visible as such in the
                             console (an amber badge, not a hidden default).

Encryption is AES-256-GCM under a gateway master key that lives OUTSIDE Redis (a key
file, exactly like the WORM signing key): dumping the Redis store yields only
ciphertext. Sandbox auto-provisions a persistent dev key under ``.keys/``; production
configures ``MCPIP_VAULT_KEY_PATH`` — without it the vault is simply ABSENT (feature
off, fail-closed on any reference to it), never silently downgraded to plaintext.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import time
from dataclasses import dataclass
from typing import Any, Optional

import redis.asyncio as redis
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from redis.exceptions import RedisError

from auth import LockError

_KEY_PREFIX = "mcpip:vault:"
# Bound the number of vault entries per tenant (broker credentials, not bulk data).
MAX_VAULT_SECRETS = 256
# Vendors the vault understands. The cloud trio backs cloud_iam brokers; api_key /
# database cover arbitrary downstream targets a gateway authenticates to server-side.
VAULT_VENDORS = frozenset({"aws", "gcp", "azure", "api_key", "database"})
# Bounds on one secret's material map (a credential envelope, never a document).
MAX_MATERIAL_KEYS = 16
MAX_MATERIAL_VALUE_LEN = 8192
_NONCE_LEN = 12  # AES-GCM standard nonce size.


@dataclass(frozen=True)
class VaultSecret:
    """Operator-visible metadata for one stored secret. NEVER carries the value."""

    secret_id: str
    vendor: str
    description: str
    # Non-secret identity of the value: first 12 hex of SHA-256 over the canonical
    # material. Lets an operator confirm WHICH key is stored without revealing it.
    fingerprint: str
    created_at: float
    updated_at: float

    def public_view(self) -> dict[str, Any]:
        return {
            "secret_id": self.secret_id,
            "vendor": self.vendor,
            "description": self.description,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def validate_material(material: dict[str, str]) -> bool:
    """Shape-check a credential envelope: flat, bounded, non-empty strings only."""
    if not isinstance(material, dict) or not material:
        return False
    if len(material) > MAX_MATERIAL_KEYS:
        return False
    for k, v in material.items():
        if not isinstance(k, str) or not k or len(k) > 128:
            return False
        if not isinstance(v, str) or not v or len(v) > MAX_MATERIAL_VALUE_LEN:
            return False
    return True


class SecretVault:
    """
    Redis-backed, per-tenant, AES-256-GCM-encrypted broker-credential store.

    The master key is held by the process (loaded from a key file at boot) and never
    persisted alongside the data: Redis holds ciphertext only. Reads of the VALUE are
    confined to ``get_material`` — the single broker-facing accessor; every operator
    surface sees only ``VaultSecret`` metadata.
    """

    def __init__(self, redis_client: "redis.Redis", master_key: bytes) -> None:
        if len(master_key) != 32:
            raise RuntimeError("vault master key must be exactly 32 bytes (AES-256)")
        self._redis = redis_client
        self._aead = AESGCM(master_key)
        # A domain-separated subkey for the operator-visible fingerprint. The fingerprint
        # is an HMAC (keyed), NOT a bare hash of the plaintext — so an operator who can
        # read the fingerprint (or the WORM record) cannot mount an OFFLINE dictionary
        # attack to confirm a guessed low-entropy secret (a bare sha256 would let them).
        self._fp_key = hashlib.sha256(b"mcpip-vault-fingerprint-v1\x00" + master_key).digest()

    def fingerprint(self, material: dict[str, str]) -> str:
        """Keyed, non-secret 'which key is stored' tag — reproducible for identical
        material under the same master key, but not reconstructable without it."""
        canonical = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._fp_key, canonical, hashlib.sha256).hexdigest()[:12]

    @staticmethod
    def _key(tenant_id: str) -> str:
        return f"{_KEY_PREFIX}{tenant_id}"

    async def count(self, tenant_id: str) -> int:
        try:
            return int(await self._redis.hlen(self._key(tenant_id)))
        except RedisError:
            return 0

    async def put(
        self,
        tenant_id: str,
        secret_id: str,
        vendor: str,
        description: str,
        material: dict[str, str],
    ) -> VaultSecret:
        """Encrypt + persist one secret. Fail-closed on transport error (never silent)."""
        now = time.time()
        created_at = now
        existing = await self._load_fields(tenant_id, secret_id)
        if existing is not None:
            try:
                created_at = float(existing.get("created_at", now))
            except (TypeError, ValueError):
                created_at = now
        plaintext = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        nonce = os.urandom(_NONCE_LEN)
        # The (tenant, secret) identity is bound as AAD, so a ciphertext blob copied
        # onto another tenant's row (or renamed) refuses to decrypt.
        blob = nonce + self._aead.encrypt(nonce, plaintext, self._aad(tenant_id, secret_id))
        record = VaultSecret(
            secret_id=secret_id,
            vendor=vendor,
            description=description,
            fingerprint=self.fingerprint(material),
            created_at=created_at,
            updated_at=now,
        )
        payload = json.dumps(
            {**record.public_view(), "blob": base64.b64encode(blob).decode()},
            separators=(",", ":"),
        )
        try:
            await self._redis.hset(self._key(tenant_id), secret_id, payload)
        except RedisError as exc:
            raise LockError("vault transport failure during put") from exc
        return record

    async def remove(self, tenant_id: str, secret_id: str) -> bool:
        try:
            removed: Any = await self._redis.hdel(self._key(tenant_id), secret_id)
        except RedisError as exc:
            raise LockError("vault transport failure during remove") from exc
        return int(removed) > 0

    async def get(self, tenant_id: str, secret_id: str) -> Optional[VaultSecret]:
        """Metadata only — the operator/console read path."""
        fields = await self._load_fields(tenant_id, secret_id)
        if fields is None:
            return None
        return _decode_meta(secret_id, fields)

    async def list_for_tenant(self, tenant_id: str) -> list[VaultSecret]:
        try:
            raw: Any = await self._redis.hgetall(self._key(tenant_id))
        except RedisError:
            return []
        out: list[VaultSecret] = []
        for k, v in (raw or {}).items():
            secret_id = k.decode() if isinstance(k, bytes) else str(k)
            fields = _parse_fields(v)
            if fields is None:
                continue
            meta = _decode_meta(secret_id, fields)
            if meta is not None:
                out.append(meta)
        out.sort(key=lambda s: s.secret_id)
        return out

    async def get_material(self, tenant_id: str, secret_id: str) -> Optional[dict[str, str]]:
        """
        Decrypt one secret's value — the SINGLE broker-facing accessor. Returns None on
        any failure (missing, transport, corrupt, wrong key): the caller treats an
        unresolvable reference as fail-closed, never as "proceed without".
        """
        fields = await self._load_fields(tenant_id, secret_id)
        if fields is None:
            return None
        blob_b64 = fields.get("blob")
        if not isinstance(blob_b64, str):
            return None
        try:
            blob = base64.b64decode(blob_b64)
            nonce, ciphertext = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
            plaintext = self._aead.decrypt(nonce, ciphertext, self._aad(tenant_id, secret_id))
            material = json.loads(plaintext)
        except Exception:  # noqa: BLE001 — any decrypt/decode failure is a miss.
            return None
        if not validate_material(material):
            return None
        return {str(k): str(v) for k, v in material.items()}

    @staticmethod
    def _aad(tenant_id: str, secret_id: str) -> bytes:
        # Length-prefixed so (tenant, secret) is UNAMBIGUOUS — no delimiter-collision class
        # where two distinct identity pairs could produce the same associated data.
        t, s = tenant_id.encode(), secret_id.encode()
        return struct.pack(">II", len(t), len(s)) + t + s

    async def _load_fields(self, tenant_id: str, secret_id: str) -> Optional[dict[str, Any]]:
        try:
            raw: Any = await self._redis.hget(self._key(tenant_id), secret_id)
        except RedisError:
            return None
        return _parse_fields(raw)


def _parse_fields(raw: Any) -> Optional[dict[str, Any]]:
    if raw is None:
        return None
    try:
        fields = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return fields if isinstance(fields, dict) else None


def _decode_meta(secret_id: str, fields: dict[str, Any]) -> Optional[VaultSecret]:
    vendor = fields.get("vendor")
    if vendor not in VAULT_VENDORS:
        return None
    try:
        return VaultSecret(
            secret_id=secret_id,
            vendor=str(vendor),
            description=str(fields.get("description", "")),
            fingerprint=str(fields.get("fingerprint", "")),
            created_at=float(fields.get("created_at", 0.0)),
            updated_at=float(fields.get("updated_at", 0.0)),
        )
    except (TypeError, ValueError):
        return None


__all__ = [
    "SecretVault",
    "VaultSecret",
    "VAULT_VENDORS",
    "MAX_VAULT_SECRETS",
    "MAX_MATERIAL_KEYS",
    "MAX_MATERIAL_VALUE_LEN",
    "validate_material",
]
