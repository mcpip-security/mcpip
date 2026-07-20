"""
Unit tests for the environment secret vault (services/secret_vault.py) and the broker's
vault-resolution path (services/cloud_broker.py) — no HTTP app, no AWS.

Redis is namespaced to a dedicated db (``/12``) so these never touch the API suite's
state. Requires a Redis on :63790 (the dev container), like the rest of the suite.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
import redis.asyncio as aioredis

from auth import LockError
from services.cloud_broker import CloudBroker, CloudEnvironment, _service_account_info
from services.secret_vault import (
    SecretVault,
    validate_material,
)

_VAULT_REDIS_URL = "redis://localhost:63790/12"
_KEY_A = b"A" * 32
_KEY_B = b"B" * 32


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


async def _fresh_vault(master_key: bytes = _KEY_A) -> tuple[SecretVault, Any]:
    client: Any = aioredis.from_url(_VAULT_REDIS_URL, decode_responses=True)  # type: ignore[no-untyped-call]
    await client.flushdb()
    return SecretVault(client, master_key), client


def test_master_key_must_be_32_bytes() -> None:
    client: Any = aioredis.from_url(_VAULT_REDIS_URL, decode_responses=True)  # type: ignore[no-untyped-call]
    with pytest.raises(RuntimeError):
        SecretVault(client, b"too-short")


def test_put_then_get_material_roundtrips() -> None:
    async def scenario() -> None:
        vault, client = await _fresh_vault()
        try:
            material = {"access_key_id": "AKIA", "secret_access_key": "shhh-secret-value"}
            rec = await vault.put("mcpip-inc", "aws-broker", "aws", "desc", material)
            # Fingerprint is a keyed HMAC (12 hex), deterministic for identical material.
            assert rec.vendor == "aws" and len(rec.fingerprint) == 12
            rec2 = await vault.put("mcpip-inc", "aws-broker-2", "aws", "", material)
            assert rec2.fingerprint == rec.fingerprint  # same material → same tag
            got = await vault.get_material("mcpip-inc", "aws-broker")
            assert got == material
            # Metadata read never carries the value.
            meta = await vault.get("mcpip-inc", "aws-broker")
            assert meta is not None and "secret_access_key" not in meta.public_view()
        finally:
            await client.aclose()

    _run(scenario())


def test_fingerprint_is_keyed_not_a_bare_hash() -> None:
    """The operator-visible fingerprint is an HMAC under the master key, NOT sha256 of the
    plaintext — so someone who reads the fingerprint (or the WORM record) can't confirm a
    guessed low-entropy secret offline. Two vaults with different master keys must produce
    different fingerprints for identical material; and it must NOT equal the bare hash."""
    import hashlib as _h, json as _j
    material = {"password": "hunter2"}
    va = SecretVault(object.__new__(type("N", (), {})) if False else _FakeRedis(), _KEY_A)
    vb = SecretVault(_FakeRedis(), _KEY_B)
    fa, fb = va.fingerprint(material), vb.fingerprint(material)
    assert len(fa) == 12 and fa != fb  # keyed: different master keys → different tags
    bare = _h.sha256(_j.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:12]
    assert fa != bare and fb != bare  # not reconstructable without the key


class _FakeRedis:
    """Minimal stand-in so SecretVault can be constructed without a live client (the
    fingerprint path touches no I/O)."""


def test_value_is_ciphertext_at_rest() -> None:
    async def scenario() -> None:
        vault, client = await _fresh_vault()
        try:
            await vault.put("mcpip-inc", "k", "aws", "", {"secret_access_key": "PLAINTEXT_MARKER"})
            raw = await client.hget("mcpip:vault:mcpip-inc", "k")
            assert "PLAINTEXT_MARKER" not in raw
        finally:
            await client.aclose()

    _run(scenario())


def test_wrong_master_key_cannot_decrypt() -> None:
    """A different master key (or a rotated one) reads the row as an unresolvable miss —
    never a partial/garbage plaintext."""
    async def scenario() -> None:
        vault_a, client = await _fresh_vault(_KEY_A)
        try:
            await vault_a.put("mcpip-inc", "k", "aws", "", {"secret_access_key": "v"})
            vault_b = SecretVault(client, _KEY_B)
            assert await vault_b.get_material("mcpip-inc", "k") is None
        finally:
            await client.aclose()

    _run(scenario())


def test_aad_binds_tenant_and_secret_id() -> None:
    """Ciphertext copied onto a different (tenant, secret_id) row refuses to decrypt —
    the identity is bound as AES-GCM associated data."""
    async def scenario() -> None:
        vault, client = await _fresh_vault()
        try:
            await vault.put("tenant-a", "k", "aws", "", {"secret_access_key": "v"})
            blob = await client.hget("mcpip:vault:tenant-a", "k")
            # Transplant tenant-a's blob under tenant-b/k.
            await client.hset("mcpip:vault:tenant-b", "k", blob)
            assert await vault.get_material("tenant-b", "k") is None
        finally:
            await client.aclose()

    _run(scenario())


def test_validate_material_bounds() -> None:
    assert validate_material({"k": "v"})
    assert not validate_material({})
    assert not validate_material({"k": ""})
    assert not validate_material({"k": 5})  # type: ignore[dict-item]
    assert not validate_material({str(i): "v" for i in range(64)})  # too many keys


def test_broker_resolves_vault_reference_or_host_identity() -> None:
    """CloudBroker._broker_material returns None for a host-identity binding, the decrypted
    material for a vault-referencing binding, and fails closed when the reference dangles."""
    async def scenario() -> None:
        vault, client = await _fresh_vault()
        try:
            await vault.put("mcpip-inc", "broker", "aws", "", {"access_key_id": "AK", "secret_access_key": "sk"})
            broker = CloudBroker(sandbox_mode=False, vault=vault)
            host_env = CloudEnvironment("e", "aws", "arn:...:role/r", "us-east-1", None, 900, None)
            assert await broker._broker_material(host_env, "mcpip-inc") is None
            vault_env = CloudEnvironment("e", "aws", "arn:...:role/r", "us-east-1", None, 900, "broker")
            resolved = await broker._broker_material(vault_env, "mcpip-inc")
            assert resolved == {"access_key_id": "AK", "secret_access_key": "sk"}
            dangling = CloudEnvironment("e", "aws", "arn:...:role/r", "us-east-1", None, 900, "missing")
            with pytest.raises(LockError):
                await broker._broker_material(dangling, "mcpip-inc")
        finally:
            await client.aclose()

    _run(scenario())


def test_broker_without_vault_fails_closed_on_reference() -> None:
    """A binding that references the vault while the broker has no vault configured fails
    closed — never a silent host-identity fallback."""
    async def scenario() -> None:
        broker = CloudBroker(sandbox_mode=False, vault=None)
        env = CloudEnvironment("e", "aws", "arn:...:role/r", "us-east-1", None, 900, "broker")
        with pytest.raises(LockError):
            await broker._broker_material(env, "mcpip-inc")

    _run(scenario())


def test_real_vend_dispatches_per_provider_and_fails_closed_without_sdk() -> None:
    """Each vendor has a real vend path; when its optional SDK is absent (as in CI) the
    vend fails CLOSED (LockError), never a silent nothing. An unknown provider also fails
    closed. (google-auth / azure-identity are not installed in the test env.)"""
    async def scenario() -> None:
        broker = CloudBroker(sandbox_mode=False, vault=None)
        for provider in ("gcp", "azure", "oracle"):
            env = CloudEnvironment("e", provider, "target", "r", None, 900, None)
            with pytest.raises(LockError):
                await broker._vend_real(env, 900, "n" * 24, "mcpip-inc")

    _run(scenario())


def test_service_account_info_parsing() -> None:
    """GCP broker material is accepted as either a whole service_account_json blob or the
    individual fields; anything lacking client_email+private_key is rejected."""
    blob = '{"client_email":"svc@p.iam.gserviceaccount.com","private_key":"-----BEGIN-----"}'
    assert _service_account_info({"service_account_json": blob}) is not None
    assert _service_account_info({"client_email": "svc@p.iam", "private_key": "pk"}) is not None
    assert _service_account_info({"nope": "1"}) is None
    assert _service_account_info({"service_account_json": "not-json"}) is None
