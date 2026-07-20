"""
MCPIP — JWKS-backed key provider (multi-key, select-by-kid).

    ◐ Auth: identity comes only from a verified JWT — no matter WHICH published
    key signed it.

`JWKSKeyProvider` is the drop-in for an IdP / workload-identity STS that rotates
signing keys: several public keys under distinct ``kid`` values, and a token names
the one that signed it. These are pure tests (no Redis, no app boot). They pin:
  * resolve-by-kid returns the correct public key (OKP + RSA);
  * unknown/absent kid, empty/malformed JWKS, private material, duplicate kid all
    fail closed (TokenError);
  * end-to-end a TokenResolver on a JWKS verifies a validly-signed token and
    rejects a foreign-key / unknown-kid / disallowed-alg one — the alg allow-list
    stays the gate even when the key is present in the JWKS.
"""

from __future__ import annotations

import json
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm

from auth import JWKSKeyProvider, TokenError, TokenResolver

_ISS = "https://sts.mcpip.example"
_AUD = "mcpip-gateway"


def _pkcs8(priv: Any) -> bytes:
    pem: bytes = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return pem


def _okp(kid: str) -> tuple[Any, bytes, dict[str, Any]]:
    priv = Ed25519PrivateKey.generate()
    jwk: dict[str, Any] = json.loads(OKPAlgorithm.to_jwk(priv.public_key()))
    jwk["kid"] = kid
    return priv, _pkcs8(priv), jwk


def _rsa(kid: str) -> tuple[Any, bytes, dict[str, Any]]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk: dict[str, Any] = json.loads(RSAAlgorithm.to_jwk(priv.public_key()))
    jwk["kid"] = kid
    return priv, _pkcs8(priv), jwk


def _ec(kid: str) -> tuple[Any, bytes, dict[str, Any]]:
    priv = generate_private_key(SECP256R1())
    jwk: dict[str, Any] = json.loads(ECAlgorithm.to_jwk(priv.public_key()))
    jwk["kid"] = kid
    return priv, _pkcs8(priv), jwk


def _claims(**over: Any) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": _ISS,
        "aud": _AUD,
        "tenant_id": "tenant-acme",
        "agent_id": "agent-1",
        "role": "ops",
        "exp": now + 300,
        "iat": now,
        "nbf": now,
    }
    claims.update(over)
    return claims


def _resolver(*jwks_keys: dict[str, Any]) -> TokenResolver:
    return TokenResolver(
        JWKSKeyProvider({"keys": list(jwks_keys)}), issuer=_ISS, audience=_AUD
    )


# ---------------------------------------------------------------------------
# Provider: resolve-by-kid + fail-closed construction.
# ---------------------------------------------------------------------------


def test_resolve_okp_returns_matching_public_pem() -> None:
    priv, _pem, jwk = _okp("k1")
    provider = JWKSKeyProvider({"keys": [jwk]})
    expected = priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    assert provider.resolve({"kid": "k1"}) == expected


def test_resolve_selects_the_named_key_among_many() -> None:
    _p1, _pem1, j1 = _okp("k1")
    p2, _pem2, j2 = _rsa("k2")
    provider = JWKSKeyProvider({"keys": [j1, j2]})
    expected2 = p2.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    assert provider.resolve({"kid": "k2"}) == expected2


def test_unknown_kid_fails_closed() -> None:
    _p, _pem, jwk = _okp("k1")
    provider = JWKSKeyProvider({"keys": [jwk]})
    with pytest.raises(TokenError, match="no JWKS key for kid"):
        provider.resolve({"kid": "nope"})


def test_missing_kid_header_fails_closed() -> None:
    _p, _pem, jwk = _okp("k1")
    provider = JWKSKeyProvider({"keys": [jwk]})
    with pytest.raises(TokenError, match="kid"):
        provider.resolve({})


def test_empty_jwks_fails_closed() -> None:
    with pytest.raises(TokenError, match="non-empty"):
        JWKSKeyProvider({"keys": []})


def test_jwks_missing_keys_array_fails_closed() -> None:
    with pytest.raises(TokenError):
        JWKSKeyProvider({"not_keys": []})


def test_key_without_kid_fails_closed() -> None:
    _p, _pem, jwk = _okp("k1")
    del jwk["kid"]
    with pytest.raises(TokenError, match="kid"):
        JWKSKeyProvider({"keys": [jwk]})


def test_duplicate_kid_fails_closed() -> None:
    _p1, _pem1, j1 = _okp("dup")
    _p2, _pem2, j2 = _okp("dup")
    with pytest.raises(TokenError, match="duplicate"):
        JWKSKeyProvider({"keys": [j1, j2]})


def test_private_material_rejected() -> None:
    _p, _pem, jwk = _okp("k1")
    jwk["d"] = "c29tZS1wcml2YXRlLXNjYWxhcg"  # a private OKP scalar has no place in a JWKS.
    with pytest.raises(TokenError, match="private"):
        JWKSKeyProvider({"keys": [jwk]})


def test_unsupported_kty_fails_closed() -> None:
    with pytest.raises(TokenError, match="unsupported"):
        JWKSKeyProvider({"keys": [{"kty": "FOO", "kid": "k1", "x": "abc"}]})


# ---------------------------------------------------------------------------
# End-to-end through TokenResolver.
# ---------------------------------------------------------------------------


def test_resolver_verifies_okp_token_via_jwks() -> None:
    priv, pem, jwk = _okp("k1")
    token = jwt.encode(_claims(), pem, algorithm="EdDSA", headers={"kid": "k1"})
    identity = _resolver(jwk).resolve(token)
    assert (identity.tenant_id, identity.agent_id) == ("tenant-acme", "agent-1")


def test_resolver_verifies_rsa_rs256_token_via_jwks() -> None:
    priv, pem, jwk = _rsa("r1")
    token = jwt.encode(_claims(), pem, algorithm="RS256", headers={"kid": "r1"})
    identity = _resolver(jwk).resolve(token)
    assert identity.role == "ops"


def test_resolver_rejects_token_signed_by_foreign_key() -> None:
    """Same kid, different key → signature cannot verify against the JWKS entry."""
    _p1, _pem1, jwk = _okp("k1")
    _p2, foreign_pem, _j2 = _okp("k1")  # attacker's key, advertising the real kid.
    token = jwt.encode(_claims(), foreign_pem, algorithm="EdDSA", headers={"kid": "k1"})
    with pytest.raises(TokenError):
        _resolver(jwk).resolve(token)


def test_resolver_rejects_unknown_kid() -> None:
    _p, pem, jwk = _okp("k1")
    token = jwt.encode(_claims(), pem, algorithm="EdDSA", headers={"kid": "k2"})
    with pytest.raises(TokenError, match="kid"):
        _resolver(jwk).resolve(token)


def test_alg_allowlist_still_gates_even_with_key_in_jwks() -> None:
    """An EC key may sit in the JWKS, but ES256 is outside the identity alg allow-list."""
    priv, pem, jwk = _ec("e1")
    token = jwt.encode(_claims(), pem, algorithm="ES256", headers={"kid": "e1"})
    with pytest.raises(TokenError, match="not permitted"):
        _resolver(jwk).resolve(token)
