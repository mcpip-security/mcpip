"""
MCPIP — Proof-of-Possession + RFC 8693 delegation: crypto-core property tests.

    ◐ Auth: "The human factor must be PROVEN, not asserted."

These are PURE unit tests over ``auth/pop.py`` — no Redis, no HTTP, no app boot.
They pin the [PO] proof-obligations the module claims in its docstring:

  * A valid DPoP-style proof binds key-possession to THIS request and passes.
  * EVERY tampering axis fails closed — wrong key, forged signature, replayed
    jti, htm/htu drift, stale/future iat, alg=none/HMAC, private JWK material,
    wrong typ, missing claims.
  * A bearer token (no ``cnf``) never consults this module; a malformed ``cnf``
    / ``act`` fails closed instead of silently downgrading to bearer.

Together with the end-to-end sender-constrained scenarios in
``test_authorize_api.py`` (which drive the real pipeline + Redis replay guard),
these establish that a captured sender-constrained token is unusable.

The suite has NO async test-runner dependency: each case drives the async
``verify_pop_proof`` synchronously via ``asyncio.run`` — matching this repo's
convention of never relying on pytest-asyncio.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac as _hmac
import json
from typing import Any, Optional

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwt.algorithms import ECAlgorithm, OKPAlgorithm

from auth.pop import (
    ID_JAG_TOKEN_TYPE,
    POP_CLOCK_SKEW_SECONDS,
    POP_MAX_AGE_SECONDS,
    InMemoryReplayGuard,
    PopError,
    is_id_jag,
    jwk_thumbprint,
    project_act_chain,
    project_act_sub,
    project_cnf_jkt,
    verify_pop_proof,
)
from interfaces import MAX_DELEGATION_CHAIN

# A fixed "now" so freshness math is deterministic (no wall-clock reads in tests).
_NOW = 1_770_000_000.0
_HTU = "https://gw.mcpip.example/v1/authorize"
_HTM = "POST"


# ---------------------------------------------------------------------------
# Key + proof construction helpers (the honest client's job).
# ---------------------------------------------------------------------------


def _okp_key() -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    """An Ed25519 keypair + its RFC-7638 public JWK (via PyJWT's own serializer)."""
    key = Ed25519PrivateKey.generate()
    pub_jwk: dict[str, Any] = json.loads(OKPAlgorithm.to_jwk(key.public_key()))
    return key, pub_jwk


def _ec_key() -> tuple[ec.EllipticCurvePrivateKey, dict[str, Any]]:
    """A P-256 keypair + its RFC-7638 public JWK."""
    key = ec.generate_private_key(ec.SECP256R1())
    pub_jwk: dict[str, Any] = json.loads(ECAlgorithm.to_jwk(key.public_key()))
    return key, pub_jwk


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# The presented access token + the canonical payload hash the proof binds to.
# ath = SHA-256(token); pch = the exact digest lock_payload_hash would produce.
_TOKEN = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhZ2VudCJ9.c2ln"
_ATH = _b64url(hashlib.sha256(_TOKEN.encode("ascii")).digest())
_PCH = "b" * 64


def _make_proof(
    private_key: Any,
    pub_jwk: dict[str, Any],
    *,
    alg: str = "EdDSA",
    typ: str = "dpop+jwt",
    htm: Optional[str] = _HTM,
    htu: Optional[str] = _HTU,
    ath: Optional[str] = _ATH,
    pch: Optional[str] = _PCH,
    iat: Optional[float] = _NOW,
    jti: Optional[str] = "jti-0001",
    extra_payload: Optional[dict[str, Any]] = None,
    header_jwk: Optional[dict[str, Any]] = None,
    drop: tuple[str, ...] = (),
) -> str:
    """Assemble + sign a DPoP-style proof; knobs let each test tamper one axis."""
    header: dict[str, Any] = {
        "typ": typ,
        "alg": alg,
        "jwk": header_jwk if header_jwk is not None else pub_jwk,
    }
    payload: dict[str, Any] = {}
    if htm is not None:
        payload["htm"] = htm
    if htu is not None:
        payload["htu"] = htu
    if ath is not None:
        payload["ath"] = ath
    if pch is not None:
        payload["pch"] = pch
    if iat is not None:
        payload["iat"] = iat
    if jti is not None:
        payload["jti"] = jti
    if extra_payload:
        payload.update(extra_payload)
    for k in drop:
        payload.pop(k, None)
    return jwt.encode(payload, private_key, algorithm=alg, headers=header)


def _verify(proof: str, *, expected_jkt: str, replay: Any, **kw: Any) -> None:
    """Drive the async verifier synchronously with suite defaults (overridable)."""
    asyncio.run(
        verify_pop_proof(
            proof,
            expected_jkt=expected_jkt,
            http_method=kw.pop("http_method", _HTM),
            http_url=kw.pop("http_url", _HTU),
            access_token=kw.pop("access_token", _TOKEN),
            expected_payload_hash=kw.pop("expected_payload_hash", _PCH),
            now_ts=kw.pop("now_ts", _NOW),
            replay=replay,
            **kw,
        )
    )


# ---------------------------------------------------------------------------
# jwk_thumbprint — RFC 7638.
# ---------------------------------------------------------------------------


def test_thumbprint_is_order_and_extra_member_invariant() -> None:
    """Thumbprint hashes ONLY the required members, sorted — order/extras cannot shift it."""
    _key, jwk = _okp_key()
    base = jwk_thumbprint(jwk)
    reordered = {"x": jwk["x"], "kty": "OKP", "crv": jwk["crv"]}
    with_extras = {**jwk, "use": "sig", "kid": "ignored", "alg": "EdDSA"}
    assert jwk_thumbprint(reordered) == base
    assert jwk_thumbprint(with_extras) == base


def test_thumbprint_matches_independent_rfc7638_computation() -> None:
    """Independently recompute SHA-256 over the canonical JSON — must agree byte-for-byte."""
    _key, jwk = _okp_key()
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    expected = _b64url(hashlib.sha256(canonical).digest())
    assert jwk_thumbprint(jwk) == expected


def test_thumbprint_ec_uses_x_and_y() -> None:
    """An EC thumbprint incorporates y; dropping a required member fails closed."""
    _key, jwk = _ec_key()
    assert jwk_thumbprint(jwk)  # well-formed EC JWK → a thumbprint.
    with pytest.raises(PopError):
        jwk_thumbprint({"crv": jwk["crv"], "kty": "EC", "x": jwk["x"]})  # no y


def test_thumbprint_rejects_unknown_kty() -> None:
    with pytest.raises(PopError):
        jwk_thumbprint({"kty": "RSA", "n": "…", "e": "AQAB"})


# ---------------------------------------------------------------------------
# verify_pop_proof — the happy paths.
# ---------------------------------------------------------------------------


def test_valid_okp_proof_passes() -> None:
    key, jwk = _okp_key()
    proof = _make_proof(key, jwk)
    _verify(proof, expected_jkt=jwk_thumbprint(jwk), replay=InMemoryReplayGuard())


def test_valid_ec_proof_passes() -> None:
    key, jwk = _ec_key()
    proof = _make_proof(key, jwk, alg="ES256")
    _verify(proof, expected_jkt=jwk_thumbprint(jwk), replay=InMemoryReplayGuard())


def test_htu_query_and_trailing_slash_are_normalized() -> None:
    """A proof htu differing only by query/fragment/trailing-slash still binds."""
    key, jwk = _okp_key()
    proof = _make_proof(key, jwk, htu=_HTU + "/?trace=abc#frag")
    _verify(
        proof,
        expected_jkt=jwk_thumbprint(jwk),
        replay=InMemoryReplayGuard(),
        http_url=_HTU + "?trace=zzz",
    )


def test_htm_is_case_insensitive() -> None:
    key, jwk = _okp_key()
    proof = _make_proof(key, jwk, htm="post")
    _verify(
        proof,
        expected_jkt=jwk_thumbprint(jwk),
        replay=InMemoryReplayGuard(),
        http_method="POST",
    )


# ---------------------------------------------------------------------------
# verify_pop_proof — every failure axis fails closed.
# ---------------------------------------------------------------------------


def test_thumbprint_mismatch_rejected() -> None:
    """A proof for a DIFFERENT key than the token's cnf.jkt is refused."""
    key, jwk = _okp_key()
    _other_key, other_jwk = _okp_key()
    proof = _make_proof(key, jwk)
    with pytest.raises(PopError, match="thumbprint"):
        _verify(proof, expected_jkt=jwk_thumbprint(other_jwk), replay=InMemoryReplayGuard())


def test_signature_forgery_rejected() -> None:
    """Advertise victim's public JWK but sign with the attacker's key → sig fails."""
    victim_key, victim_jwk = _okp_key()
    attacker_key, _attacker_jwk = _okp_key()
    # Header claims the victim's key (so the thumbprint matches cnf) but the JWS
    # is signed by the attacker — the embedded public key cannot verify it.
    proof = _make_proof(attacker_key, victim_jwk, header_jwk=victim_jwk)
    with pytest.raises(PopError, match="signature|invalid"):
        _verify(proof, expected_jkt=jwk_thumbprint(victim_jwk), replay=InMemoryReplayGuard())


def test_replayed_jti_rejected() -> None:
    """A proof is single-use: the SAME jti twice → second is a replay."""
    key, jwk = _okp_key()
    guard = InMemoryReplayGuard()
    jkt = jwk_thumbprint(jwk)
    first = _make_proof(key, jwk, jti="unique-jti")
    _verify(first, expected_jkt=jkt, replay=guard)
    # A freshly-signed proof reusing the jti is still a replay (jti, not bytes).
    again = _make_proof(key, jwk, jti="unique-jti")
    with pytest.raises(PopError, match="replay"):
        _verify(again, expected_jkt=jkt, replay=guard)


def test_htm_mismatch_rejected() -> None:
    key, jwk = _okp_key()
    proof = _make_proof(key, jwk, htm="GET")
    with pytest.raises(PopError, match="htm"):
        _verify(
            proof,
            expected_jkt=jwk_thumbprint(jwk),
            replay=InMemoryReplayGuard(),
            http_method="POST",
        )


def test_htu_mismatch_rejected() -> None:
    """A proof minted for one resource cannot be relayed to another."""
    key, jwk = _okp_key()
    proof = _make_proof(key, jwk, htu="https://gw.mcpip.example/v1/mcp")
    with pytest.raises(PopError, match="htu"):
        _verify(
            proof,
            expected_jkt=jwk_thumbprint(jwk),
            replay=InMemoryReplayGuard(),
            http_url=_HTU,
        )


def test_stale_iat_rejected() -> None:
    key, jwk = _okp_key()
    proof = _make_proof(key, jwk, iat=_NOW - POP_MAX_AGE_SECONDS - 1)
    with pytest.raises(PopError, match="stale|future"):
        _verify(proof, expected_jkt=jwk_thumbprint(jwk), replay=InMemoryReplayGuard())


def test_future_iat_rejected() -> None:
    key, jwk = _okp_key()
    proof = _make_proof(key, jwk, iat=_NOW + POP_CLOCK_SKEW_SECONDS + 5)
    with pytest.raises(PopError, match="stale|future"):
        _verify(proof, expected_jkt=jwk_thumbprint(jwk), replay=InMemoryReplayGuard())


def test_alg_none_rejected() -> None:
    """An unsigned proof (alg=none) never reaches signature verification."""
    _key, jwk = _okp_key()
    header = _b64url(json.dumps({"typ": "dpop+jwt", "alg": "none", "jwk": jwk}).encode())
    payload = _b64url(json.dumps({"htm": _HTM, "htu": _HTU, "iat": _NOW, "jti": "x"}).encode())
    forged = f"{header}.{payload}."
    with pytest.raises(PopError, match="alg"):
        _verify(forged, expected_jkt=jwk_thumbprint(jwk), replay=InMemoryReplayGuard())


def test_hmac_alg_rejected() -> None:
    """A symmetric alg (HS256) is outside the asymmetric allow-list → refused."""
    _key, jwk = _okp_key()
    # Sign with HMAC using the public x as the "secret" — the key-confusion trick.
    header = _b64url(json.dumps({"typ": "dpop+jwt", "alg": "HS256", "jwk": jwk}).encode())
    payload = _b64url(json.dumps({"htm": _HTM, "htu": _HTU, "iat": _NOW, "jti": "x"}).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = _b64url(_hmac.new(jwk["x"].encode(), signing_input, hashlib.sha256).digest())
    forged = f"{header}.{payload}.{sig}"
    with pytest.raises(PopError, match="alg"):
        _verify(forged, expected_jkt=jwk_thumbprint(jwk), replay=InMemoryReplayGuard())


def test_wrong_typ_rejected() -> None:
    key, jwk = _okp_key()
    proof = _make_proof(key, jwk, typ="JWT")
    with pytest.raises(PopError, match="typ"):
        _verify(proof, expected_jkt=jwk_thumbprint(jwk), replay=InMemoryReplayGuard())


def test_private_jwk_material_rejected() -> None:
    """A proof header leaking private members (d) is refused before any use."""
    key, jwk = _okp_key()
    poisoned = {**jwk, "d": "c29tZS1wcml2YXRlLXNjYWxhcg"}
    proof = _make_proof(key, jwk, header_jwk=poisoned)
    with pytest.raises(PopError, match="private"):
        _verify(proof, expected_jkt=jwk_thumbprint(jwk), replay=InMemoryReplayGuard())


def test_missing_jwk_rejected() -> None:
    key, jwk = _okp_key()
    # Build a proof whose header carries no jwk at all, reusing a real body+sig.
    header = _b64url(json.dumps({"typ": "dpop+jwt", "alg": "EdDSA"}).encode())
    signed = _make_proof(key, jwk)
    body_sig = signed.split(".", 1)[1]
    forged = f"{header}.{body_sig}"
    with pytest.raises(PopError):
        _verify(forged, expected_jkt=jwk_thumbprint(jwk), replay=InMemoryReplayGuard())


def test_ath_mismatch_rejected() -> None:
    """A proof minted for one access token cannot be presented with another."""
    key, jwk = _okp_key()
    proof = _make_proof(key, jwk)  # ath binds _TOKEN
    with pytest.raises(PopError, match="ath"):
        _verify(
            proof,
            expected_jkt=jwk_thumbprint(jwk),
            replay=InMemoryReplayGuard(),
            access_token="a.different.token",
        )


def test_pch_body_swap_rejected() -> None:
    """A proof minted for payload A cannot be substituted onto payload B (body swap)."""
    key, jwk = _okp_key()
    proof = _make_proof(key, jwk, pch="a" * 64)  # proof attests payload A
    with pytest.raises(PopError, match="pch|payload"):
        _verify(
            proof,
            expected_jkt=jwk_thumbprint(jwk),
            replay=InMemoryReplayGuard(),
            expected_payload_hash="c" * 64,  # gateway computed a DIFFERENT action
        )


@pytest.mark.parametrize("missing", ["htm", "htu", "ath", "pch", "iat", "jti"])
def test_missing_required_payload_claim_rejected(missing: str) -> None:
    key, jwk = _okp_key()
    proof = _make_proof(key, jwk, drop=(missing,))
    with pytest.raises(PopError):
        _verify(proof, expected_jkt=jwk_thumbprint(jwk), replay=InMemoryReplayGuard())


def test_empty_proof_rejected() -> None:
    _key, jwk = _okp_key()
    with pytest.raises(PopError, match="missing"):
        _verify("", expected_jkt=jwk_thumbprint(jwk), replay=InMemoryReplayGuard())


def test_fail_closed_replay_guard_denies() -> None:
    """A replay guard that cannot confirm single-use (returns False) → deny."""

    class _AlwaysFail:
        async def record(self, jti: str, *, ttl_seconds: int) -> bool:
            return False

    key, jwk = _okp_key()
    proof = _make_proof(key, jwk)
    with pytest.raises(PopError, match="replay"):
        _verify(proof, expected_jkt=jwk_thumbprint(jwk), replay=_AlwaysFail())


# ---------------------------------------------------------------------------
# Claim projection — never silently downgrade to bearer.
# ---------------------------------------------------------------------------


def test_project_cnf_absent_is_bearer() -> None:
    assert project_cnf_jkt({"sub": "x"}) is None


def test_project_cnf_present() -> None:
    assert project_cnf_jkt({"cnf": {"jkt": "abc"}}) == "abc"


@pytest.mark.parametrize(
    "claims",
    [
        {"cnf": "not-an-object"},
        {"cnf": {"jkt": ""}},
        {"cnf": {"jkt": 123}},
        {"cnf": {}},
    ],
)
def test_project_cnf_malformed_fails_closed(claims: dict[str, Any]) -> None:
    """A cnf we cannot interpret must raise, NOT degrade to a bearer token."""
    with pytest.raises(PopError):
        project_cnf_jkt(claims)


def test_project_act_absent_is_not_delegation() -> None:
    assert project_act_sub({"sub": "x"}) is None


def test_project_act_present() -> None:
    assert project_act_sub({"act": {"sub": "human:alice"}}) == "human:alice"


@pytest.mark.parametrize(
    "claims",
    [{"act": "nope"}, {"act": {"sub": ""}}, {"act": {"sub": 42}}, {"act": {}}],
)
def test_project_act_malformed_fails_closed(claims: dict[str, Any]) -> None:
    with pytest.raises(PopError):
        project_act_sub(claims)


# ---------------------------------------------------------------------------
# N3 — full RFC 8693 delegation chain + ID-JAG token-type recognition.
# ---------------------------------------------------------------------------


def test_project_act_chain_absent_is_empty() -> None:
    """No ``act`` claim → () (not a delegation chain, legacy behavior)."""
    assert project_act_chain({"sub": "x"}) == ()


def test_project_act_chain_single_hop() -> None:
    """A single ``act.sub`` → a one-element ordered chain."""
    assert project_act_chain({"act": {"sub": "A"}}) == ("A",)


def test_project_act_chain_multi_hop_in_order() -> None:
    """Nested ``act`` walks immediate-actor-first to the ultimate delegator."""
    claims = {"act": {"sub": "A", "act": {"sub": "B", "act": {"sub": "C"}}}}
    assert project_act_chain(claims) == ("A", "B", "C")


@pytest.mark.parametrize(
    "claims",
    [
        {"act": "nope"},                                   # non-dict root
        {"act": {"sub": ""}},                              # empty sub
        {"act": {"sub": 42}},                              # non-str sub
        {"act": {}},                                       # missing sub
        {"act": {"sub": "A", "act": "bad"}},               # malformed NESTED act
        {"act": {"sub": "A", "act": {"sub": ""}}},         # empty sub deeper in
        {"act": {"sub": "A", "act": {"sub": "B", "act": {}}}},  # missing sub at leaf
    ],
)
def test_project_act_chain_malformed_fails_closed(claims: dict[str, Any]) -> None:
    """Any malformed node at ANY hop raises, never a silent partial/downgrade."""
    with pytest.raises(PopError):
        project_act_chain(claims)


def test_project_act_chain_over_length_rejected() -> None:
    """A chain deeper than MAX_DELEGATION_CHAIN is a claim-stuffing token → PopError."""
    node: dict[str, Any] = {"sub": "leaf"}
    # Build MAX_DELEGATION_CHAIN + 1 nested actors (one hop over the ceiling).
    for i in range(MAX_DELEGATION_CHAIN):
        node = {"sub": f"h{i}", "act": node}
    with pytest.raises(PopError):
        project_act_chain({"act": node})


def test_project_act_chain_exactly_max_allowed() -> None:
    """A chain of exactly MAX_DELEGATION_CHAIN hops is accepted (boundary)."""
    node: dict[str, Any] = {"sub": f"h{MAX_DELEGATION_CHAIN - 1}"}
    for i in range(MAX_DELEGATION_CHAIN - 1):
        node = {"sub": f"h{i}", "act": node}
    chain = project_act_chain({"act": node})
    assert len(chain) == MAX_DELEGATION_CHAIN


def test_project_act_sub_unchanged_for_single_hop() -> None:
    """project_act_sub keeps its exact single-hop behavior alongside the new chain fn."""
    assert project_act_sub({"act": {"sub": "human:alice"}}) == "human:alice"
    # A multi-hop token still yields ONLY the first hop from project_act_sub.
    claims = {"act": {"sub": "A", "act": {"sub": "B"}}}
    assert project_act_sub(claims) == "A"
    assert project_act_chain(claims) == ("A", "B")


def test_is_id_jag_via_token_type_claim() -> None:
    assert is_id_jag({"token_type": ID_JAG_TOKEN_TYPE}, {}) is True


def test_is_id_jag_via_header_typ() -> None:
    assert is_id_jag({}, {"typ": ID_JAG_TOKEN_TYPE}) is True


def test_is_id_jag_plain_token_is_false() -> None:
    assert is_id_jag({"sub": "x"}, {"typ": "JWT"}) is False
    assert is_id_jag({}, {}) is False
