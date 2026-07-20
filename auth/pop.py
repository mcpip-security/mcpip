"""
MCPIP — Proof-of-Possession (sender-constrained tokens) + RFC 8693 delegation chain.

    ◐ Auth: "The human factor must be PROVEN, not asserted."

A bearer JWT proves nothing about who presents it — a stolen token is a valid
token. A *sender-constrained* token carries a ``cnf`` (confirmation) claim binding
it to a proof key via that key's RFC-7638 JWK thumbprint (``jkt``). To use such a
token the caller MUST additionally present a **proof-of-possession**: a short,
single-use JWS (DPoP-style, RFC-9449-inspired) signed by the matching private key
and bound to *this action* — method + URI, the presented token (``ath``), the
canonical payload hash (``pch`` — the SAME digest the PIN lock binds), freshness,
and a unique id. Possession of the token is no longer sufficient; the caller proves
possession of the *key* AND that the proof was minted for exactly this call, so a
sniffed / relayed proof cannot be substituted onto another alias or arguments.

This closes the "delegation asserted, not proven" gap: when a delegated token
(``act.sub`` = the human principal) carries a ``cnf`` binding, the presenter must
cryptographically demonstrate key possession, defeating token theft / replay / relay.

Claim discipline:
  * [BC] The typ / alg-allowlist / thumbprint / signature / htm / htu / freshness
    checks are total and fail-closed; an auditor verifies the mechanism here.
  * [PO] "A captured sender-constrained token is unusable" holds ONLY IF (a) the
    replay guard is durable and single-use, and (b) htm/htu bind to the real request.
    Both are exercised in tests/test_pop_delegation.py — not assumed.
  * Additive & backward-compatible: a token with no ``cnf`` is a legacy bearer token
    and this module is never consulted for it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Optional, Protocol, runtime_checkable

import jwt
from jwt import InvalidTokenError
from jwt.algorithms import ECAlgorithm, OKPAlgorithm

from interfaces import MAX_DELEGATION_CHAIN, constant_time_equals

# RFC 8693 token-exchange marker for an "Identity and Authorization Grant JWT"
# (ID-JAG, draft-ietf-oauth-identity-chaining). A token declaring this token-type
# (as a top-level `token_type` claim or a header `typ`) arrived via an identity-
# chaining exchange. Recognition is ADDITIVE: it is still a JWT verified exactly as
# today ({EdDSA, RS256}, iss/aud/temporal/required-claims) — no new trust root, no
# assumed act/sub schema.
ID_JAG_TOKEN_TYPE: str = "urn:ietf:params:oauth:token-type:id-jag"

# Proof signatures: asymmetric only, same discipline as the identity token. No
# ``none``, no HMAC — a PoP proof an attacker can forge is not a proof.
POP_ALGORITHMS: tuple[str, ...] = ("EdDSA", "ES256")

# A proof is single-use and short-lived; this bounds acceptable clock skew and age.
POP_MAX_AGE_SECONDS: int = 120
POP_CLOCK_SKEW_SECONDS: int = 30

# Private-key members that must NEVER appear in a proof's public JWK.
_PRIVATE_JWK_MEMBERS: frozenset[str] = frozenset({"d", "p", "q", "dp", "dq", "qi", "k"})


class PopError(Exception):
    """Any proof-of-possession verification failure (fail-closed → JWT_INVALID)."""


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """
    RFC 7638 JWK thumbprint (SHA-256, base64url, no padding).

    Only the REQUIRED members for the key type are hashed, in lexicographic order,
    with compact separators — exactly as the RFC mandates, so the thumbprint is
    canonical and independent of member ordering or extra members.
    """
    kty = jwk.get("kty")
    if kty == "OKP":
        members = {"crv": jwk.get("crv"), "kty": "OKP", "x": jwk.get("x")}
    elif kty == "EC":
        members = {"crv": jwk.get("crv"), "kty": "EC", "x": jwk.get("x"), "y": jwk.get("y")}
    else:
        raise PopError(f"unsupported JWK kty {kty!r}")
    if any(v is None or not isinstance(v, str) or not v for v in members.values()):
        raise PopError("JWK is missing required members")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64url_nopad(hashlib.sha256(canonical).digest())


def _public_key_from_jwk(jwk: dict[str, Any]) -> Any:
    """Build a public key object from a public JWK (OKP/Ed25519 or EC/P-256)."""
    kty = jwk.get("kty")
    payload = json.dumps(jwk)
    try:
        if kty == "OKP":
            return OKPAlgorithm.from_jwk(payload)
        if kty == "EC":
            return ECAlgorithm.from_jwk(payload)
    except Exception as exc:  # noqa: BLE001 — any parse failure is a fail-closed proof error.
        raise PopError("proof JWK is not a valid public key") from exc
    raise PopError(f"unsupported JWK kty {kty!r}")


def _normalize_htu(url: str) -> str:
    """
    Normalize an htu for comparison: strip the query and fragment (a proof binds to
    the resource, not to volatile query params) and drop a trailing slash.
    """
    base = url.split("?", 1)[0].split("#", 1)[0]
    if len(base) > 1 and base.endswith("/"):
        base = base[:-1]
    return base


@runtime_checkable
class ReplayGuard(Protocol):
    """Records a proof ``jti`` exactly once. ``record`` returns True iff NEWLY seen."""

    async def record(self, jti: str, *, ttl_seconds: int) -> bool: ...


class InMemoryReplayGuard:
    """Single-process replay guard for tests / the reference pipeline (no TTL evict)."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    async def record(self, jti: str, *, ttl_seconds: int) -> bool:
        if jti in self._seen:
            return False
        self._seen.add(jti)
        return True


class RedisReplayGuard:
    """
    Production replay guard: an atomic ``SET key 1 NX EX ttl``. NX makes first-writer-
    wins across every stateless node, and EX bounds memory to the proof lifetime.
    Fail-closed: a transport error is treated as "cannot prove single-use" → replay.
    """

    def __init__(self, redis: Any, *, prefix: str = "mcpip:pop:jti:") -> None:
        self._redis = redis
        self._prefix = prefix

    async def record(self, jti: str, *, ttl_seconds: int) -> bool:
        try:
            ok = await self._redis.set(self._prefix + jti, "1", nx=True, ex=ttl_seconds)
        except Exception:  # noqa: BLE001 — cannot confirm single-use → fail closed.
            return False
        return bool(ok)


async def verify_pop_proof(
    proof: str,
    *,
    expected_jkt: str,
    http_method: str,
    http_url: str,
    access_token: str,
    expected_payload_hash: str,
    now_ts: float,
    replay: ReplayGuard,
    max_age_seconds: int = POP_MAX_AGE_SECONDS,
) -> None:
    """
    Verify a DPoP-style proof binds the caller (by key possession) to THIS ACTION.

    Order is load-bearing and every step fails closed:
      1. Header, untrusted: typ == "dpop+jwt", alg in the asymmetric allow-list, a
         PUBLIC jwk present (private members rejected).
      2. Thumbprint binding: SHA-256 JWK thumbprint == the token's ``cnf.jkt``
         (constant-time). A proof for a different key cannot bind this token.
      3. Signature: verify the JWS with the embedded public key.
      4. Request binding: htm == method, htu == normalized url.
      4b. ACTION binding: ``ath`` == SHA-256(access token) and ``pch`` == the
          canonical payload hash (the SAME digest the PIN lock binds). Without
          this the proof would attest only "some call to this endpoint by this
          key, now" — and since every alias shares one endpoint URL, a sniffed /
          relayed proof could be substituted onto a different alias or arguments.
          ``pch`` makes the proof the machine analog of the payload-bound PIN;
          ``ath`` pins it to the exact bearer token presented (RFC 9449).
      5. Freshness: iat within [now - max_age, now + skew].
      6. Single-use: the jti is recorded exactly once (replay guard).
    """
    if not isinstance(proof, str) or not proof:
        raise PopError("missing proof-of-possession")

    try:
        header = jwt.get_unverified_header(proof)
    except InvalidTokenError as exc:
        raise PopError("malformed proof header") from exc

    if header.get("typ") != "dpop+jwt":
        raise PopError("proof typ must be dpop+jwt")
    alg = header.get("alg")
    if alg not in POP_ALGORITHMS:
        raise PopError(f"proof alg {alg!r} not permitted")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise PopError("proof header must carry a public jwk")
    if any(member in jwk for member in _PRIVATE_JWK_MEMBERS):
        raise PopError("proof jwk must not contain private key material")

    # 2) Binding to the token's confirmed key.
    jkt = jwk_thumbprint(jwk)
    if not constant_time_equals(jkt, expected_jkt):
        raise PopError("proof key thumbprint does not match token cnf")

    # 3) Signature — reject none/HMAC by passing only the asymmetric allow-list.
    key = _public_key_from_jwk(jwk)
    try:
        payload: dict[str, Any] = jwt.decode(
            proof,
            key=key,
            algorithms=[alg],
            options={
                "require": ["htm", "htu", "ath", "pch", "iat", "jti"],
                "verify_signature": True,
                "verify_aud": False,
                "verify_exp": True,  # only enforced if present; proofs use iat+max_age
            },
        )
    except InvalidTokenError as exc:
        raise PopError(f"proof signature/claims invalid: {exc}") from exc

    # 4) Request binding.
    htm = payload.get("htm")
    if not isinstance(htm, str) or htm.upper() != http_method.upper():
        raise PopError("proof htm does not match request method")
    htu = payload.get("htu")
    if not isinstance(htu, str) or _normalize_htu(htu) != _normalize_htu(http_url):
        raise PopError("proof htu does not match request url")

    # 4b) Action binding — token hash (ath) + canonical payload hash (pch). Both
    #     constant-time; a proof minted for one token/action cannot be replayed
    #     onto another at the same endpoint.
    expected_ath = _b64url_nopad(hashlib.sha256(access_token.encode("ascii")).digest())
    ath = payload.get("ath")
    if not isinstance(ath, str) or not constant_time_equals(ath, expected_ath):
        raise PopError("proof ath does not match the presented token")
    pch = payload.get("pch")
    if not isinstance(pch, str) or not constant_time_equals(pch, expected_payload_hash):
        raise PopError("proof pch does not match the request payload")

    # 5) Freshness.
    iat = payload.get("iat")
    if not isinstance(iat, (int, float)):
        raise PopError("proof iat missing")
    if iat > now_ts + POP_CLOCK_SKEW_SECONDS or iat < now_ts - max_age_seconds:
        raise PopError("proof is stale or future-dated")

    # 6) Exactly-once.
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        raise PopError("proof jti missing")
    if not await replay.record(jti, ttl_seconds=max_age_seconds + POP_CLOCK_SKEW_SECONDS):
        raise PopError("proof replayed (jti already seen)")


def project_cnf_jkt(claims: dict[str, Any]) -> Optional[str]:
    """
    Extract the sender-constraint ``cnf.jkt`` from verified JWT claims.

    Absent → None (bearer token, back-compat). Present but malformed → PopError
    (fail-closed → JWT_INVALID): a ``cnf`` we cannot interpret must never silently
    downgrade a token to bearer.
    """
    cnf = claims.get("cnf")
    if cnf is None:
        return None
    if not isinstance(cnf, dict):
        raise PopError("cnf claim must be an object")
    jkt = cnf.get("jkt")
    if not isinstance(jkt, str) or not jkt:
        raise PopError("cnf.jkt must be a non-empty string")
    return jkt


def project_act_sub(claims: dict[str, Any]) -> Optional[str]:
    """
    Extract the delegation actor ``act.sub`` (RFC 8693) from verified JWT claims.

    Absent → None (not a delegation chain). Present but malformed → PopError.
    """
    act = claims.get("act")
    if act is None:
        return None
    if not isinstance(act, dict):
        raise PopError("act claim must be an object")
    sub = act.get("sub")
    if not isinstance(sub, str) or not sub:
        raise PopError("act.sub must be a non-empty string")
    return sub


def project_act_chain(claims: dict[str, Any]) -> tuple[str, ...]:
    """
    Extract the FULL RFC 8693 nested delegation chain from verified JWT claims.

    Walks ``act`` → ``act.act`` → ``act.act.act`` → … collecting each node's ``sub``
    in ORDER (immediate actor first, the ultimate delegator last). This is the
    multi-hop generalization of ``project_act_sub`` (which returns only the first
    hop); ``project_act_sub`` stays byte-for-byte unchanged for backward compat.

    Fail-closed, mirroring ``project_act_sub``'s malformed rules at EVERY hop: a node
    that is not a dict, or whose ``sub`` is empty / not a str, raises ``PopError`` — a
    malformed nested actor must never silently downgrade to a shorter (or bearer)
    chain. Absent ``act`` → ``()`` (not a delegation chain, legacy behavior).

    Bounded by ``MAX_DELEGATION_CHAIN``: JSON has no cycles, so the walk terminates on
    the first absent trailing ``act``; the bound additionally caps work at MAX+1
    iterations, defeating a claim-stuffing / deeply-nested token. Exceeding it raises
    ``PopError``.
    """
    node = claims.get("act")
    if node is None:
        return ()
    chain: list[str] = []
    while node is not None:
        if not isinstance(node, dict):
            raise PopError("act claim must be an object")
        sub = node.get("sub")
        if not isinstance(sub, str) or not sub:
            raise PopError("act.sub must be a non-empty string")
        if len(chain) >= MAX_DELEGATION_CHAIN:
            raise PopError("delegation chain exceeds maximum length")
        chain.append(sub)
        node = node.get("act")
    return tuple(chain)


def is_id_jag(claims: dict[str, Any], header: dict[str, Any]) -> bool:
    """
    Recognize an ID-JAG (identity-chaining) token by its token-type marker.

    True iff a top-level ``token_type`` claim OR the JWT ``typ`` header equals
    ``ID_JAG_TOKEN_TYPE``. Recognition ONLY — it changes nothing about verification
    (no new trust root, no alg change, no assumed act/sub schema). A normal token
    (``typ`` ``'JWT'``, no ``token_type``) → False.
    """
    return (
        claims.get("token_type") == ID_JAG_TOKEN_TYPE
        or header.get("typ") == ID_JAG_TOKEN_TYPE
    )


__all__ = [
    "PopError",
    "POP_ALGORITHMS",
    "POP_MAX_AGE_SECONDS",
    "ID_JAG_TOKEN_TYPE",
    "jwk_thumbprint",
    "verify_pop_proof",
    "project_cnf_jkt",
    "project_act_sub",
    "project_act_chain",
    "is_id_jag",
    "ReplayGuard",
    "InMemoryReplayGuard",
    "RedisReplayGuard",
]
