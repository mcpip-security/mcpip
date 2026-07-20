"""
MCPIP V2 — Auth: JWT identity sovereignty.

    ◐ Auth: "A payload-bound PIN that's spent exactly once, or the action never runs."

Identity (tenant_id, agent_id, role) comes EXCLUSIVELY from a cryptographically
verified JWT. Nothing in the LLM tool-call payload can influence it.

Hardening:
  * Algorithms pinned to {EdDSA, RS256}. ``alg=none`` and any HMAC (HS*) are
    rejected — first by an explicit header-alg allow-list check (defeats the
    RS256→HS256 key-confusion trick), then again by PyJWT's own ``algorithms=``.
  * Eight claims are REQUIRED and verified: exp, iat, nbf, iss, aud, tenant_id,
    agent_id, role. exp/iat/nbf are time-verified; iss/aud are matched to config.
  * Any failure raises — the gateway converts to JWT_INVALID / JWT_CLAIMS_MISSING
    and denies fail-closed.

``KeyProvider`` is an ABC so a future JWKS-backed provider can drop in without
touching this resolver. The shipped ``StaticPEMKeyProvider`` returns one public
key regardless of ``kid`` (sufficient for a single-IdP deployment/demo).
"""

from __future__ import annotations

import json
import uuid
from abc import ABC, abstractmethod
from typing import Any, Optional, Protocol, Sequence, runtime_checkable

import jwt
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jwt import InvalidTokenError, MissingRequiredClaimError
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm

from interfaces import MAX_CAPABILITIES, Identity
from auth.pop import (
    PopError,
    is_id_jag,
    project_act_chain,
    project_act_sub,
    project_cnf_jkt,
)

# Private JWK members that must NEVER appear in a published (public) JWKS.
_PRIVATE_JWK_MEMBERS: frozenset[str] = frozenset({"d", "p", "q", "dp", "dq", "qi", "k"})

# Algorithms MCPIP will ever accept. Asymmetric only — no shared-secret HMAC.
ALLOWED_ALGORITHMS: tuple[str, ...] = ("EdDSA", "RS256")

# Claims that MUST be present and (for the temporal/identity ones) verified.
REQUIRED_CLAIMS: tuple[str, ...] = (
    "exp",
    "iat",
    "nbf",
    "iss",
    "aud",
    "tenant_id",
    "agent_id",
    "role",
)


class TokenError(Exception):
    """Raised on any JWT verification or claim-shape failure (fail-closed)."""


class TokenClaimsMissing(TokenError):
    """A required claim was absent. Gateway maps this to JWT_CLAIMS_MISSING."""


class KeyProvider(ABC):
    """
    Resolves the verification key for a given JWT header.

    Two providers ship: ``StaticPEMKeyProvider`` (one key for every ``kid`` — a
    single-IdP deployment/demo) and ``JWKSKeyProvider`` (select by ``kid`` from a
    JWKS document — an IdP / workload-identity STS that rotates signing keys).
    """

    @abstractmethod
    def resolve(self, header: dict[str, Any]) -> bytes | str:
        """Return the public key (PEM bytes or str) for this token header."""
        raise NotImplementedError  # pragma: no cover - abstract contract.


class StaticPEMKeyProvider(KeyProvider):
    """
    Single-key provider: returns one PEM public key for every ``kid``.

    Suitable for a deployment with exactly one trusted issuing key (the demo
    generates an Ed25519 keypair at startup and hands the public PEM here).
    """

    def __init__(self, pem: bytes | str) -> None:
        self._pem = pem

    def resolve(self, header: dict[str, Any]) -> bytes | str:
        # kid is ignored by design; one key serves the whole IdP.
        return self._pem


def _jwk_to_public_pem(jwk: dict[str, Any]) -> bytes:
    """
    Serialize a PUBLIC JWK (OKP / RSA / EC) to SubjectPublicKeyInfo PEM.

    Private material is rejected outright — a published JWKS is public-only, and a
    JWKS carrying private keys is a misconfiguration we must not silently accept.
    ``TokenError`` on anything malformed (fail-closed → JWT_INVALID upstream).
    """
    if any(member in jwk for member in _PRIVATE_JWK_MEMBERS):
        raise TokenError("JWKS key must not contain private key material")
    kty = jwk.get("kty")
    payload = json.dumps(jwk)
    try:
        if kty == "OKP":
            key: Any = OKPAlgorithm.from_jwk(payload)
        elif kty == "RSA":
            key = RSAAlgorithm.from_jwk(payload)
        elif kty == "EC":
            key = ECAlgorithm.from_jwk(payload)
        else:
            raise TokenError(f"unsupported JWKS key type {kty!r}")
    except TokenError:
        raise
    except Exception as exc:  # noqa: BLE001 — any parse failure is a fail-closed key error.
        raise TokenError("malformed JWKS key") from exc
    pem: bytes = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return pem


class JWKSKeyProvider(KeyProvider):
    """
    Multi-key provider backed by a JWKS document, selecting the verification key by
    the token header's ``kid``.

    This is the drop-in for a real IdP / workload-identity STS that ROTATES signing
    keys: publish several keys under distinct ``kid`` values, and a token names the
    key that signed it. Only the key types behind the identity alg allow-list matter
    (OKP→EdDSA, RSA→RS256); the alg allow-list in ``TokenResolver`` remains the gate,
    so an EC key in the JWKS still cannot be used to smuggle an ``ES256`` identity
    token.

    Deliberately NOT network-fetching. The JWKS is supplied at construction (loaded
    from config / a mounted file / a boot-time fetch the operator performs), so the
    per-request auth path stays free of a synchronous JWKS round-trip — a fetch on
    the hot path would be a fail-closed single point of failure. Rotate by supplying
    an updated document (overlap old+new ``kid`` across the rotation window).
    """

    def __init__(self, jwks: dict[str, Any]) -> None:
        keys = jwks.get("keys")
        if not isinstance(keys, list) or not keys:
            raise TokenError("JWKS document must contain a non-empty 'keys' array")
        by_kid: dict[str, bytes] = {}
        for jwk in keys:
            if not isinstance(jwk, dict):
                raise TokenError("JWKS key entry must be an object")
            kid = jwk.get("kid")
            if not isinstance(kid, str) or not kid:
                raise TokenError("every JWKS key must carry a non-empty 'kid'")
            if kid in by_kid:
                raise TokenError(f"duplicate kid {kid!r} in JWKS")
            by_kid[kid] = _jwk_to_public_pem(jwk)
        self._by_kid = by_kid

    def resolve(self, header: dict[str, Any]) -> bytes | str:
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenError("token header missing 'kid' (required with a JWKS provider)")
        pem = self._by_kid.get(kid)
        if pem is None:
            raise TokenError(f"no JWKS key for kid {kid!r}")
        return pem


@runtime_checkable
class IdentityResolver(Protocol):
    """Anything that verifies a JWT and returns a sovereign ``Identity``.

    Both ``TokenResolver`` (single issuer) and ``MultiIssuerResolver`` satisfy this,
    so the engine can be wired with either without knowing which.
    """

    def resolve(self, token: str) -> Identity: ...

    @property
    def issuers(self) -> tuple[str, ...]:
        """The trusted issuer(s) this resolver verifies against (RFC 9728 discovery)."""
        ...


class TokenResolver:
    """Verifies a JWT and projects it into a frozen ``Identity``."""

    def __init__(
        self,
        key_provider: KeyProvider,
        *,
        issuer: str,
        audience: str,
        algorithms: Sequence[str] = ALLOWED_ALGORITHMS,
        attesting: bool = True,
    ) -> None:
        self._key_provider = key_provider
        self._issuer = issuer
        self._audience = audience
        # Freeze to a tuple so the allow-list cannot be mutated post-construction.
        self._algorithms: tuple[str, ...] = tuple(algorithms)
        # Whether a `cnf` minted by THIS issuer counts as ATTESTED for the
        # sender-constraint gate. A single-issuer deployment leaves this True (its one
        # issuer is the attesting authority); a multi-issuer deployment sets it False
        # for a lower-assurance identity IdP so its `cnf` cannot satisfy a resource that
        # demands an attested sender-constrained token (closes the downgrade lane).
        self._attesting = attesting

    @property
    def issuer(self) -> str:
        """The single issuer this resolver trusts (routing key for MultiIssuerResolver)."""
        return self._issuer

    @property
    def issuers(self) -> tuple[str, ...]:
        """The trusted issuer set as a tuple (one issuer for a single-IdP resolver).

        Read-only; used by the RFC 9728 Protected Resource Metadata builder so the
        discovery document derives its ``authorization_servers`` from the live resolver
        rather than re-reading configuration.
        """
        return (self._issuer,)

    def resolve(self, token: str) -> Identity:
        """
        Verify ``token`` and return the sovereign ``Identity``.

        Raises ``TokenError`` on ANY problem: bad/absent header, disallowed alg,
        signature failure, expired/not-yet-valid, wrong iss/aud, or a missing
        required claim. The gateway maps this to a JWT_* deny.
        """
        if not isinstance(token, str) or not token:
            raise TokenError("token must be a non-empty string")

        # 1) Inspect the header WITHOUT trusting it — reject alg=none / HS* early.
        #    This blocks the classic key-confusion attack where an attacker signs
        #    with HMAC using the RSA public key as the secret and sets alg=HS256.
        try:
            header = jwt.get_unverified_header(token)
        except InvalidTokenError as exc:
            raise TokenError("malformed JWT header") from exc

        alg = header.get("alg")
        if alg not in self._algorithms:
            # Covers "none", "HS256", "HS384", "HS512", and anything unlisted.
            raise TokenError(f"algorithm {alg!r} not permitted")

        key = self._key_provider.resolve(header)

        # 2) Full cryptographic verification with the pinned algorithm list and
        #    strict claim requirements. PyJWT verifies exp/iat/nbf/aud/iss and
        #    enforces presence of the ``require`` list.
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=list(self._algorithms),
                audience=self._audience,
                issuer=self._issuer,
                options={
                    "require": list(REQUIRED_CLAIMS),
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except MissingRequiredClaimError as exc:
            # A required claim is absent — distinct deny reason for the audit trail.
            raise TokenClaimsMissing(f"missing required claim: {exc}") from exc
        except InvalidTokenError as exc:
            # One opaque type upstream — the specific cause goes only to WORM.
            raise TokenError(f"jwt verification failed: {exc}") from exc

        # 3) Project verified claims into a frozen Identity. Defensive re-check of
        #    the identity claims (PyJWT's ``require`` already guarantees presence,
        #    but we assert non-empty string types before trusting them).
        try:
            tenant_id = _require_str(claims, "tenant_id")
            agent_id = _require_str(claims, "agent_id")
            role = _require_str(claims, "role")
        except KeyError as exc:
            raise TokenClaimsMissing(f"missing identity claim: {exc}") from exc
        except TypeError as exc:
            raise TokenError(f"malformed identity claim: {exc}") from exc

        # 4) OPTIONAL compartment + capabilities (UUID-identified authorization).
        #    Absent → None/() so legacy 8-claim tokens behave EXACTLY as before.
        #    Malformed/oversized → TokenError (fail-closed, mapped to JWT_INVALID).
        compartment = _optional_uuid_claim(claims, "compartment")
        capabilities = _capabilities_claim(claims)

        # 5) OPTIONAL sender-constraint (cnf.jkt) + delegation actor (act.sub).
        #    Absent → None (legacy bearer token, unchanged). A malformed cnf/act must
        #    NOT silently downgrade the token to bearer → fail-closed to JWT_INVALID.
        #    act_chain captures the FULL nested delegation chain (WORM/audit only);
        #    act_sub keeps the single-hop actor unchanged; id_jag records whether the
        #    identity arrived via an ID-JAG exchange. A malformed NESTED act now fails
        #    JWT_INVALID here rather than silently authenticating on the first hop.
        try:
            cnf_jkt = project_cnf_jkt(claims)
            act_sub = project_act_sub(claims)
            act_chain = project_act_chain(claims)
            id_jag = is_id_jag(claims, header)
        except PopError as exc:
            raise TokenError(str(exc)) from exc

        # 6) OPTIONAL SEP-2352 issuer-binding hint (defense-in-depth). If the token
        #    asserts a top-level ``iss_binding``, it MUST equal the CRYPTOGRAPHICALLY
        #    VERIFIED issuer (``self._issuer`` — jwt.decode already matched iss against
        #    it). A mismatch means a re-wrapped / token-exchanged token whose internal
        #    issuer assertion disagrees with the AS that actually signed it → fail
        #    closed (mapped to the opaque JWT_INVALID the agent already sees). Absent ⇒
        #    no-op, so legacy tokens are byte-identical. This adds NO Identity field
        #    (``issuer`` already carries the verified value) and touches nothing in the
        #    {EdDSA, RS256} alg gate — it is an ADDITIONAL check AFTER full verification,
        #    never a relaxation. Living inside the per-issuer resolver, it is inherited
        #    automatically by ``MultiIssuerResolver``.
        iss_binding = claims.get("iss_binding")
        if iss_binding is not None and (
            not isinstance(iss_binding, str) or iss_binding != self._issuer
        ):
            raise TokenError("iss_binding does not match the verified issuer")

        return Identity(
            tenant_id=tenant_id,
            agent_id=agent_id,
            role=role,
            issuer=self._issuer,
            audience=self._audience,
            jti=claims.get("jti"),
            compartment=compartment,
            capabilities=capabilities,
            cnf_jkt=cnf_jkt,
            act_sub=act_sub,
            act_chain=act_chain,
            id_jag=id_jag,
            # A cnf is ATTESTED only when it came from an attesting issuer.
            cnf_attested=cnf_jkt is not None and self._attesting,
        )


class MultiIssuerResolver:
    """
    Verify a JWT against a SET of trusted issuers, each with its own key, audience,
    and attesting designation.

    Selection is by the token's ``iss`` claim: the UNVERIFIED iss routes to the
    per-issuer ``TokenResolver``, which then fully verifies (signature, ``iss`` ==
    its config, ``aud``, temporal, required claims). No trust is placed in the
    unverified value beyond routing — a forged ``iss`` merely selects a resolver
    that then rejects the token on the signature, exactly as a single-issuer
    resolver would. An ``iss`` naming no trusted issuer is a fail-closed
    ``TokenError``.

    The whole point is the ``attesting`` axis: trusting a lower-assurance identity
    IdP (``attesting=False``) for authentication no longer lets its ``cnf`` satisfy a
    resource that DEMANDS an attested sender-constrained token — the per-issuer flag
    flows to ``Identity.cnf_attested`` and the gate checks it. This closes the
    weak-issuer downgrade lane.
    """

    def __init__(self, resolvers: Sequence[TokenResolver]) -> None:
        by_iss: dict[str, TokenResolver] = {}
        for resolver in resolvers:
            if resolver.issuer in by_iss:
                raise TokenError(f"duplicate trusted issuer {resolver.issuer!r}")
            by_iss[resolver.issuer] = resolver
        if not by_iss:
            raise TokenError("at least one issuer resolver is required")
        self._by_iss = by_iss

    @property
    def issuers(self) -> tuple[str, ...]:
        """The full set of trusted issuers, sorted for a deterministic discovery doc.

        Read-only; the RFC 9728 Protected Resource Metadata builder reads this so a
        multi-issuer deployment publishes every trusted ``authorization_servers`` entry.
        """
        return tuple(sorted(self._by_iss))

    def resolve(self, token: str) -> Identity:
        if not isinstance(token, str) or not token:
            raise TokenError("token must be a non-empty string")
        # Peek the issuer WITHOUT trusting it — routing only; the selected resolver
        # performs the full cryptographic + claim verification.
        try:
            unverified: dict[str, Any] = jwt.decode(
                token,
                options={
                    "verify_signature": False,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_aud": False,
                    "verify_iss": False,
                },
            )
        except InvalidTokenError as exc:
            raise TokenError("malformed JWT") from exc
        iss = unverified.get("iss")
        if not isinstance(iss, str) or not iss:
            raise TokenError("token missing a string 'iss' claim")
        resolver = self._by_iss.get(iss)
        if resolver is None:
            raise TokenError(f"untrusted issuer {iss!r}")
        return resolver.resolve(token)


def _require_str(claims: dict[str, Any], name: str) -> str:
    """Fetch ``name`` from claims, asserting it is a non-empty string."""
    value = claims[name]  # KeyError if absent (should not happen after require).
    if not isinstance(value, str) or not value:
        raise TypeError(f"claim '{name}' must be a non-empty string")
    return value


def _optional_uuid_claim(claims: dict[str, Any], name: str) -> Optional[str]:
    """
    Parse an OPTIONAL claim that, when present, must be a well-formed UUID string.

    Absent → None (back-compat). Present-but-not-a-string or not-a-UUID → TokenError
    (fail-closed → JWT_INVALID). The compartment id is UUID-identified; a human label
    never appears on the wire.
    """
    value = claims.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise TokenError(f"claim '{name}' must be a string")
    try:
        uuid.UUID(value)
    except ValueError as exc:
        raise TokenError(f"claim '{name}' is not a well-formed UUID") from exc
    return value


def _capabilities_claim(claims: dict[str, Any]) -> tuple[str, ...]:
    """
    Parse the OPTIONAL ``capabilities`` claim into a frozen tuple of UUID strings.

    Absent → empty tuple. Must be a list, size-bounded by ``MAX_CAPABILITIES``, with
    every entry a well-formed UUID string. Any deviation → TokenError (fail-closed →
    JWT_INVALID). Size-bounding defeats a resource-exhaustion / claim-stuffing token.
    """
    raw = claims.get("capabilities")
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > MAX_CAPABILITIES:
        raise TokenError("capabilities claim malformed or oversized")
    out: list[str] = []
    for c in raw:
        if not isinstance(c, str):
            raise TokenError("capability entry must be a string")
        try:
            uuid.UUID(c)
        except ValueError as exc:
            raise TokenError("capability entry is not a well-formed UUID") from exc
        out.append(c)
    return tuple(out)


__all__ = [
    "ALLOWED_ALGORITHMS",
    "REQUIRED_CLAIMS",
    "TokenError",
    "TokenClaimsMissing",
    "KeyProvider",
    "StaticPEMKeyProvider",
    "JWKSKeyProvider",
    "IdentityResolver",
    "TokenResolver",
    "MultiIssuerResolver",
]
