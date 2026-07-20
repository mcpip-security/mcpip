"""
MCPIP — multi-issuer trust + attesting-issuer scoping.

    ◐ Auth: trusting a weak issuer for identity must never downgrade the
    sender-constraint gate.

`MultiIssuerResolver` verifies a JWT against a SET of trusted issuers, each with
its own key, audience, and ``attesting`` designation. The per-issuer flag flows to
``Identity.cnf_attested`` — a resource that DEMANDS sender-constraint is satisfied
only by a `cnf` from an attesting issuer, closing the weak-issuer downgrade lane.

Pure tests (no Redis / app boot): the resolver-level guarantees. The end-to-end
gate check (a non-attested cnf is refused at a `require_sender_constraint` alias
even with a valid proof) lives in `test_authorize_api.py`.
"""

from __future__ import annotations

import time
from typing import Any, Optional

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from auth import MultiIssuerResolver, StaticPEMKeyProvider, TokenError, TokenResolver

_AUD = "mcpip-gateway"


def _idp() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_pem = priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem


def _token(priv_pem: bytes, *, iss: str, cnf: Optional[str] = None, **over: Any) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": iss,
        "aud": _AUD,
        "tenant_id": "tenant-acme",
        "agent_id": "agent-1",
        "role": "ops",
        "exp": now + 300,
        "iat": now,
        "nbf": now,
    }
    if cnf is not None:
        claims["cnf"] = {"jkt": cnf}
    claims.update(over)
    return jwt.encode(claims, priv_pem, algorithm="EdDSA")


def _resolver(pub: bytes, iss: str, *, attesting: bool = True) -> TokenResolver:
    return TokenResolver(
        StaticPEMKeyProvider(pub), issuer=iss, audience=_AUD, attesting=attesting
    )


# ---------------------------------------------------------------------------
# Attesting designation → Identity.cnf_attested.
# ---------------------------------------------------------------------------


def test_attesting_issuer_cnf_is_attested() -> None:
    priv, pub = _idp()
    multi = MultiIssuerResolver([_resolver(pub, "iss-strong", attesting=True)])
    ident = multi.resolve(_token(priv, iss="iss-strong", cnf="jkt-1"))
    assert ident.cnf_jkt == "jkt-1"
    assert ident.cnf_attested is True
    assert ident.issuer == "iss-strong"


def test_non_attesting_issuer_cnf_is_not_attested() -> None:
    """The downgrade lane: a weak issuer's cnf is a cnf, but it is NOT attested."""
    priv, pub = _idp()
    multi = MultiIssuerResolver([_resolver(pub, "iss-weak", attesting=False)])
    ident = multi.resolve(_token(priv, iss="iss-weak", cnf="jkt-2"))
    assert ident.cnf_jkt == "jkt-2"
    assert ident.cnf_attested is False


def test_no_cnf_is_never_attested() -> None:
    priv, pub = _idp()
    multi = MultiIssuerResolver([_resolver(pub, "iss-strong", attesting=True)])
    ident = multi.resolve(_token(priv, iss="iss-strong"))
    assert ident.cnf_jkt is None and ident.cnf_attested is False


# ---------------------------------------------------------------------------
# Routing + fail-closed selection.
# ---------------------------------------------------------------------------


def test_routes_by_issuer_to_the_matching_key() -> None:
    s_priv, s_pub = _idp()
    w_priv, w_pub = _idp()
    multi = MultiIssuerResolver(
        [_resolver(s_pub, "iss-strong"), _resolver(w_pub, "iss-weak", attesting=False)]
    )
    assert multi.resolve(_token(w_priv, iss="iss-weak")).issuer == "iss-weak"
    assert multi.resolve(_token(s_priv, iss="iss-strong")).issuer == "iss-strong"


def test_untrusted_issuer_rejected() -> None:
    priv, pub = _idp()
    multi = MultiIssuerResolver([_resolver(pub, "iss-strong")])
    with pytest.raises(TokenError, match="untrusted issuer"):
        multi.resolve(_token(priv, iss="iss-rogue"))


def test_forged_issuer_fails_on_signature() -> None:
    """A token CLAIMING a trusted issuer but signed by a different key routes to that
    issuer's resolver and is rejected on the signature — routing trusts nothing."""
    s_priv, s_pub = _idp()
    w_priv, w_pub = _idp()
    multi = MultiIssuerResolver(
        [_resolver(s_pub, "iss-strong"), _resolver(w_pub, "iss-weak")]
    )
    forged = _token(w_priv, iss="iss-strong")  # weak key, strong iss claim
    with pytest.raises(TokenError):
        multi.resolve(forged)


def test_missing_iss_rejected() -> None:
    priv, pub = _idp()
    multi = MultiIssuerResolver([_resolver(pub, "iss-strong")])
    # Build a token whose iss we blank out (still signed correctly).
    now = int(time.time())
    claims = {
        "aud": _AUD, "tenant_id": "t", "agent_id": "a", "role": "ops",
        "exp": now + 300, "iat": now, "nbf": now,
    }
    token = jwt.encode(claims, priv, algorithm="EdDSA")
    with pytest.raises(TokenError, match="iss"):
        multi.resolve(token)


def test_duplicate_issuer_rejected() -> None:
    _p, pub = _idp()
    with pytest.raises(TokenError, match="duplicate"):
        MultiIssuerResolver([_resolver(pub, "dup"), _resolver(pub, "dup")])


def test_empty_resolver_set_rejected() -> None:
    with pytest.raises(TokenError):
        MultiIssuerResolver([])


# ---------------------------------------------------------------------------
# Single-issuer backward-compatibility (the default path).
# ---------------------------------------------------------------------------


def test_single_resolver_defaults_to_attesting() -> None:
    """A single-issuer TokenResolver treats its one issuer as attesting by default,
    so all existing cnf tokens stay attested — no behavior change."""
    priv, pub = _idp()
    ident = _resolver(pub, "iss").resolve(_token(priv, iss="iss", cnf="jkt-x"))
    assert ident.cnf_attested is True


def test_single_resolver_can_be_marked_non_attesting() -> None:
    priv, pub = _idp()
    ident = _resolver(pub, "iss", attesting=False).resolve(
        _token(priv, iss="iss", cnf="jkt-x")
    )
    assert ident.cnf_attested is False
