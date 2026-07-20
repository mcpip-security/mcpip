"""
MCPIP V2 — JWKS refresh helper test suite (off-hot-path key-set rotation).

    ◐  "The key set that verifies identity may rotate — but it never goes empty."

Exercises the REAL ``JWKSRefresher`` end to end. The verification-key set is NEVER emptied:

  * ``resolve`` delegates to the live inner ``JWKSKeyProvider`` (the only hot-path op) and
    a token signed by a seeded key verifies through a real ``TokenResolver``;
  * a successful ``refresh`` swaps in a validated NEW set — a rotated-in ``kid`` verifies, a
    removed ``kid`` is grace-then-rejected — while the alg allow-list stays the gate;
  * a FAILED refresh (non-2xx / oversized / malformed / private-material / too-many-keys /
    transport / SSRF rejection) RETAINS the last-good set and an unknown ``kid`` still fails
    CLOSED (``TokenError``), never an open pass, never an empty set;
  * the SSRF guard rejects an http / loopback / link-local JWKS URL (real DNS);
  * the fetch client is HERMETIC (``trust_env=False`` + ``proxy=None``, no redirects).

Only the network I/O boundary is ever stubbed — a fake ``httpx.AsyncClient`` and (for the
fetch-logic tests) ``_resolve_and_validate``, exactly mirroring
``tests/test_authn_channel.py``'s hermetic webhook test. The refresher's OWN logic
(build-before-swap, retain-on-failure, the size / key-count caps, ``JWKSKeyProvider``
validation) runs for real, and the SSRF tests use the real guard against real DNS.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Optional

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from jwt.algorithms import OKPAlgorithm

import auth.jwks_refresher as jr
from auth import JWKSRefreshError, JWKSRefresher, TokenError
from auth.token_resolver import JWKSKeyProvider, TokenResolver
from interfaces import MAX_JWKS_DOC_BYTES, MAX_JWKS_KEYS

_ISS = "https://sts.mcpip.example"
_AUD = "mcpip-gateway"
_URL = "https://sts.mcpip.example/.well-known/jwks.json"


# ---------------------------------------------------------------------------
# Key / token helpers.
# ---------------------------------------------------------------------------


def _okp(kid: str) -> tuple[bytes, dict[str, Any]]:
    """Return (private PKCS8 PEM, public JWK with kid) for a fresh Ed25519 key."""
    priv = Ed25519PrivateKey.generate()
    pem: bytes = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    jwk: dict[str, Any] = json.loads(OKPAlgorithm.to_jwk(priv.public_key()))
    jwk["kid"] = kid
    return pem, jwk


def _doc(*jwks: dict[str, Any]) -> dict[str, Any]:
    return {"keys": list(jwks)}


def _provider(*jwks: dict[str, Any]) -> JWKSKeyProvider:
    return JWKSKeyProvider(_doc(*jwks))


def _token(priv_pem: bytes, kid: str) -> str:
    now = int(time.time())
    claims = {
        "iss": _ISS,
        "aud": _AUD,
        "tenant_id": "tenant-acme",
        "agent_id": "agent-1",
        "role": "ops",
        "exp": now + 300,
        "iat": now,
        "nbf": now,
    }
    return jwt.encode(claims, priv_pem, algorithm="EdDSA", headers={"kid": kid})


def _resolver(refresher: JWKSRefresher) -> TokenResolver:
    return TokenResolver(refresher, issuer=_ISS, audience=_AUD)


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Fake network boundary (mirrors the webhook hermetic test). Serves one canned
# body + status and captures the AsyncClient construction kwargs.
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, body: bytes, status: int) -> None:
        self._body = body
        self.status_code = status

    async def aiter_raw(self) -> Any:
        # Stream in modest chunks so the size-cap read path is genuinely exercised.
        for i in range(0, len(self._body), 4096):
            yield self._body[i : i + 4096]

    async def aclose(self) -> None:
        return None


def _install_fake_network(
    monkeypatch: pytest.MonkeyPatch,
    *,
    body: bytes,
    status: int = 200,
    captured: Optional[dict[str, Any]] = None,
) -> None:
    """Patch ONLY the socket boundary: DNS validation returns a public IP and the httpx
    client is a canned responder. All refresher logic under test still runs for real."""

    class _FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            if captured is not None:
                captured.update(kwargs)

        async def __aenter__(self) -> "_FakeClient":
            return self

        async def __aexit__(self, *exc: Any) -> None:
            return None

        def build_request(self, *args: Any, **kwargs: Any) -> object:
            return object()

        async def send(self, *args: Any, **kwargs: Any) -> _FakeResponse:
            return _FakeResponse(body, status)

    async def _fake_validate(_host: str, _port: int) -> str:
        return "203.0.113.10"  # TEST-NET-3, a non-blocked public literal.

    monkeypatch.setattr(jr, "_resolve_and_validate", _fake_validate)
    monkeypatch.setattr(jr.httpx, "AsyncClient", _FakeClient)


# ---------------------------------------------------------------------------
# 1) resolve delegates; a seeded key verifies a token end to end.
# ---------------------------------------------------------------------------


def test_resolve_delegates_and_verifies_token() -> None:
    pem, jwk = _okp("k1")
    refresher = JWKSRefresher(_URL, seed=_provider(jwk))
    identity = _resolver(refresher).resolve(_token(pem, "k1"))
    assert identity.tenant_id == "tenant-acme"
    assert identity.agent_id == "agent-1"


# ---------------------------------------------------------------------------
# 2) A successful refresh swaps kid->key: rotated-in verifies, grace overlap, then the
#    removed kid is rejected. The alg allow-list stays the gate throughout.
# ---------------------------------------------------------------------------


def test_refresh_rotates_key_set(monkeypatch: pytest.MonkeyPatch) -> None:
    pem1, jwk1 = _okp("k1")
    pem2, jwk2 = _okp("k2")
    refresher = JWKSRefresher(_URL, seed=_provider(jwk1))

    # Before rotation: k1 verifies, k2 is unknown (fail-closed).
    assert _resolver(refresher).resolve(_token(pem1, "k1")).agent_id == "agent-1"
    with pytest.raises(TokenError):
        _resolver(refresher).resolve(_token(pem2, "k2"))

    # Rotation window: the STS publishes BOTH keys — grace overlap, both verify.
    _install_fake_network(monkeypatch, body=json.dumps(_doc(jwk1, jwk2)).encode())
    _run(refresher.refresh())
    assert _resolver(refresher).resolve(_token(pem1, "k1")).agent_id == "agent-1"
    assert _resolver(refresher).resolve(_token(pem2, "k2")).agent_id == "agent-1"

    # Rotation completes: the old key is withdrawn — a token under the removed kid is now
    # rejected, while the rotated-in key keeps verifying. The set never went empty.
    _install_fake_network(monkeypatch, body=json.dumps(_doc(jwk2)).encode())
    _run(refresher.refresh())
    assert _resolver(refresher).resolve(_token(pem2, "k2")).agent_id == "agent-1"
    with pytest.raises(TokenError):
        _resolver(refresher).resolve(_token(pem1, "k1"))


# ---------------------------------------------------------------------------
# 3) A refresh can add/replace keys but NEVER widen the alg allow-list — an EC (ES256)
#    key rotated into the JWKS still cannot smuggle an ES256 identity token.
# ---------------------------------------------------------------------------


def test_refresh_never_widens_alg_allow_list(monkeypatch: pytest.MonkeyPatch) -> None:
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
    from jwt.algorithms import ECAlgorithm

    pem1, jwk1 = _okp("k1")
    ec_priv = generate_private_key(SECP256R1())
    ec_pem: bytes = ec_priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    ec_jwk: dict[str, Any] = json.loads(ECAlgorithm.to_jwk(ec_priv.public_key()))
    ec_jwk["kid"] = "ec1"

    refresher = JWKSRefresher(_URL, seed=_provider(jwk1))
    _install_fake_network(monkeypatch, body=json.dumps(_doc(jwk1, ec_jwk)).encode())
    _run(refresher.refresh())

    # The EC key is present in the set, but an ES256 token is still refused — the
    # TokenResolver alg allow-list ({EdDSA, RS256}) is the gate, unchanged by refresh.
    now = int(time.time())
    es_token = jwt.encode(
        {
            "iss": _ISS,
            "aud": _AUD,
            "tenant_id": "t",
            "agent_id": "a",
            "role": "ops",
            "exp": now + 300,
            "iat": now,
            "nbf": now,
        },
        ec_pem,
        algorithm="ES256",
        headers={"kid": "ec1"},
    )
    with pytest.raises(TokenError, match="not permitted"):
        _resolver(refresher).resolve(es_token)
    # And the EdDSA key still verifies.
    assert _resolver(refresher).resolve(_token(pem1, "k1")).agent_id == "agent-1"


# ---------------------------------------------------------------------------
# 4) A FAILED refresh retains the last-good set; unknown kid still fails closed.
#    Every failure axis is covered (non-2xx / malformed / private / oversized / too-many).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body,status,match",
    [
        (b'{"keys":[]}', 500, "non-2xx"),  # non-2xx status.
        (b"not json at all", 200, "not valid JSON"),  # malformed body.
        (b'{"keys":[]}', 200, "invalid"),  # empty keys array (JWKSKeyProvider rejects).
        (b"x" * (MAX_JWKS_DOC_BYTES + 1), 200, "size cap"),  # oversized body.
    ],
)
def test_failed_refresh_retains_last_good_set(
    monkeypatch: pytest.MonkeyPatch, body: bytes, status: int, match: str
) -> None:
    pem1, jwk1 = _okp("k1")
    pem2, jwk2 = _okp("k2")
    refresher = JWKSRefresher(_URL, seed=_provider(jwk1))

    _install_fake_network(monkeypatch, body=body, status=status)
    with pytest.raises(JWKSRefreshError, match=match):
        _run(refresher.refresh())

    # RETAINED: the last-good key still verifies; an unknown kid still fails CLOSED
    # (TokenError) — the set was never emptied nor swapped for a degenerate one.
    assert _resolver(refresher).resolve(_token(pem1, "k1")).agent_id == "agent-1"
    with pytest.raises(TokenError):
        _resolver(refresher).resolve(_token(pem2, "k2"))


def test_failed_refresh_rejects_private_material(monkeypatch: pytest.MonkeyPatch) -> None:
    pem1, jwk1 = _okp("k1")
    # A JWKS that (mis)publishes PRIVATE key material ('d') must be refused, not swapped in.
    priv_jwk = dict(jwk1)
    priv_jwk["d"] = "AAAA"
    refresher = JWKSRefresher(_URL, seed=_provider(jwk1))
    _install_fake_network(monkeypatch, body=json.dumps(_doc(priv_jwk)).encode())
    with pytest.raises(JWKSRefreshError):
        _run(refresher.refresh())
    assert _resolver(refresher).resolve(_token(pem1, "k1")).agent_id == "agent-1"


def test_failed_refresh_rejects_too_many_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    pem1, jwk1 = _okp("k1")
    over = [_okp(f"k{i}")[1] for i in range(MAX_JWKS_KEYS + 1)]
    refresher = JWKSRefresher(_URL, seed=_provider(jwk1))
    _install_fake_network(monkeypatch, body=json.dumps(_doc(*over)).encode())
    with pytest.raises(JWKSRefreshError, match="too many keys"):
        _run(refresher.refresh())
    # Retained.
    assert _resolver(refresher).resolve(_token(pem1, "k1")).agent_id == "agent-1"


# ---------------------------------------------------------------------------
# 5) SSRF guard: http / loopback / link-local JWKS URLs are refused (real DNS), and a
#    refresh to a loopback URL retains the last-good set.
# ---------------------------------------------------------------------------


def test_http_url_is_refused_at_construction() -> None:
    with pytest.raises(ValueError, match="https"):
        JWKSRefresher("http://sts.mcpip.example/jwks", seed=_provider(_okp("k1")[1]))
    # bootstrap rejects it too, before any fetch.
    with pytest.raises(ValueError, match="https"):
        _run(JWKSRefresher.bootstrap("http://sts.mcpip.example/jwks"))


def test_hostless_url_is_refused() -> None:
    with pytest.raises(ValueError, match="host"):
        JWKSRefresher("https:///jwks", seed=_provider(_okp("k1")[1]))


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost/jwks",          # resolves to 127.0.0.1 / ::1
        "https://127.0.0.1/jwks",          # loopback literal
        "https://169.254.169.254/jwks",    # cloud-metadata link-local
        "https://10.255.255.254/jwks",     # private literal
    ],
)
def test_refresh_refuses_internal_host_and_retains(url: str) -> None:
    pem1, jwk1 = _okp("k1")
    refresher = JWKSRefresher(url, seed=_provider(jwk1))
    # Real DNS + the real SSRF guard (reused _is_blocked_ip) reject the fetch.
    with pytest.raises(JWKSRefreshError):
        _run(refresher.refresh())
    # The seeded set is retained — a blocked refresh never empties the verifier.
    assert _resolver(refresher).resolve(_token(pem1, "k1")).agent_id == "agent-1"


def test_bootstrap_refuses_internal_host() -> None:
    # bootstrap must FAIL CLOSED (raise, never produce an empty-verifier refresher) when
    # the initial fetch targets a blocked host.
    with pytest.raises(JWKSRefreshError):
        _run(JWKSRefresher.bootstrap("https://127.0.0.1/jwks"))


# ---------------------------------------------------------------------------
# 6) The fetch client is HERMETIC: trust_env=False, proxy=None, no redirects, verify on.
# ---------------------------------------------------------------------------


def test_fetch_client_is_hermetic(monkeypatch: pytest.MonkeyPatch) -> None:
    # Hostile ambient env — exactly what httpx honors under the default trust_env=True.
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/ca.pem")

    _pem1, jwk1 = _okp("k1")
    refresher = JWKSRefresher(_URL, seed=_provider(jwk1))
    captured: dict[str, Any] = {}
    _install_fake_network(monkeypatch, body=json.dumps(_doc(jwk1)).encode(), captured=captured)
    _run(refresher.refresh())

    assert captured.get("trust_env") is False, "JWKS fetch client must be trust_env=False"
    assert captured.get("proxy") is None, "JWKS fetch client must not honor an ambient proxy"
    assert captured.get("follow_redirects") is False
    assert captured.get("verify") is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
