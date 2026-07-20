"""
tests/test_oauth_resource_metadata.py — N2: OAuth 2.1 Resource-Server surface.

Covers the three strictly-additive pieces of item N2:

  (1) RFC 9728 Protected Resource Metadata at
      ``GET /.well-known/oauth-protected-resource`` — a PUBLIC, unauthenticated
      discovery doc rendered from real Settings + the trusted-issuer resolver.
      Asserts the exact fields, the honest omission of ``scopes_supported``, that it
      carries no secret, that it is reachable without a token, and that it is exempt
      from edge shedding.

  (2) RFC 8707 resource-indicator / audience binding — regression coverage that a
      token minted for a DIFFERENT ``aud`` is rejected at the resolver AND
      end-to-end (opaque 403), and that a correct-aud token still resolves (we did
      not widen anything).

  (3) SEP-2352 issuer pinning — the OPTIONAL ``iss_binding`` claim: a match resolves
      normally, a mismatch fails closed (resolver ``TokenError`` + opaque 403
      end-to-end), and its ABSENCE leaves behavior byte-identical (back-compat).

Driven through Starlette's ``TestClient`` against the same sandbox composition root
the rest of the API suite boots. No mock/fake data — every token is validly signed
by the real in-process sandbox IdP and every field is derived from real config.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# --- Sandbox environment MUST be set before importing app.main (its composition
#     root reads the lru_cached settings once, at import). Identical namespace to
#     tests/test_authorize_api.py so import order is irrelevant. -------------------
os.environ["MCPIP_REDIS_URL"] = "redis://localhost:63790/5"
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_worm.jsonl"),
)

import json
import time
import uuid
from typing import Any, Iterator, Optional

import jwt
import pytest
import redis as redis_sync
from fastapi.testclient import TestClient
from httpx import Response

from auth import (
    WELL_KNOWN_PRM_PATH,
    MultiIssuerResolver,
    StaticPEMKeyProvider,
    TokenResolver,
    build_protected_resource_metadata,
)
from auth.token_resolver import TokenError

from app.main import _EDGE_EXEMPT_PATHS, _components, app
from main import _DemoIdP

_TEST_REDIS_URL = "redis://localhost:63790/5"
_AUTO_ALIAS = "skill_spend_summary"
_CORR_HEADER = "x-mcpip-correlation-id"


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def idp() -> _DemoIdP:
    """The in-process sandbox IdP the composition root booted (same keypair)."""
    demo = _components.demo_idp
    assert demo is not None, "sandbox IdP must be present in sandbox mode"
    return demo


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    """Module-scoped TestClient; flushes the dedicated test db before the lifespan."""
    reset: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    reset.flushdb()
    reset.close()
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _base_claims(idp: _DemoIdP, **overrides: Any) -> dict[str, Any]:
    """A valid 8-claim EdDSA claim set, with per-test overrides applied on top."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": _DemoIdP.ISSUER,
        "aud": _DemoIdP.AUDIENCE,
        "tenant_id": "tenant-acme",
        "agent_id": "agent-orchestrator-1",
        "role": "ops",
        "exp": now + 300,
        "iat": now,
        "nbf": now,
        "jti": uuid.uuid4().hex,
    }
    claims.update(overrides)
    return claims


def _sign(idp: _DemoIdP, claims: dict[str, Any]) -> str:
    """Sign arbitrary claims with the sandbox IdP's real private key."""
    token: str = jwt.encode(claims, idp._private_pem, algorithm="EdDSA")
    return token


def _resolver_for(idp: _DemoIdP, *, audience: str) -> TokenResolver:
    """A TokenResolver over the sandbox IdP public key, bound to ``audience``."""
    return TokenResolver(
        StaticPEMKeyProvider(idp.public_pem),
        issuer=_DemoIdP.ISSUER,
        audience=audience,
    )


def _openai_call(alias: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "call_test",
        "type": "function",
        "function": {"name": alias, "arguments": json.dumps(arguments)},
    }


def _post_authorize(client: TestClient, token: str) -> Response:
    body: dict[str, Any] = {
        "source_format": "openai_tool_call",
        "tool_call": _openai_call(_AUTO_ALIAS, {"period": "2026-Q2"}),
        "jwt": token,
    }
    response: Response = client.post("/v1/authorize", json=body)
    return response


def _assert_opaque_denial(resp: Response) -> None:
    assert resp.status_code == 403, resp.text
    data: Any = resp.json()
    assert isinstance(data, dict)
    assert set(data.keys()) == {"error", "correlation_id"}, data
    header_id = resp.headers.get(_CORR_HEADER)
    assert header_id is not None
    assert header_id == data["correlation_id"]


# ---------------------------------------------------------------------------
# (1) RFC 9728 Protected Resource Metadata.
# ---------------------------------------------------------------------------


def test_prm_path_constant() -> None:
    """The well-known path is the RFC 9728 canonical location."""
    assert WELL_KNOWN_PRM_PATH == "/.well-known/oauth-protected-resource"


def test_prm_document_from_real_settings(client: TestClient) -> None:
    """The doc renders from the real boot Settings/resolver — exact fields, no fabrication."""
    resp = client.get(WELL_KNOWN_PRM_PATH)
    assert resp.status_code == 200, resp.text
    data: Any = resp.json()
    assert isinstance(data, dict)
    assert data["resource"] == "mcpip-gateway"
    assert data["authorization_servers"] == ["mcpip-demo-idp"]
    assert data["bearer_methods_supported"] == ["header"]
    # No OAuth scopes exist in MCPIP — honest omission, never a fabricated list.
    assert "scopes_supported" not in data


def test_prm_document_carries_no_secret(client: TestClient) -> None:
    """The discovery doc must contain no secret / key / topology material."""
    resp = client.get(WELL_KNOWN_PRM_PATH)
    blob = json.dumps(resp.json()).lower()
    for needle in (
        "begin",
        "private",
        "-----",
        "pem",
        "otp",
        '"pin"',
        "password",
        "secret",
        "authorization:",
    ):
        assert needle not in blob, f"discovery doc leaked {needle!r}: {blob}"


def test_prm_is_public_unauthenticated(client: TestClient) -> None:
    """No Authorization header required — it is a discovery doc, like /healthz."""
    resp = client.get(WELL_KNOWN_PRM_PATH)  # deliberately no auth header
    assert resp.status_code == 200, resp.text


def test_prm_is_edge_exempt() -> None:
    """The well-known path is exempt from admission-control shedding (never dropped)."""
    assert WELL_KNOWN_PRM_PATH in _EDGE_EXEMPT_PATHS


def test_prm_builder_renders_multiple_issuers_sorted(idp: _DemoIdP) -> None:
    """Pure builder over a synthetic MultiIssuerResolver lists BOTH issuers, sorted.

    Proves multi-issuer rendering without an app reboot; resource stays the real
    configured audience read from live Settings.
    """
    strong = TokenResolver(
        StaticPEMKeyProvider(idp.public_pem),
        issuer="iss-strong",
        audience="mcpip-gateway",
        attesting=True,
    )
    weak = TokenResolver(
        StaticPEMKeyProvider(idp.public_pem),
        issuer="iss-weak",
        audience="mcpip-gateway",
        attesting=False,
    )
    multi = MultiIssuerResolver([weak, strong])  # unsorted input order on purpose
    doc = build_protected_resource_metadata(multi, _components.settings)
    assert doc["authorization_servers"] == ["iss-strong", "iss-weak"]
    assert doc["resource"] == _components.settings.jwt_audience
    assert doc["bearer_methods_supported"] == ["header"]


def test_resolver_issuers_properties(idp: _DemoIdP) -> None:
    """Both resolver types expose the read-only ``issuers`` tuple used by the builder."""
    single = _resolver_for(idp, audience="mcpip-gateway")
    assert single.issuers == ("mcpip-demo-idp",)
    multi = MultiIssuerResolver(
        [
            TokenResolver(
                StaticPEMKeyProvider(idp.public_pem), issuer="b-iss", audience="a"
            ),
            TokenResolver(
                StaticPEMKeyProvider(idp.public_pem), issuer="a-iss", audience="a"
            ),
        ]
    )
    assert multi.issuers == ("a-iss", "b-iss")


# ---------------------------------------------------------------------------
# (2) RFC 8707 audience / resource-indicator binding.
# ---------------------------------------------------------------------------


def test_rfc8707_wrong_aud_rejected_at_resolver(idp: _DemoIdP) -> None:
    """A token minted for a DIFFERENT resource (aud) is rejected — binding honored."""
    resolver = _resolver_for(idp, audience="mcpip-gateway")
    wrong = _sign(idp, _base_claims(idp, aud="other-resource"))
    with pytest.raises(TokenError):
        resolver.resolve(wrong)


def test_rfc8707_correct_aud_still_resolves(idp: _DemoIdP) -> None:
    """We did NOT widen: a correctly-audienced token still resolves to an Identity."""
    resolver = _resolver_for(idp, audience="mcpip-gateway")
    ident = resolver.resolve(_sign(idp, _base_claims(idp)))
    assert ident.tenant_id == "tenant-acme"
    assert ident.audience == "mcpip-gateway"
    assert ident.issuer == "mcpip-demo-idp"


def test_rfc8707_wrong_aud_opaque_deny_end_to_end(
    client: TestClient, idp: _DemoIdP
) -> None:
    """A wrong-aud token at /v1/authorize is an opaque 403 — no reason leak."""
    wrong = _sign(idp, _base_claims(idp, aud="some-other-audience"))
    _assert_opaque_denial(_post_authorize(client, wrong))


# ---------------------------------------------------------------------------
# (3) SEP-2352 issuer pinning via the OPTIONAL ``iss_binding`` claim.
# ---------------------------------------------------------------------------


def test_iss_binding_match_resolves(idp: _DemoIdP) -> None:
    """iss_binding == the verified iss resolves normally; Identity.issuer unchanged."""
    resolver = _resolver_for(idp, audience="mcpip-gateway")
    token = _sign(idp, _base_claims(idp, iss_binding=_DemoIdP.ISSUER))
    ident = resolver.resolve(token)
    assert ident.issuer == _DemoIdP.ISSUER


def test_iss_binding_mismatch_fails_closed_at_resolver(idp: _DemoIdP) -> None:
    """iss_binding naming a different issuer than the verified iss is a TokenError."""
    resolver = _resolver_for(idp, audience="mcpip-gateway")
    token = _sign(idp, _base_claims(idp, iss_binding="some-other-issuer"))
    with pytest.raises(TokenError):
        resolver.resolve(token)


def test_iss_binding_non_string_fails_closed(idp: _DemoIdP) -> None:
    """A present-but-non-string iss_binding fails closed (never silently ignored)."""
    resolver = _resolver_for(idp, audience="mcpip-gateway")
    token = _sign(idp, _base_claims(idp, iss_binding=12345))
    with pytest.raises(TokenError):
        resolver.resolve(token)


def test_iss_binding_mismatch_opaque_deny_end_to_end(
    client: TestClient, idp: _DemoIdP
) -> None:
    """iss_binding mismatch at /v1/authorize is an opaque 403."""
    token = _sign(idp, _base_claims(idp, iss_binding="wrong-issuer"))
    _assert_opaque_denial(_post_authorize(client, token))


def test_iss_binding_absent_is_backward_compatible(
    client: TestClient, idp: _DemoIdP
) -> None:
    """A token with NO iss_binding claim resolves EXACTLY as before (200 allow)."""
    resolver = _resolver_for(idp, audience="mcpip-gateway")
    legacy = _sign(idp, _base_claims(idp))  # no iss_binding
    ident = resolver.resolve(legacy)
    assert ident.issuer == _DemoIdP.ISSUER
    # And end-to-end the legacy token still authorizes an AUTO alias.
    resp = _post_authorize(client, legacy)
    assert resp.status_code == 200, resp.text
    assert resp.json()["decision"] == "allow"
