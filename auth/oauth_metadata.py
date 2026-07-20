"""
MCPIP V2 — Auth: OAuth 2.1 Protected Resource Metadata (RFC 9728).

    ◐ Auth: "A compliant MCP client discovers the AS here — and cannot route around us."

MCPIP's MCP edge is an OAuth 2.1 RESOURCE SERVER. RFC 9728 says a resource server
publishes a small, PUBLIC discovery document at
``/.well-known/oauth-protected-resource`` naming (a) its own resource identifier
and (b) the authorization server(s) that issue tokens for it. A conformant client
reads that doc, obtains a token from the named AS bound to the named resource
(RFC 8707), and presents it — so it cannot silently talk to a look-alike endpoint.

This module is a PURE, boot-free builder. It imports no HTTP client / socket / SDK
and holds no state, so a test can render the document without an app reboot. Every
field is DERIVED FROM REAL configuration — it NEVER fabricates an issuer or audience:

  * ``resource``                  — the gateway's own resource identifier, i.e. the
                                    single RFC 8707 audience this RS represents
                                    (``settings.jwt_audience``).
  * ``authorization_servers``     — the trusted issuer set read from the RESOLVER
                                    (not re-read from env), sorted for determinism, so
                                    a multi-issuer deployment lists all its issuers and
                                    the shipped single-issuer path lists exactly one.
  * ``bearer_methods_supported``  — ``["header"]``: MCPIP accepts the bearer token only
                                    in the ``Authorization: Bearer`` header (or the
                                    header-class JSON ``jwt`` field) — never a query
                                    parameter.

There is deliberately NO ``scopes_supported`` key: MCPIP has no OAuth scopes. The
``role`` claim authorizes nothing; authorization is capability-UUID / grant based and
those UUIDs are HIDDEN topology. Honest omission beats a fabricated scope list.

The document carries NO secret and NO alias→target topology — only the two non-secret
discovery identifiers RFC 9728 exists to publish.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only, no runtime import (keeps this pure).
    from core.config import Settings

    from auth.token_resolver import IdentityResolver

# RFC 9728 well-known path for Protected Resource Metadata. Single source of truth so
# the route wiring and the tests agree on the exact string.
WELL_KNOWN_PRM_PATH: str = "/.well-known/oauth-protected-resource"


def build_protected_resource_metadata(
    resolver: "IdentityResolver",
    settings: "Settings",
) -> dict[str, Any]:
    """
    Render the RFC 9728 Protected Resource Metadata document from live state.

    ``resolver`` must expose the read-only ``issuers`` property (both ``TokenResolver``
    and ``MultiIssuerResolver`` do); the trusted issuer set is read from it so a future
    multi-issuer wiring lists every issuer without this builder re-reading env. Pure and
    deterministic: no I/O, no clock, no secret. Safe to call on every request.
    """
    return {
        "resource": settings.jwt_audience,
        # Sorted for a deterministic document regardless of resolver iteration order.
        "authorization_servers": sorted(resolver.issuers),
        "bearer_methods_supported": ["header"],
    }


__all__ = [
    "WELL_KNOWN_PRM_PATH",
    "build_protected_resource_metadata",
]
