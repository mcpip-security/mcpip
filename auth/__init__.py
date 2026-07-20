"""
MCPIP V2 — Auth package.

    ◐ Auth: "A payload-bound PIN that's spent exactly once, or the action never runs."

Re-exports the Auth pillars:
  * JWT identity sovereignty  — TokenResolver / KeyProvider / StaticPEMKeyProvider.
  * The canonical payload lock — PinValidator / lock_payload_hash / LOCK_CONSUME_LUA.
  * Proof-of-possession        — verify_pop_proof / replay guards (sender-constrained
                                 tokens + the RFC 8693 delegation actor).
"""

from __future__ import annotations

from auth.jwks_refresher import (
    JWKSRefreshError,
    JWKSRefresher,
)
from auth.oauth_metadata import (
    WELL_KNOWN_PRM_PATH,
    build_protected_resource_metadata,
)
from auth.pin_validator import (
    LOCK_CONSUME_LUA,
    LockError,
    PinValidator,
    lock_payload_hash,
)
from auth.pop import (
    InMemoryReplayGuard,
    PopError,
    RedisReplayGuard,
    ReplayGuard,
    jwk_thumbprint,
    verify_pop_proof,
)
from auth.token_resolver import (
    ALLOWED_ALGORITHMS,
    REQUIRED_CLAIMS,
    IdentityResolver,
    JWKSKeyProvider,
    KeyProvider,
    MultiIssuerResolver,
    StaticPEMKeyProvider,
    TokenClaimsMissing,
    TokenError,
    TokenResolver,
)

__all__ = [
    # token_resolver
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
    # jwks_refresher
    "JWKSRefresher",
    "JWKSRefreshError",
    # oauth_metadata (RFC 9728 Protected Resource Metadata)
    "WELL_KNOWN_PRM_PATH",
    "build_protected_resource_metadata",
    # pin_validator
    "LOCK_CONSUME_LUA",
    "LockError",
    "PinValidator",
    "lock_payload_hash",
    # pop
    "PopError",
    "ReplayGuard",
    "InMemoryReplayGuard",
    "RedisReplayGuard",
    "verify_pop_proof",
    "jwk_thumbprint",
]
