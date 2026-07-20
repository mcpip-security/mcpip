"""
MCPIP V2 — Services package (thin orchestration over the engine).

    ◐ "AI Reasons. MCPIP Authorizes. Systems Execute."

Thin service objects wrap engine pillars so the FastAPI app depends on small,
typed seams instead of the raw engine classes:

  * ``AuthEngine``        — TokenResolver + PinValidator, plus the sandbox out-of-band
                            OTP delivery stand-in.
  * ``ObfuscatorService`` — fail-closed alias -> AliasEntry resolution.
  * ``QuarantineStore``   — canary-tripwire agent freeze list (Redis, TTL-bounded).

Services never reimplement crypto or locking; they call the engine and translate its
results into the gateway's shared control types.
"""

from __future__ import annotations

from services.auth_engine import AuthEngine
from services.community_gate import (
    NoOpCommunityGateProvider,
    active_community_gate_provider,
    community_gate_engine_registered,
    register_community_gate_engine,
)
from services.grant_store import GrantRecord, GrantStore
from services.obfuscator import ObfuscatorService
from services.relation_store import RelationEdge, RelationTupleStore
from services.policy_engine import (
    POLICY_SCHEMA,
    PolicyDocStore,
    PolicyDocumentError,
    VelocityAmountPolicyEngine,
)
from services.quarantine import QuarantineStore

__all__ = [
    "AuthEngine",
    "ObfuscatorService",
    "GrantStore",
    "GrantRecord",
    "RelationTupleStore",
    "RelationEdge",
    "QuarantineStore",
    "NoOpCommunityGateProvider",
    "active_community_gate_provider",
    "community_gate_engine_registered",
    "register_community_gate_engine",
    "POLICY_SCHEMA",
    "PolicyDocStore",
    "PolicyDocumentError",
    "VelocityAmountPolicyEngine",
]
