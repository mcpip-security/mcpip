"""
MCPIP V2 — Service: DelegationStore (attenuated session grants).

    ◐ "A spawned session holds LESS than its spawner, never the same by default."

Implements phase 2 of ``docs/SESSION_DELEGATION_DESIGN.md``: a parent session
registers a grant for a child session whose authority is strictly a subset of
the parent's — capabilities ⊆, compartment same-or-narrower, lifetime ≤ — and
the authorize path then INTERSECTS the child's JWT claims with the grant. The
store is gateway-side state that can only NARROW an IdP-issued identity (the
same shape as the deny-only policy overlay and the additive-only catalog
overlay); it never mints a token, so identity sovereignty is untouched.

Guardrails (normative — the safety of delegation rests on these):
  * ATTENUATION IS CHECKED AT REGISTRATION, and refused — never silently
    intersected. Requesting a capability the parent lacks fails the whole
    registration, because silent narrowing hides operator mistakes.
  * Chain depth ≤ ``MAX_DEPTH``. A child registering its own grant is checked
    against its EFFECTIVE (already-narrowed) set, so authority only shrinks
    down a chain. Cycles cannot form: a grant references its parent grant,
    which must already exist and be live.
  * REVOCATION CASCADES BY CONSTRUCTION: every grant denormalizes its ancestor
    session ids, and the hot-path liveness check probes a revocation key for
    the child AND every ancestor — one thrown key kills the whole subtree with
    no enumeration at revoke time. Same key-presence, fail-closed pattern as
    the principal kill-switch (``services/revocation.py``).
  * Reads are FAIL-CLOSED: a Redis transport failure raises ``LockError``; an
    unreadable grant never lets a delegated token through un-narrowed.
  * Grants expire by Redis TTL at their effective expiry (min of parent token
    exp, parent grant expiry, requested). The WORM chain keeps the forensic
    record; the store keeps only live state.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional

import redis.asyncio as redis
from redis.exceptions import RedisError

from auth import LockError

_GRANT_PREFIX = "mcpip:delegation:grant:"
_REVOKED_PREFIX = "mcpip:delegation:revoked:"

MAX_DEPTH = 4


class DelegationError(ValueError):
    """A registration violated an attenuation rule (safe, non-secret message)."""


@dataclass(frozen=True)
class Grant:
    """One live delegation grant, as stored (and as listed to admins)."""

    delegation_id: str
    tenant_id: str
    parent_session_id: str
    child_session_id: str
    child_agent_id: str
    capabilities: tuple[str, ...]
    compartment: Optional[str]
    expires_at: int  # epoch seconds
    depth: int
    # Ancestor SESSION ids, root-first, excluding the child itself. Denormalized
    # so the hot path can probe every revocation key without walking grants.
    ancestors: tuple[str, ...]


class DelegationStore:
    """Redis-backed attenuated grants — persistent, fail-closed reads."""

    def __init__(self, redis_client: "redis.Redis") -> None:
        self._redis = redis_client

    @staticmethod
    def _grant_key(tenant_id: str, delegation_id: str) -> str:
        # Tenant-scoped like every sibling store: a grant can never be addressed
        # from another tenant, and lookups always use the token's own tenant.
        return f"{_GRANT_PREFIX}{tenant_id}:{delegation_id}"

    @staticmethod
    def _revoked_key(tenant_id: str, session_id: str) -> str:
        return f"{_REVOKED_PREFIX}{tenant_id}:{session_id}"

    # ------------------------------------------------------------------ write

    @staticmethod
    def prepare(
        *,
        tenant_id: str,
        parent_session_id: str,
        parent_effective_capabilities: tuple[str, ...],
        parent_effective_compartment: Optional[str],
        parent_token_exp: Optional[int],
        parent_grant: Optional[Grant],
        child_agent_id: str,
        child_session_id: str,
        capabilities: list[str],
        compartment: Optional[str],
        expires_in_s: int,
    ) -> Grant:
        """
        PURE validation of the attenuation rules → the Grant that WOULD be written.
        Touches no storage, so the caller can seal the WORM ``delegation_granted``
        event between validation and ``persist`` — write-before-execute applies to
        the grant exactly as to a decision, and a rule violation never reaches the
        chain at all.

        Raises ``DelegationError`` on any rule violation (safe to surface to the
        parent — it names the operator's mistake, never a secret or topology).
        """
        # Attenuation: strictly ⊆ the parent's EFFECTIVE set, refused otherwise.
        excess = sorted(set(capabilities) - set(parent_effective_capabilities))
        if excess:
            raise DelegationError(
                f"capabilities not held by the delegating session: {', '.join(excess)}"
            )
        # Compartment: same-or-narrower. An un-compartmented parent (tenant-wide)
        # may pin the child to any compartment; a compartmented parent may only
        # hand down its own.
        if parent_effective_compartment is not None and (
            compartment != parent_effective_compartment
        ):
            raise DelegationError(
                "compartment must equal the delegating session's compartment"
            )
        depth = 1 if parent_grant is None else parent_grant.depth + 1
        if depth > MAX_DEPTH:
            raise DelegationError(f"delegation chain depth exceeds {MAX_DEPTH}")
        if child_session_id == parent_session_id:
            raise DelegationError("a session cannot delegate to itself")
        if expires_in_s <= 0:
            raise DelegationError("expires_in_s must be positive")

        now = int(time.time())
        expires_at = now + expires_in_s
        if parent_token_exp is not None:
            expires_at = min(expires_at, parent_token_exp)
        if parent_grant is not None:
            expires_at = min(expires_at, parent_grant.expires_at)
        if expires_at <= now:
            raise DelegationError("effective expiry is already in the past")

        ancestors: tuple[str, ...] = (
            (*parent_grant.ancestors, parent_session_id)
            if parent_grant is not None
            else (parent_session_id,)
        )
        return Grant(
            delegation_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            parent_session_id=parent_session_id,
            child_session_id=child_session_id,
            child_agent_id=child_agent_id,
            capabilities=tuple(capabilities),
            compartment=compartment,
            expires_at=expires_at,
            depth=depth,
            ancestors=ancestors,
        )

    async def persist(self, grant: Grant) -> None:
        """Write a prepared (already WORM-sealed) grant as live state, TTL'd to
        its effective expiry. Fail-closed on transport."""
        now = int(time.time())
        payload = json.dumps(
            {
                "parent_session_id": grant.parent_session_id,
                "child_session_id": grant.child_session_id,
                "child_agent_id": grant.child_agent_id,
                "capabilities": list(grant.capabilities),
                "compartment": grant.compartment,
                "expires_at": grant.expires_at,
                "depth": grant.depth,
                "ancestors": list(grant.ancestors),
            },
            separators=(",", ":"),
        )
        try:
            await self._redis.set(
                self._grant_key(grant.tenant_id, grant.delegation_id),
                payload,
                ex=max(1, grant.expires_at - now),
            )
        except RedisError as exc:
            raise LockError("delegation transport failure during persist") from exc

    async def revoke_session(
        self, *, tenant_id: str, session_id: str
    ) -> None:
        """
        Throw the kill-switch for one session — every grant whose chain passes
        through it dies on the next liveness probe (no TTL: a kill-switch stays
        thrown, exactly like the principal revocation). Fail-closed on transport.
        """
        try:
            await self._redis.set(
                self._revoked_key(tenant_id, session_id), str(time.time_ns())
            )
        except RedisError as exc:
            raise LockError("delegation transport failure during revoke") from exc

    # ------------------------------------------------------------------- read

    async def fetch(self, tenant_id: str, delegation_id: str) -> Optional[Grant]:
        """The live grant, or None (missing = expired-by-TTL or never existed)."""
        try:
            raw: Any = await self._redis.get(self._grant_key(tenant_id, delegation_id))
        except RedisError as exc:
            raise LockError("delegation transport failure") from exc
        if raw is None:
            return None
        try:
            doc = json.loads(raw)
            return Grant(
                delegation_id=delegation_id,
                tenant_id=tenant_id,
                parent_session_id=str(doc["parent_session_id"]),
                child_session_id=str(doc["child_session_id"]),
                child_agent_id=str(doc["child_agent_id"]),
                capabilities=tuple(str(c) for c in doc["capabilities"]),
                compartment=(
                    str(doc["compartment"]) if doc.get("compartment") is not None else None
                ),
                expires_at=int(doc["expires_at"]),
                depth=int(doc["depth"]),
                ancestors=tuple(str(a) for a in doc["ancestors"]),
            )
        except (ValueError, KeyError, TypeError):
            # A malformed stored grant must never pass a delegated token through
            # un-narrowed — treat as absent, which the caller denies fail-closed.
            return None

    async def is_chain_revoked(self, tenant_id: str, grant: Grant) -> bool:
        """
        True iff the child or ANY ancestor session has been revoked — the cascade.
        O(depth ≤ MAX_DEPTH) key-presence probes; fail-closed on transport.
        """
        sessions = (*grant.ancestors, grant.child_session_id)
        try:
            pipe = self._redis.pipeline(transaction=False)
            for sid in sessions:
                pipe.exists(self._revoked_key(tenant_id, sid))
            hits: Any = await pipe.execute()
        except RedisError as exc:
            raise LockError("delegation transport failure") from exc
        return any(int(h) > 0 for h in hits)

    async def list_grants(self, tenant_id: str) -> list[Grant]:
        """
        Every LIVE grant for one tenant (admin read surface — off the hot path,
        SCAN-based). Malformed entries are skipped, never guessed at.
        """
        prefix = f"{_GRANT_PREFIX}{tenant_id}:"
        grants: list[Grant] = []
        try:
            async for key in self._redis.scan_iter(match=f"{prefix}*", count=200):
                name = key.decode() if isinstance(key, (bytes, bytearray)) else str(key)
                delegation_id = name[len(prefix):]
                grant = await self.fetch(tenant_id, delegation_id)
                if grant is not None:
                    grants.append(grant)
        except RedisError as exc:
            raise LockError("delegation transport failure during list") from exc
        grants.sort(key=lambda g: (g.depth, g.expires_at))
        return grants
