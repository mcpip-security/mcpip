"""
MCPIP V2 — Service: RevocationStore (operator principal kill-switch).

    ◐ "Identity is the IdP's to mint. Denial is the gateway's to enforce."

An operator holding ``CAP_DIRECTORY_ADMIN`` can REVOKE a principal (a tenant +
agent_id). While the revocation key lives, EVERY subsequent request from that
(tenant, agent) is denied ``PRINCIPAL_REVOKED`` immediately after identity
verification — a compromised or offboarded agent is blocked at the gateway even
before its IdP rotates the token. An admin ``reactivate`` lifts it.

This does NOT touch identity sovereignty: the gateway never mints, edits, or
re-signs a credential. It only *denies* requests bearing an otherwise-valid JWT —
which is squarely the gateway's job. The IdP remains the sole source of identity;
this is a local, immediate, reversible block layered on top.

Deliberately SEPARATE from ``QuarantineStore``:
  * A quarantine is an AUTOMATIC, TTL-bounded canary-tripwire freeze.
  * A revocation is a DELIBERATE, admin-issued block that PERSISTS until an admin
    reactivates it (no TTL) — a kill-switch stays thrown until someone lifts it.
Keeping them apart keeps the WORM/forensic story clean: the operator can tell a
tripwire freeze from a deliberate revocation at a glance.

Fail-closed discipline (mirrors ``QuarantineStore`` / ``GrantStore``):
  * ``is_revoked`` runs on the hot path for every request; a Redis transport
    failure raises ``LockError`` so the single funnel denies LOCK_ERROR rather
    than skipping the gate — an unreadable revocation list never lets a
    possibly-revoked principal through.
  * ``revoke`` / ``reactivate`` are admin mutations; a transport failure raises
    ``LockError`` so the operator is told the block did NOT durably land, rather
    than silently believing a compromised agent is contained when it is not.
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

import redis.asyncio as redis
from redis.exceptions import RedisError

from auth import LockError

_KEY_PREFIX = "mcpip:revoked:"


class RevocationStore:
    """Redis-backed (tenant, agent) revocation list — persistent, fail-closed reads."""

    def __init__(self, redis_client: "redis.Redis") -> None:
        self._redis = redis_client

    @staticmethod
    def _key(tenant_id: str, agent_id: str) -> str:
        # Tenant-scoped: an admin can only ever revoke within its own tenant, and
        # ``is_revoked`` is queried with the token's own tenant, so a revocation can
        # never leak across the tenant boundary.
        return f"{_KEY_PREFIX}{tenant_id}:{agent_id}"

    async def revoke(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        issued_by: str,
        correlation_id: str,
        reason: Optional[str] = None,
    ) -> None:
        """
        Block a principal until an admin reactivates it (no TTL — a kill-switch
        stays thrown). The stored payload is operator forensics only; enforcement
        needs nothing but key presence. Fail-closed: a transport error raises
        ``LockError`` so the caller learns the block did not durably land.
        """
        payload = json.dumps(
            {
                "issued_by": issued_by,
                "correlation_id": correlation_id,
                "reason": reason,
                "revoked_at_ns": time.time_ns(),
            },
            separators=(",", ":"),
        )
        try:
            await self._redis.set(self._key(tenant_id, agent_id), payload)
        except RedisError as exc:
            raise LockError("revocation transport failure during revoke") from exc

    async def reactivate(self, *, tenant_id: str, agent_id: str) -> bool:
        """Lift a revocation. Returns True iff a key was removed. Fail-closed on error."""
        try:
            removed: Any = await self._redis.delete(self._key(tenant_id, agent_id))
        except RedisError as exc:
            raise LockError("revocation transport failure during reactivate") from exc
        return int(removed) > 0

    async def is_revoked(self, tenant_id: str, agent_id: str) -> bool:
        """
        True iff an admin revocation is in force. Read-only; runs on the hot path.

        Fail-closed: a transport failure raises ``LockError`` (mapped to a
        LOCK_ERROR deny by the funnel) — an unreadable revocation list never lets
        a possibly-revoked principal through.
        """
        try:
            raw: Any = await self._redis.get(self._key(tenant_id, agent_id))
        except RedisError as exc:
            raise LockError("revocation transport failure") from exc
        return raw is not None

    async def list_revoked(self, tenant_id: str) -> list[str]:
        """
        Return the agent_ids currently revoked in ``tenant_id`` (operator view).

        Uses non-blocking ``SCAN`` over the tenant-scoped key prefix. Fail-soft:
        a transport error yields an empty list rather than raising — this backs a
        read-only admin listing, never an authorization decision.

        The tenant id is glob-escaped (single shared rule in ``services.quarantine``)
        so a wildcard-bearing tenant id can never widen the scan into another
        tenant's key namespace.
        """
        from services.quarantine import _glob_escape

        pattern = f"{_glob_escape(f'{_KEY_PREFIX}{tenant_id}:')}*"
        prefix_len = len(f"{_KEY_PREFIX}{tenant_id}:")
        found: list[str] = []
        try:
            async for key in self._redis.scan_iter(match=pattern):
                text = key.decode() if isinstance(key, bytes) else str(key)
                found.append(text[prefix_len:])
        except RedisError:
            return []
        return found


__all__ = ["RevocationStore"]
