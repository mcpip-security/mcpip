"""
MCPIP V2 — Service: SkillGateStore (operator skill kill-switch).

    ◐ "Disable a skill for everyone; never touch where it points."

An admin holding ``CAP_DIRECTORY_ADMIN`` can DISABLE an alias for their tenant.
While disabled, every invocation of that alias is denied ``SKILL_DISABLED`` —
regardless of the caller's capabilities — until an admin re-enables it. This is
the skill-side twin of the principal kill-switch (``RevocationStore``): a fast,
reversible operator control to take a tool offline (a compromised integration, a
deprecated skill, an incident) without a redeploy.

It NEVER edits the alias→target mapping. The obfuscation layer (which real system
an alias resolves to) stays immutable config; this store only holds a per-tenant
set of *disabled alias names* and the pipeline turns membership into a DENY. So a
console operator can toggle availability without ever being able to repoint a
skill at a different (or malicious) target.

Fail-closed discipline (mirrors ``RevocationStore``):
  * ``is_disabled`` runs on the hot path; a Redis transport failure raises
    ``LockError`` (→ LOCK_ERROR deny) so an unreadable disable-set never lets a
    possibly-disabled skill through.
  * ``disable`` / ``enable`` are admin mutations; a transport failure raises
    ``LockError`` so the operator learns the toggle did not durably land.
"""

from __future__ import annotations

from typing import Any

import redis.asyncio as redis
from redis.exceptions import RedisError

from auth import LockError

_KEY_PREFIX = "mcpip:skill_disabled:"


class SkillGateStore:
    """Redis-backed per-tenant set of disabled alias names — fail-closed reads."""

    def __init__(self, redis_client: "redis.Redis") -> None:
        self._redis = redis_client

    @staticmethod
    def _key(tenant_id: str) -> str:
        # Tenant-scoped: an admin disables/enables ONLY within its own tenant, and
        # ``is_disabled`` is queried with the token's own tenant, so a disable can
        # never leak across the tenant boundary.
        return f"{_KEY_PREFIX}{tenant_id}"

    async def disable(self, tenant_id: str, alias: str) -> bool:
        """Disable ``alias`` for ``tenant_id``. Returns True iff newly added."""
        try:
            added: Any = await self._redis.sadd(self._key(tenant_id), alias)
        except RedisError as exc:
            raise LockError("skill gate transport failure during disable") from exc
        return int(added) > 0

    async def enable(self, tenant_id: str, alias: str) -> bool:
        """Re-enable ``alias`` for ``tenant_id``. Returns True iff it was disabled."""
        try:
            removed: Any = await self._redis.srem(self._key(tenant_id), alias)
        except RedisError as exc:
            raise LockError("skill gate transport failure during enable") from exc
        return int(removed) > 0

    async def is_disabled(self, tenant_id: str, alias: str) -> bool:
        """
        True iff ``alias`` is disabled for ``tenant_id``. Runs on the hot path.

        Fail-closed: a transport failure raises ``LockError`` (mapped to a
        LOCK_ERROR deny by the funnel) — an unreadable disable-set never lets a
        possibly-disabled skill through.
        """
        try:
            member: Any = await self._redis.sismember(self._key(tenant_id), alias)
        except RedisError as exc:
            raise LockError("skill gate transport failure") from exc
        return bool(member)

    async def list_disabled(self, tenant_id: str) -> list[str]:
        """
        Return the disabled alias names for ``tenant_id`` (operator view). Fail-soft:
        a transport error yields an empty list rather than raising — this backs a
        read-only listing, never an authorization decision.
        """
        try:
            members: Any = await self._redis.smembers(self._key(tenant_id))
        except RedisError:
            return []
        return sorted(m.decode() if isinstance(m, bytes) else str(m) for m in members)


__all__ = ["SkillGateStore"]
