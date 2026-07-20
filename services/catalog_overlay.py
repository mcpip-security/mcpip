"""
MCPIP V2 — Service: CatalogOverlayStore (operator-registered skills).

    ◐ "The config catalog is immutable. Operators may ADD, never override."

The alias catalog (which real system an alias resolves to) ships as signed,
immutable config — the obfuscation core. This store lets an admin holding
``CAP_DIRECTORY_ADMIN`` REGISTER a NEW skill (a new alias→target) at runtime and
have it persist across restarts, WITHOUT ever being able to override or shadow a
config-defined alias.

Guardrails (normative — the safety of runtime registration rests on these):
  * ADDITIVE ONLY. Registration is refused if the alias already resolves for the
    tenant (config OR a prior overlay entry). An operator can never repoint an
    existing skill — only introduce a new name.
  * ``cloud_rest`` transport only. Operator skills cannot be minted onto the
    privileged legacy-mainframe or the internal grant-issue transports.
  * Every registration/deregistration is WORM-logged and tenant-scoped.

Persistence: the overlay lives in a per-tenant Redis hash and is LOADED into the
in-memory ``AliasRegistry`` at boot (and registered live on the worker that
handles the request). Resolve stays synchronous and in-memory — no I/O is added
to the hot path.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import redis.asyncio as redis
from redis.exceptions import RedisError

from auth import LockError

_KEY_PREFIX = "mcpip:catalog_overlay:"
# Bound the number of operator-registered skills per tenant (metadata, not bulk).
MAX_OVERLAY_ENTRIES = 512


class CatalogOverlayStore:
    """Redis-backed per-tenant additive alias overlay. Never overrides config."""

    def __init__(self, redis_client: "redis.Redis") -> None:
        self._redis = redis_client

    @staticmethod
    def _key(tenant_id: str) -> str:
        return f"{_KEY_PREFIX}{tenant_id}"

    async def count(self, tenant_id: str) -> int:
        try:
            return int(await self._redis.hlen(self._key(tenant_id)))
        except RedisError:
            return 0

    async def add(self, tenant_id: str, alias: str, fields: dict[str, str]) -> bool:
        """
        ADDITIVELY persist one operator-registered alias — ATOMIC additive-only.

        Uses ``HSETNX`` so the create is decided by Redis (the authoritative, cross-worker
        source of truth), NOT by any per-worker in-memory pre-check: returns ``True`` iff
        the field was NEWLY created, ``False`` if the alias already existed in the overlay
        (a concurrent second admin register, or a community approval racing on another
        worker whose stale in-memory ``has_alias`` said "absent"). An already-present alias
        is therefore NEVER silently overwritten/repointed — the caller must treat ``False``
        as a hard additive-only refusal and NOT register the alias live. Fail-closed on a
        transport error.
        """
        payload = json.dumps(fields, separators=(",", ":"))
        try:
            created: Any = await self._redis.hsetnx(self._key(tenant_id), alias, payload)
        except RedisError as exc:
            raise LockError("catalog overlay transport failure during add") from exc
        return int(created) > 0

    async def exists(self, tenant_id: str, alias: str) -> bool:
        """
        Authoritative (Redis ``HEXISTS``) test of whether ``alias`` is already an overlay
        entry for ``tenant_id``. Used to compute the reviewer-facing additive-only diff
        from the SAME cross-worker source of truth the atomic ``add`` decides on, so the
        console can't be deceived by a stale per-worker in-memory registry. Fail-soft: a
        transport error reports ``False`` (a display hint, never an authorization decision;
        the authoritative additive-only guard is the fail-closed ``add`` HSETNX).
        """
        try:
            present: Any = await self._redis.hexists(self._key(tenant_id), alias)
        except RedisError:
            return False
        return bool(present)

    async def remove(self, tenant_id: str, alias: str) -> bool:
        """Drop one operator-registered alias. Returns True iff it existed."""
        try:
            removed: Any = await self._redis.hdel(self._key(tenant_id), alias)
        except RedisError as exc:
            raise LockError("catalog overlay transport failure during remove") from exc
        return int(removed) > 0

    async def get(self, tenant_id: str, alias: str) -> Optional[dict[str, str]]:
        """Return the stored fields for one overlay alias, or None. Fail-soft."""
        try:
            raw: Any = await self._redis.hget(self._key(tenant_id), alias)
        except RedisError:
            return None
        if raw is None:
            return None
        try:
            loaded = json.loads(raw)
        except (ValueError, TypeError):
            return None
        return loaded if isinstance(loaded, dict) else None

    async def list_for_tenant(self, tenant_id: str) -> dict[str, dict[str, str]]:
        """All overlay aliases for a tenant → {alias: fields}. Fail-soft."""
        try:
            raw: Any = await self._redis.hgetall(self._key(tenant_id))
        except RedisError:
            return {}
        out: dict[str, dict[str, str]] = {}
        for k, v in (raw or {}).items():
            alias = k.decode() if isinstance(k, bytes) else str(k)
            try:
                fields = json.loads(v)
            except (ValueError, TypeError):
                continue
            if isinstance(fields, dict):
                out[alias] = fields
        return out

    async def all_tenants(self) -> list[str]:
        """Tenant ids that have a catalog overlay (SCAN). Fail-soft — for boot-load."""
        prefix_len = len(_KEY_PREFIX)
        tenants: list[str] = []
        try:
            async for key in self._redis.scan_iter(match=f"{_KEY_PREFIX}*"):
                text = key.decode() if isinstance(key, bytes) else str(key)
                tenants.append(text[prefix_len:])
        except RedisError:
            return []
        return tenants


__all__ = ["CatalogOverlayStore", "MAX_OVERLAY_ENTRIES"]
