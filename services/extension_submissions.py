"""
MCPIP V2 — Service: ExtensionSubmissionStore (community-skill submit/review state).

    ◐ "Submit is broadly reachable; approve is reviewer-gated. Keep the two keyspaces
       tenant-scoped so a reviewer can only ever reach its own tenant's queue."

Backing store for the Phase 1 author-your-own-SKILL workflow. Two per-tenant Redis
namespaces, both keyed by the JWT-derived tenant id (so cross-tenant reach is structurally
impossible — a reviewer's reads and the register apply all target its own tenant only):

  * ``mcpip:ext:pending:{tenant}`` — a hash ``submission_id → record`` of PENDING (and,
    once acted on, APPROVED/REJECTED) submissions. Each record carries the canonical
    manifest, the submitter's JWT ``agent_id``, the declared ``author`` label, the alias,
    ``created_at``, and the ``state``. Bounded by ``MAX_PENDING_SUBMISSIONS`` against
    flooding (a Contributor is ANY authenticated principal).
  * ``mcpip:ext:approved:{tenant}`` — a hash ``alias → record`` of APPROVED community
    skills: the canonical manifest, the pinned ``sha256`` (the rug-pull digest), the
    approving reviewer's ``agent_id``, and ``approved_at``. Read at boot by the hydrator
    to re-verify each community overlay entry's manifest pin before it loads.

Fail posture matches ``CatalogOverlayStore``: WRITES fail CLOSED (a ``RedisError`` raises
``LockError`` → opaque deny, so a submission/approval is never silently lost), while the
LISTING reads fail SOFT (``{}``/``[]`` — a roster read never gates an authorization
decision). A single-record GET used by approve fails SOFT to ``None``, which the approve
handler treats as "not found" → opaque deny (fail-closed in effect: no approval happens).
"""

from __future__ import annotations

import json
from typing import Any, Final, Optional

import redis.asyncio as redis
from redis.exceptions import RedisError

from auth import LockError

_PENDING_PREFIX: Final[str] = "mcpip:ext:pending:"
_APPROVED_PREFIX: Final[str] = "mcpip:ext:approved:"

# Submission lifecycle states. A submission is created PENDING; approve/reject are terminal.
STATE_PENDING: Final[str] = "pending"
STATE_APPROVED: Final[str] = "approved"
STATE_REJECTED: Final[str] = "rejected"


class ExtensionSubmissionStore:
    """Redis-backed per-tenant community-extension submission + approval state."""

    def __init__(self, redis_client: "redis.Redis") -> None:
        self._redis = redis_client

    @staticmethod
    def _pending_key(tenant_id: str) -> str:
        return f"{_PENDING_PREFIX}{tenant_id}"

    @staticmethod
    def _approved_key(tenant_id: str) -> str:
        return f"{_APPROVED_PREFIX}{tenant_id}"

    # -- Pending submissions ------------------------------------------------------------

    async def count_pending(self, tenant_id: str) -> int:
        """Number of records in the pending hash. Fail-soft (0 on error).

        Mirrors ``CatalogOverlayStore.count``: a transport error returns 0 here, but the
        subsequent ``add_pending`` fails CLOSED, so a Redis outage never smuggles a
        submission past the ``MAX_PENDING_SUBMISSIONS`` bound — it just denies at the write.
        """
        try:
            return int(await self._redis.hlen(self._pending_key(tenant_id)))
        except RedisError:
            return 0

    async def add_pending(
        self, tenant_id: str, submission_id: str, record: dict[str, Any]
    ) -> None:
        """Persist one PENDING submission. Fail-closed on transport error."""
        payload = json.dumps(record, separators=(",", ":"), sort_keys=True)
        try:
            await self._redis.hset(self._pending_key(tenant_id), submission_id, payload)
        except RedisError as exc:
            raise LockError("extension submission transport failure during add") from exc

    async def get_pending(
        self, tenant_id: str, submission_id: str
    ) -> Optional[dict[str, Any]]:
        """One submission record by id, or None. Fail-soft (None → approve denies)."""
        try:
            raw: Any = await self._redis.hget(self._pending_key(tenant_id), submission_id)
        except RedisError:
            return None
        return _decode_record(raw)

    async def set_state(
        self, tenant_id: str, submission_id: str, record: dict[str, Any]
    ) -> None:
        """Rewrite a submission record (e.g. to mark APPROVED/REJECTED). Fail-closed."""
        await self.add_pending(tenant_id, submission_id, record)

    async def list_pending(self, tenant_id: str) -> dict[str, dict[str, Any]]:
        """All submission records for a tenant → {submission_id: record}. Fail-soft."""
        try:
            raw: Any = await self._redis.hgetall(self._pending_key(tenant_id))
        except RedisError:
            return {}
        return _decode_hash(raw)

    # -- Approved community skills ------------------------------------------------------

    async def add_approved(
        self, tenant_id: str, alias: str, record: dict[str, Any]
    ) -> None:
        """Persist one APPROVED community skill (canonical manifest + pin). Fail-closed."""
        payload = json.dumps(record, separators=(",", ":"), sort_keys=True)
        try:
            await self._redis.hset(self._approved_key(tenant_id), alias, payload)
        except RedisError as exc:
            raise LockError("extension approval transport failure during add") from exc

    async def get_approved(
        self, tenant_id: str, alias: str
    ) -> Optional[dict[str, Any]]:
        """The approved-manifest record for one alias, or None. Fail-soft.

        Used by the boot hydrator to re-verify a community overlay entry's manifest pin;
        None (miss OR transport error) makes the hydrator SKIP the entry (fail-closed load).
        """
        try:
            raw: Any = await self._redis.hget(self._approved_key(tenant_id), alias)
        except RedisError:
            return None
        return _decode_record(raw)

    async def list_approved(self, tenant_id: str) -> dict[str, dict[str, Any]]:
        """All approved community skills for a tenant → {alias: record}. Fail-soft."""
        try:
            raw: Any = await self._redis.hgetall(self._approved_key(tenant_id))
        except RedisError:
            return {}
        return _decode_hash(raw)


def _decode_record(raw: Any) -> Optional[dict[str, Any]]:
    """Decode one stored JSON record → dict, or None on absence/corruption. Fail-soft."""
    if raw is None:
        return None
    try:
        loaded = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return loaded if isinstance(loaded, dict) else None


def _decode_hash(raw: Any) -> dict[str, dict[str, Any]]:
    """Decode a Redis hash of JSON records → {field: record}, skipping corrupt rows."""
    out: dict[str, dict[str, Any]] = {}
    for k, v in (raw or {}).items():
        field = k.decode() if isinstance(k, bytes) else str(k)
        record = _decode_record(v)
        if record is not None:
            out[field] = record
    return out


__all__ = [
    "ExtensionSubmissionStore",
    "STATE_PENDING",
    "STATE_APPROVED",
    "STATE_REJECTED",
]
