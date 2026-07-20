"""
MCPIP V2 — Service: VerifiedPublisherStore (the registry-governance allow-list, X3).

    ◐ "The official MCP Registry is preview + unsigned. A registry-sourced skill earns
       trust from a reviewer-PINNED allow-list of publisher namespaces — never from the
       server.json's own (untrusted) provenance."

Backing store for the X3 verified-publisher gate. One per-tenant Redis document,
``mcpip:ext:publishers:{tenant}`` (schema ``mcpip-registry-publishers/1``), holding a
BOUNDED set of allowed publisher NAMESPACES (the reverse-DNS prefix of a server.json
``name``, e.g. ``io.github.owner``). It is the reviewer-maintained pinned allow-list the
registry approve/boot re-verify consult — there is NO live PKI and NO network fetch on any
path; the read happens OFF the auth hot path (only at approve + boot).

Fail posture (mirrors ``PolicyDocStore``):
  * ``validate`` — strict write-time gate the admin PUT uses (opaque deny on malformed).
  * ``load`` — fail-CLOSED read used at approve + boot: a ``RedisError`` OR an absent/
    malformed document raises :class:`PublisherStoreError`, so the caller treats a missing
    allow-list as "not verified" and REFUSES the approval (never a silent open pass).
  * ``get`` — fail-SOFT operator read backing the admin GET (a transport error yields None).
  * ``put`` — fail-closed persist (a ``RedisError`` raises ``LockError``).

Every key is tenant-scoped from the JWT-derived tenant id — a reviewer reads/writes ONLY
its own tenant's allow-list, so a cross-tenant publisher grant is structurally impossible.
"""

from __future__ import annotations

import json
from typing import Any, Final, Optional

import redis.asyncio as redis
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from redis.exceptions import RedisError

from auth import LockError
from interfaces import (
    MAX_PUBLISHER_NAMESPACE_LEN,
    MAX_VERIFIED_PUBLISHERS,
    reject_unsafe_string,
)

# Schema tag every stored/accepted allow-list document must carry (mirrors the policy
# store's ``mcpip-policy/1`` discipline). A bump means a breaking shape change.
PUBLISHERS_SCHEMA: Final[str] = "mcpip-registry-publishers/1"

_KEY_PREFIX: Final[str] = "mcpip:ext:publishers:"


class PublisherAllowListError(ValueError):
    """The supplied allow-list document is malformed or over-cap (caller → opaque deny)."""


class PublisherStoreError(Exception):
    """
    Internal error reading the stored allow-list (Redis transport error, an absent doc, or
    a malformed persisted doc). The approve/boot gate treats this as NOT-verified and
    REFUSES fail-closed — it never propagates to the caller as itself.
    """


class PublisherAllowList(BaseModel):
    """A validated per-tenant verified-publisher allow-list: a schema tag + a bounded set.

    Each namespace is a reverse-DNS publisher prefix (e.g. ``io.github.owner``), charset-
    scrubbed, identity-fold-safe (a ``role``/``tenant_id`` homoglyph namespace is refused),
    length-bounded, and de-duplicated. The list is bounded by ``MAX_VERIFIED_PUBLISHERS``.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_: str = Field(alias="schema")
    namespaces: list[str] = Field(
        default_factory=list, max_length=MAX_VERIFIED_PUBLISHERS
    )

    @field_validator("namespaces")
    @classmethod
    def _validate_namespaces(cls, value: list[str]) -> list[str]:
        from bridge.intent_parser import _FORBIDDEN_IDENTITY_KEYS, _identity_fold

        seen: set[str] = set()
        cleaned: list[str] = []
        for ns in value:
            if not isinstance(ns, str) or not ns:
                raise ValueError("publisher namespace must be a non-empty string")
            if len(ns) > MAX_PUBLISHER_NAMESPACE_LEN:
                raise ValueError("publisher namespace exceeds the length cap")
            try:
                safe = reject_unsafe_string(ns, "publisher_namespace")
            except ValueError as exc:
                raise ValueError("unsafe character in publisher namespace") from exc
            if _identity_fold(safe) in _FORBIDDEN_IDENTITY_KEYS:
                raise ValueError("identity-shaped publisher namespace")
            if safe in seen:
                raise ValueError("duplicate publisher namespace")
            seen.add(safe)
            cleaned.append(safe)
        return cleaned

    @model_validator(mode="after")
    def _validate_schema(self) -> "PublisherAllowList":
        if self.schema_ != PUBLISHERS_SCHEMA:
            raise ValueError("unknown or missing publishers schema")
        return self

    def contains(self, namespace: str) -> bool:
        """True iff ``namespace`` is a pinned member of this allow-list."""
        return namespace in self.namespaces


class VerifiedPublisherStore:
    """Redis-backed per-tenant verified-publisher allow-list store."""

    def __init__(self, redis_client: "redis.Redis") -> None:
        self._redis = redis_client

    @staticmethod
    def _key(tenant_id: str) -> str:
        return f"{_KEY_PREFIX}{tenant_id}"

    @staticmethod
    def validate(document: object) -> dict[str, Any]:
        """
        Strict-validate an operator-supplied allow-list document. Fail-closed.

        Enforces the ``mcpip-registry-publishers/1`` schema, ``<= MAX_VERIFIED_PUBLISHERS``
        charset-safe/identity-safe/de-duplicated namespaces. Raises
        :class:`PublisherAllowListError` on any violation. Returns the canonical stored dict
        (the re-serialized validated document) so a stored doc always round-trips through the
        same strict model ``load`` parses.
        """
        if not isinstance(document, dict):
            raise PublisherAllowListError("publishers document must be a JSON object")
        try:
            allow = PublisherAllowList.model_validate(document)
        except ValidationError as exc:
            raise PublisherAllowListError("malformed publishers document") from exc
        return allow.model_dump(by_alias=True)

    async def get(self, tenant_id: str) -> Optional[dict[str, Any]]:
        """Return the stored document for ``tenant_id``, or None. Fail-SOFT (admin read)."""
        try:
            raw: Any = await self._redis.get(self._key(tenant_id))
        except RedisError:
            return None
        if raw is None:
            return None
        try:
            loaded = json.loads(raw)
        except (ValueError, TypeError):
            return None
        return loaded if isinstance(loaded, dict) else None

    async def load(self, tenant_id: str) -> PublisherAllowList:
        """
        Fail-CLOSED read used at approve + boot. Returns the parsed allow-list, or RAISES
        :class:`PublisherStoreError` on a Redis transport error, an ABSENT document, or a
        malformed persisted document. An absent allow-list is deliberately an ERROR (not an
        empty pass): with no pinned publishers, NOTHING is verified, so a registry approval
        must be refused fail-closed.
        """
        try:
            raw: Any = await self._redis.get(self._key(tenant_id))
        except RedisError as exc:
            raise PublisherStoreError("publishers document transport failure") from exc
        if raw is None:
            raise PublisherStoreError("no verified-publisher allow-list configured")
        try:
            loaded = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise PublisherStoreError("stored publishers document is not valid JSON") from exc
        try:
            return PublisherAllowList.model_validate(loaded)
        except ValidationError as exc:
            raise PublisherStoreError("stored publishers document is malformed") from exc

    async def is_verified(self, tenant_id: str, namespace: str) -> bool:
        """
        Fail-CLOSED membership check for the approve/boot gate.

        True ONLY if the tenant's allow-list loads AND ``namespace`` is a pinned member.
        Any load failure (transport, absent, malformed) → False (not verified → refuse).
        """
        try:
            allow = await self.load(tenant_id)
        except PublisherStoreError:
            return False
        return allow.contains(namespace)

    async def put(self, tenant_id: str, document: dict[str, Any]) -> None:
        """
        Persist a validated allow-list for ``tenant_id``. Fail-closed: a transport error
        raises ``LockError`` so the caller learns the save did not durably land. Callers
        MUST pass a document already through :meth:`validate`.
        """
        payload = json.dumps(document, separators=(",", ":"))
        try:
            await self._redis.set(self._key(tenant_id), payload)
        except RedisError as exc:
            raise LockError("publishers document transport failure during put") from exc


__all__ = [
    "PUBLISHERS_SCHEMA",
    "PublisherAllowList",
    "PublisherAllowListError",
    "PublisherStoreError",
    "VerifiedPublisherStore",
]
