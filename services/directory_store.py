"""
MCPIP V2 — Service: DirectoryStore (operator directory persistence).

    ◐ "The gateway persists policy ABOUT identities. It never mints one."

The operator directory is the org chart the console edits: Org Units → Teams →
principal *references* (agent_id, label, key-id, role, status) + the RBAC
role→capability matrix. This store persists that document per tenant so the
console's add / delete / drag / role edits survive across sessions and nodes.

Identity sovereignty (normative): this is NON-AUTHORITATIVE metadata. A directory
principal is a *reference* to an identity an external IdP mints
(``mint_principal.py``) — the gateway never mints, edits, or re-signs a credential
here, and the authorization pipeline NEVER consults this document. Authority still
comes only from a verified JWT + the Redis grant/revocation stores. The directory
is an address book; deleting a row here does not by itself deny anything (that is
the B1 revocation kill-switch's job).

Fail-closed discipline:
  * ``get`` is a fail-soft operator read (a transport error yields None — the
    console falls back to its local tree rather than crashing).
  * ``put`` raises ``LockError`` on a transport error so the operator is told the
    save did not durably land, rather than believing an edit persisted.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import redis.asyncio as redis
from redis.exceptions import RedisError

from auth import LockError

_KEY_PREFIX = "mcpip:directory:"
# A directory document is metadata, not bulk data — bound it well under the
# 256 KiB pre-auth body cap so a runaway payload can never bloat Redis.
MAX_DIRECTORY_BYTES = 128 * 1024
_DIRECTORY_SCHEMA = "mcpip-directory/1"


class DirectoryDocumentError(ValueError):
    """The supplied directory document is malformed or too large (caller → opaque deny)."""


class DirectoryStore:
    """Redis-backed per-tenant operator directory document. Non-authoritative."""

    def __init__(self, redis_client: "redis.Redis") -> None:
        self._redis = redis_client

    @staticmethod
    def _key(tenant_id: str) -> str:
        # Tenant-scoped: an admin reads/writes ONLY its own tenant's directory.
        return f"{_KEY_PREFIX}{tenant_id}"

    @staticmethod
    def validate(document: object) -> dict[str, Any]:
        """
        Validate an operator-supplied directory document. Fail-closed.

        Requires a JSON object carrying ``schema == "mcpip-directory/1"``, an
        ``org_units`` list, and (optional) a ``rbac`` object, serializing within
        ``MAX_DIRECTORY_BYTES``. Raises ``DirectoryDocumentError`` otherwise. The
        inner shape is operator metadata (bounded by the size cap) — the gateway
        never interprets it for authorization, so it is stored as given.
        """
        if not isinstance(document, dict):
            raise DirectoryDocumentError("directory document must be a JSON object")
        if document.get("schema") != _DIRECTORY_SCHEMA:
            raise DirectoryDocumentError("unknown or missing directory schema")
        if not isinstance(document.get("org_units"), list):
            raise DirectoryDocumentError("org_units must be a list")
        rbac = document.get("rbac")
        if rbac is not None and not isinstance(rbac, dict):
            raise DirectoryDocumentError("rbac must be an object")
        try:
            encoded = json.dumps(document, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise DirectoryDocumentError("directory document is not JSON-serializable") from exc
        if len(encoded) > MAX_DIRECTORY_BYTES:
            raise DirectoryDocumentError("directory document exceeds the size cap")
        return document

    async def get(self, tenant_id: str) -> Optional[dict[str, Any]]:
        """Return the stored document for ``tenant_id``, or None. Fail-soft read."""
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

    async def put(self, tenant_id: str, document: dict[str, Any]) -> None:
        """
        Persist a validated document for ``tenant_id``. Fail-closed: a transport
        error raises ``LockError`` so the caller learns the save did not land.
        Callers MUST pass a document already through :meth:`validate`.
        """
        payload = json.dumps(document, separators=(",", ":"))
        try:
            await self._redis.set(self._key(tenant_id), payload)
        except RedisError as exc:
            raise LockError("directory transport failure during put") from exc


__all__ = ["DirectoryStore", "DirectoryDocumentError", "MAX_DIRECTORY_BYTES"]
