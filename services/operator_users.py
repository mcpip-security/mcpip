"""
MCPIP — Service: OperatorUserStore (the admin-managed console team roster).

    ◐ "Who may operate this gateway is a roster the admin curates — invite by email,
       assign a role LABEL, enable/disable/remove. But the roster authorizes NOTHING:
       identity and authorization still come only from a verified JWT + capabilities.
       The role here is a management word, never a gate."

An email-keyed, per-tenant record set the console's admin surface manages at scale
(``GET``/``POST``/``PUT``/``DELETE /v1/admin/users``). Deliberately a MANAGEMENT
surface, kept honest against MCPIP's load-bearing invariants:

  * **The ``role`` label authorizes nothing.** It is `admin` / `member` / `viewer`
    for the operator's own team bookkeeping and for the operator's IdP/SSO to honor
    when it issues tokens — the gateway hot path NEVER reads it (the role-claim
    invariant: authorization gates only on capability UUIDs + grants). Nothing in
    this module is consulted on the authorize path.
  * **Identity stays JWT-only.** This roster does not authenticate anyone and mints
    no session — an invite produces a shareable *reference token*, not a credential.
    The invited person still authenticates through the configured IdP.
  * **Scale.** The roster is a Redis HASH ``mcpip:opusers:{tenant}`` (field = the
    normalized email, value = the record JSON), listed by HSCAN **cursor** (never an
    offset), bounded by ``MAX_OPERATOR_USERS``; a page is ``<= MAX_OPERATOR_PAGE``.
  * **Tenant isolation.** Every key is derived from the JWT tenant id — an admin
    reads/writes ONLY its own tenant's roster; a cross-tenant edit is structurally
    impossible.

Fail posture mirrors the other admin stores: reads are fail-soft (transport error →
empty), writes are fail-closed (transport error → ``LockError`` so the caller learns
the change did not durably land). Every human string is ``reject_unsafe_string``-
scrubbed and identity-fold-checked before it is ever stored.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Final, Literal, Optional

import redis.asyncio as redis
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from redis.exceptions import RedisError

from auth import LockError
from interfaces import (
    MAX_OPERATOR_EMAIL_LEN,
    MAX_OPERATOR_PAGE,
    MAX_OPERATOR_USERS,
    reject_unsafe_string,
)

_KEY_PREFIX: Final[str] = "mcpip:opusers:"

# A deliberately conservative address shape: exactly one ``@``, non-empty, dotted
# domain, no whitespace. Combined with reject_unsafe_string + the length + identity
# checks — this is a SHAPE gate for a stored key, not RFC-5322 validation.
_EMAIL_RE: Final[re.Pattern[str]] = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

OperatorRole = Literal["admin", "member", "viewer"]
OperatorStatus = Literal["invited", "active", "disabled"]

_ROLES: Final[frozenset[str]] = frozenset(("admin", "member", "viewer"))
_STATUSES: Final[frozenset[str]] = frozenset(("invited", "active", "disabled"))


class OperatorUserError(ValueError):
    """A supplied operator-user field is malformed / out of range (caller → opaque deny)."""


class OperatorUserConflict(Exception):
    """An invite targets an email already on the roster (caller → opaque conflict deny)."""


class OperatorUserNotFound(Exception):
    """An update/remove targets an email not on the roster (caller → opaque not-found)."""


class OperatorUserCapExceeded(Exception):
    """The roster is at ``MAX_OPERATOR_USERS`` (caller → opaque deny)."""


def normalize_email(raw: object) -> str:
    """Normalize + strictly validate an operator email into the stored key form.

    Lowercases and strips, bounds the length, enforces the address shape, runs the
    shared charset guard, and refuses an identity-shaped local part (a ``role`` /
    ``tenant_id`` homoglyph can never become a roster key). Raises
    :class:`OperatorUserError` on any violation.
    """
    if not isinstance(raw, str):
        raise OperatorUserError("email must be a string")
    email = raw.strip().lower()
    if not email or len(email) > MAX_OPERATOR_EMAIL_LEN:
        raise OperatorUserError("email is empty or exceeds the length cap")
    if not _EMAIL_RE.match(email):
        raise OperatorUserError("email is not a valid address")
    try:
        safe = reject_unsafe_string(email, "operator_email")
    except ValueError as exc:
        raise OperatorUserError("unsafe character in email") from exc
    # Identity-fold guard: the local part must not be an identity-shaped token.
    from bridge.intent_parser import _FORBIDDEN_IDENTITY_KEYS, _identity_fold

    local = safe.split("@", 1)[0]
    if _identity_fold(local) in _FORBIDDEN_IDENTITY_KEYS:
        raise OperatorUserError("identity-shaped email local part")
    return safe


def _validate_role(raw: object) -> OperatorRole:
    if not isinstance(raw, str) or raw not in _ROLES:
        raise OperatorUserError("role must be one of admin|member|viewer")
    return raw  # type: ignore[return-value]


def _validate_status(raw: object) -> OperatorStatus:
    if not isinstance(raw, str) or raw not in _STATUSES:
        raise OperatorUserError("status must be one of invited|active|disabled")
    return raw  # type: ignore[return-value]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class OperatorUser(BaseModel):
    """One roster record. Frozen + strict; ``invite_token_hash`` never crosses the wire."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    email: str
    role: OperatorRole
    status: OperatorStatus
    invited_by: str
    invited_at: str
    updated_at: str
    # SHA-256 of the one-time invite reference token; the raw token is returned ONCE
    # at invite time and never stored or re-shown. None once accepted/cleared.
    invite_token_hash: Optional[str] = None

    def public(self) -> dict[str, Any]:
        """The admin-facing projection — the secret token hash is never included."""
        return {
            "email": self.email,
            "role": self.role,
            "status": self.status,
            "invited_by": self.invited_by,
            "invited_at": self.invited_at,
            "updated_at": self.updated_at,
        }


class OperatorUserStore:
    """Redis-backed, per-tenant, email-keyed operator/team roster."""

    def __init__(self, redis_client: "redis.Redis") -> None:
        self._redis = redis_client

    @staticmethod
    def _key(tenant_id: str) -> str:
        return f"{_KEY_PREFIX}{tenant_id}"

    async def count(self, tenant_id: str) -> int:
        """Roster cardinality. Fail-soft (0 on transport error)."""
        try:
            return int(await self._redis.hlen(self._key(tenant_id)))
        except RedisError:
            return 0

    async def get(self, tenant_id: str, email: str) -> Optional[OperatorUser]:
        """Return one record by email, or None. Fail-soft."""
        try:
            key_email = normalize_email(email)
        except OperatorUserError:
            return None
        try:
            raw: Any = await self._redis.hget(self._key(tenant_id), key_email)
        except RedisError:
            return None
        return self._parse(raw)

    async def list(
        self, tenant_id: str, cursor: str = "0", limit: int = MAX_OPERATOR_PAGE
    ) -> tuple[list[OperatorUser], str]:
        """
        A cursor page of the roster (HSCAN, never an offset). Returns ``(users,
        next_cursor)`` where ``next_cursor == "0"`` means the scan is complete.
        Fail-soft: a transport error returns an empty, completed page.
        """
        try:
            count = max(1, min(int(limit), MAX_OPERATOR_PAGE))
        except (TypeError, ValueError):
            count = MAX_OPERATOR_PAGE
        cur = cursor if isinstance(cursor, str) and cursor.isdigit() else "0"
        try:
            next_cur, mapping = await self._redis.hscan(
                self._key(tenant_id), cursor=int(cur), count=count
            )
        except RedisError:
            return [], "0"
        users: list[OperatorUser] = []
        for raw in (mapping or {}).values():
            parsed = self._parse(raw)
            if parsed is not None:
                users.append(parsed)
        users.sort(key=lambda u: u.email)
        return users, str(next_cur)

    async def invite(
        self, tenant_id: str, email: str, role: object, invited_by: str
    ) -> tuple[OperatorUser, str]:
        """
        Add a NEW roster member in ``invited`` status. Additive-only: an email already
        on the roster raises :class:`OperatorUserConflict` (never a silent repoint). A
        full roster raises :class:`OperatorUserCapExceeded`. Returns the record and the
        RAW one-time invite reference token (stored only as a hash).
        """
        key_email = normalize_email(email)
        vrole = _validate_role(role)
        if await self.count(tenant_id) >= MAX_OPERATOR_USERS:
            raise OperatorUserCapExceeded("operator roster is at capacity")
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = _now_iso()
        record = OperatorUser(
            email=key_email,
            role=vrole,
            status="invited",
            invited_by=invited_by,
            invited_at=now,
            updated_at=now,
            invite_token_hash=token_hash,
        )
        # HSETNX is atomic + additive-only: a concurrent invite for the same email
        # cannot repoint an existing record (mirrors the catalog-overlay discipline).
        try:
            created = await self._redis.hsetnx(
                self._key(tenant_id), key_email, self._dump(record)
            )
        except RedisError as exc:
            raise LockError("operator roster transport failure during invite") from exc
        if not created:
            raise OperatorUserConflict("email already on the roster")
        return record, token

    async def update(
        self,
        tenant_id: str,
        email: str,
        *,
        role: Optional[object] = None,
        status: Optional[object] = None,
    ) -> OperatorUser:
        """
        Update an EXISTING member's role and/or status. Refuses a non-member with
        :class:`OperatorUserNotFound`. Activating (``status='active'``) clears the
        pending invite token. Fail-closed on transport (``LockError``).
        """
        key_email = normalize_email(email)
        existing = await self.get(tenant_id, key_email)
        if existing is None:
            raise OperatorUserNotFound("email is not on the roster")
        new_role = _validate_role(role) if role is not None else existing.role
        new_status = _validate_status(status) if status is not None else existing.status
        token_hash = existing.invite_token_hash
        if new_status != "invited":
            token_hash = None  # accepted/disabled ⇒ the invite reference is spent
        updated = OperatorUser(
            email=existing.email,
            role=new_role,
            status=new_status,
            invited_by=existing.invited_by,
            invited_at=existing.invited_at,
            updated_at=_now_iso(),
            invite_token_hash=token_hash,
        )
        try:
            await self._redis.hset(self._key(tenant_id), key_email, self._dump(updated))
        except RedisError as exc:
            raise LockError("operator roster transport failure during update") from exc
        return updated

    async def remove(self, tenant_id: str, email: str) -> bool:
        """Remove a member. Returns True if a record was deleted. Fail-closed on transport."""
        key_email = normalize_email(email)
        try:
            deleted = await self._redis.hdel(self._key(tenant_id), key_email)
        except RedisError as exc:
            raise LockError("operator roster transport failure during remove") from exc
        return bool(deleted)

    # -- serialization helpers -------------------------------------------------
    @staticmethod
    def _dump(record: OperatorUser) -> str:
        return json.dumps(record.model_dump(), separators=(",", ":"))

    @staticmethod
    def _parse(raw: Any) -> Optional[OperatorUser]:
        if raw is None:
            return None
        try:
            loaded = json.loads(raw)
        except (ValueError, TypeError):
            return None
        try:
            return OperatorUser.model_validate(loaded)
        except ValidationError:
            return None


__all__ = [
    "MAX_OPERATOR_PAGE",
    "OperatorRole",
    "OperatorStatus",
    "OperatorUser",
    "OperatorUserCapExceeded",
    "OperatorUserConflict",
    "OperatorUserError",
    "OperatorUserNotFound",
    "OperatorUserStore",
    "normalize_email",
]
