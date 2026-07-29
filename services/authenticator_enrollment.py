"""
MCPIP V2 — Service: per-user authenticator enrollment (user-based 2FA, RFC 6238 TOTP).

    ◐ Auth: "The step-up code stays payload-bound; the HUMAN who may see it
       is now proven by something they hold."

Before this module, step-up delivery was DEPLOYMENT-based (one sandbox stash or one
tenant webhook). This store makes the second factor USER-based: each principal enrolls
a standard authenticator app (Google Authenticator / 1Password / Authy — plain RFC 6238
TOTP, SHA-1/6-digit/30s), and only a principal presenting a valid, fresh, un-replayed
code from THEIR enrolled device can release a staged one-time PIN to complete a
``PIN_REQUIRED`` action.

What this module deliberately does NOT do:

  * It never touches how the payload-bound PIN is derived, bound, or consumed —
    ``canonical_json`` / ``enforce_argument_safety`` / scrypt / the atomic Lua and the
    Rust mirror are all out of scope (the G1 delivery-seam invariant). TOTP gates WHO
    may READ a delivered code, never what the lock verifies.
  * It is not an identity source. Identity still comes exclusively from the verified
    JWT; enrollment binds extra proof-of-possession to that principal, confers no
    capability, and the ``role`` claim still authorizes nothing.

Storage discipline (mirrors ``services/secret_vault.py``): the TOTP secret is
AES-256-GCM-encrypted under a dedicated 32-byte master key held OUTSIDE Redis
(``MCPIP_AUTHN_TOTP_KEY_PATH`` in production; a persistent ``.keys/`` dev key in
sandbox). The (tenant, principal) identity is length-prefix-bound as AAD, so a blob
transplanted to another principal or tenant will not decrypt. Dumping Redis yields
ciphertext only; destroying the key crypto-shreds every enrollment at once.

Verification discipline (all fail-closed):

  * constant-time digit compare (``hmac.compare_digest``);
  * ±``TOTP_DRIFT_STEPS`` steps of clock drift, nothing more;
  * REPLAY GUARD — a (tenant, principal, timestep) that verified once is burned via
    ``SET NX`` for the drift window, so the same 6 digits can never be spent twice;
  * ATTEMPT LIMITER — a fixed-window failure counter (``MAX_TOTP_ATTEMPTS`` per
    ``TOTP_ATTEMPT_WINDOW_S``) locks verification out BEFORE any secret is decrypted,
    defeating online guessing with O(1) Redis work;
  * any Redis/decrypt/shape failure verifies as False — never an open pass.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import time
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import quote

import redis.asyncio as redis
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from redis.exceptions import RedisError

from interfaces import (
    MAX_AUTHENTICATOR_ROSTER,
    MAX_TOTP_ATTEMPTS,
    TOTP_ATTEMPT_WINDOW_S,
    TOTP_DIGITS,
    TOTP_DRIFT_STEPS,
    TOTP_PERIOD_S,
)

_ENROLL_PREFIX = "mcpip:authn:totp:"
_USED_PREFIX = "mcpip:authn:used:"
_FAIL_PREFIX = "mcpip:authn:fail:"
_NONCE_LEN = 12  # AES-GCM standard nonce size.
_SECRET_BYTES = 20  # 160-bit shared secret (RFC 4226 recommended minimum).
_ISSUER = "MCPIP"


@dataclass(frozen=True)
class EnrollmentStatus:
    """Operator-visible state of one principal's enrollment. NEVER carries the secret."""

    enrolled: bool          # an ACTIVE, confirmed authenticator exists.
    pending: bool           # a begin() was issued but not yet confirmed.
    enrolled_at: Optional[float]

    def public_view(self) -> dict[str, Any]:
        return {
            "enrolled": self.enrolled,
            "pending": self.pending,
            "enrolled_at": self.enrolled_at,
        }


@dataclass(frozen=True)
class EnrollmentBegin:
    """One-time provisioning material returned ONCE at begin(). Never persisted plaintext."""

    secret_base32: str      # manual-entry key for the authenticator app.
    provisioning_uri: str   # otpauth:// URI (QR payload) for scan-based apps.
    digits: int
    period_s: int


def _hotp(secret: bytes, counter: int) -> str:
    """RFC 4226 HOTP: HMAC-SHA1 dynamic truncation to ``TOTP_DIGITS`` decimal digits."""
    mac = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**TOTP_DIGITS)
    return str(code).zfill(TOTP_DIGITS)


def _totp_at(secret: bytes, timestep: int) -> str:
    """RFC 6238 TOTP = HOTP over the Unix-time step counter."""
    return _hotp(secret, timestep)


def current_timestep(now: Optional[float] = None) -> int:
    """The RFC 6238 step counter for ``now`` (exposed for tests)."""
    return int((now if now is not None else time.time()) // TOTP_PERIOD_S)


class AuthenticatorEnrollmentStore:
    """
    Redis-backed, per-(tenant, principal), AES-256-GCM-encrypted TOTP enrollment store.

    The master key is process-held (loaded from a key file at boot) and never persisted
    beside the data. The raw secret leaves this module exactly once — inside the
    ``EnrollmentBegin`` returned to the enrolling principal over TLS — and is never
    logged, never WORM-recorded, and never readable back out of any endpoint.
    """

    def __init__(self, redis_client: "redis.Redis", master_key: bytes) -> None:
        if len(master_key) != 32:
            raise RuntimeError("authenticator master key must be exactly 32 bytes (AES-256)")
        self._redis = redis_client
        self._aead = AESGCM(master_key)

    # ------------------------------------------------------------------ keys

    @staticmethod
    def _key(tenant_id: str, agent_id: str) -> str:
        return f"{_ENROLL_PREFIX}{tenant_id}:{agent_id}"

    @staticmethod
    def _aad(tenant_id: str, agent_id: str) -> bytes:
        """Length-prefixed (tenant, principal) binding — unambiguous, transplant-proof."""
        t = tenant_id.encode("utf-8")
        a = agent_id.encode("utf-8")
        return struct.pack(">II", len(t), len(a)) + t + a

    # ------------------------------------------------------------ lifecycle

    async def begin(self, tenant_id: str, agent_id: str) -> Optional[EnrollmentBegin]:
        """
        Mint a fresh TOTP secret and store it as PENDING for this principal.

        Refused (None) while an ACTIVE enrollment exists — turning off or replacing a
        live authenticator must present a valid current code first (``disable``), so a
        stolen bearer token alone can never silently swap the human's second factor.
        A prior un-confirmed PENDING is overwritten (retry-friendly: nothing was proven).
        """
        fields = await self._load(tenant_id, agent_id)
        if fields is not None and fields.get("state") == "active":
            return None
        secret = os.urandom(_SECRET_BYTES)
        nonce = os.urandom(_NONCE_LEN)
        blob = nonce + self._aead.encrypt(nonce, secret, self._aad(tenant_id, agent_id))
        payload = {
            "state": "pending",
            "blob": base64.b64encode(blob).decode("ascii"),
            "created_at": time.time(),
            "confirmed_at": None,
        }
        await self._redis.set(self._key(tenant_id, agent_id), json.dumps(payload))
        secret_b32 = base64.b32encode(secret).decode("ascii").rstrip("=")
        label = quote(f"{_ISSUER}:{agent_id}", safe=":")
        uri = (
            f"otpauth://totp/{label}?secret={secret_b32}&issuer={_ISSUER}"
            f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD_S}"
        )
        return EnrollmentBegin(
            secret_base32=secret_b32,
            provisioning_uri=uri,
            digits=TOTP_DIGITS,
            period_s=TOTP_PERIOD_S,
        )

    async def confirm(self, tenant_id: str, agent_id: str, code: str) -> bool:
        """
        Prove possession: verify ``code`` against the PENDING secret and activate it.

        The activation flip is the only write; a wrong code leaves the enrollment
        pending (and burns an attempt in the shared limiter).
        """
        if not await self._admit_attempt(tenant_id, agent_id):
            return False
        fields = await self._load(tenant_id, agent_id)
        if fields is None or fields.get("state") != "pending":
            return False
        secret = self._decrypt(tenant_id, agent_id, fields)
        matched = self._code_matches(secret, code) if secret is not None else None
        if matched is None:
            await self._record_failure(tenant_id, agent_id)
            return False
        if not await self._burn_timestep(tenant_id, agent_id, matched):
            return False
        fields["state"] = "active"
        fields["confirmed_at"] = time.time()
        try:
            await self._redis.set(self._key(tenant_id, agent_id), json.dumps(fields))
        except RedisError:
            return False
        return True

    async def verify(self, tenant_id: str, agent_id: str, code: str) -> bool:
        """
        Verify a live code from this principal's ACTIVE authenticator. Fail-closed on
        every path: lockout, unenrolled, pending-only, undecryptable, wrong code, or a
        replayed timestep all return False.
        """
        if not await self._admit_attempt(tenant_id, agent_id):
            return False
        fields = await self._load(tenant_id, agent_id)
        if fields is None or fields.get("state") != "active":
            # Burn the attempt anyway: probing "is this principal enrolled?" costs the
            # same budget as a wrong guess (no cheaper oracle).
            await self._record_failure(tenant_id, agent_id)
            return False
        secret = self._decrypt(tenant_id, agent_id, fields)
        matched = self._code_matches(secret, code) if secret is not None else None
        if matched is None:
            await self._record_failure(tenant_id, agent_id)
            return False
        return await self._burn_timestep(tenant_id, agent_id, matched)

    async def status(self, tenant_id: str, agent_id: str) -> EnrollmentStatus:
        fields = await self._load(tenant_id, agent_id)
        if fields is None:
            return EnrollmentStatus(enrolled=False, pending=False, enrolled_at=None)
        state = fields.get("state")
        confirmed = fields.get("confirmed_at")
        return EnrollmentStatus(
            enrolled=state == "active",
            pending=state == "pending",
            enrolled_at=float(confirmed) if isinstance(confirmed, (int, float)) else None,
        )

    async def disable(self, tenant_id: str, agent_id: str, code: str) -> bool:
        """
        Self-service removal: requires a valid CURRENT code (standard 2FA-off ceremony —
        a bearer token alone cannot strip the human's factor). Admin lost-device removal
        is ``admin_disable`` below, gated by the caller on ``CAP_DIRECTORY_ADMIN``.
        """
        if not await self.verify(tenant_id, agent_id, code):
            return False
        try:
            await self._redis.delete(self._key(tenant_id, agent_id))
        except RedisError:
            return False
        return True

    async def admin_disable(self, tenant_id: str, agent_id: str) -> bool:
        """Capability-gated (by the endpoint) lost-device removal — same tenant only."""
        try:
            return bool(await self._redis.delete(self._key(tenant_id, agent_id)))
        except RedisError:
            return False

    async def list_enrolled(self, tenant_id: str) -> list[dict[str, Any]]:
        """
        Bounded admin roster of this tenant's enrollments (principal + state + time).
        Fail-soft ``[]`` on transport error — it backs a listing, never an authorization
        decision. The tenant id is glob-escaped so a wildcard-bearing tenant id cannot
        widen the SCAN into another tenant's namespace (shared rule with quarantine).
        """
        pattern = f"{_ENROLL_PREFIX}{_glob_escape(tenant_id)}:*"
        prefix_len = len(f"{_ENROLL_PREFIX}{tenant_id}:")
        rows: list[dict[str, Any]] = []
        try:
            async for key in self._redis.scan_iter(match=pattern, count=100):
                text = key.decode() if isinstance(key, (bytes, bytearray)) else str(key)
                raw = await self._redis.get(text)
                fields = _parse_fields(raw)
                if fields is None:
                    continue
                confirmed = fields.get("confirmed_at")
                rows.append(
                    {
                        "agent_id": text[prefix_len:],
                        "state": fields.get("state"),
                        "enrolled_at": confirmed
                        if isinstance(confirmed, (int, float))
                        else None,
                    }
                )
                if len(rows) >= MAX_AUTHENTICATOR_ROSTER:
                    break
        except RedisError:
            return []
        rows.sort(key=lambda r: str(r["agent_id"]))
        return rows

    # ------------------------------------------------------------- internals

    async def _load(self, tenant_id: str, agent_id: str) -> Optional[dict[str, Any]]:
        try:
            raw = await self._redis.get(self._key(tenant_id, agent_id))
        except RedisError:
            return None
        return _parse_fields(raw)

    def _decrypt(
        self, tenant_id: str, agent_id: str, fields: dict[str, Any]
    ) -> Optional[bytes]:
        blob_b64 = fields.get("blob")
        if not isinstance(blob_b64, str):
            return None
        try:
            blob = base64.b64decode(blob_b64.encode("ascii"), validate=True)
            nonce, ciphertext = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
            return self._aead.decrypt(nonce, ciphertext, self._aad(tenant_id, agent_id))
        except Exception:  # noqa: BLE001 — corrupt/foreign blob verifies as absent.
            return None

    @staticmethod
    def _code_matches(secret: bytes, code: str) -> Optional[int]:
        """
        Constant-time compare across the ±drift window; shape-checked first. Returns the
        MATCHED absolute timestep (so the replay guard burns exactly the code that was
        spent — RFC 6238 §5.2 one-success-per-code), or None on no match.
        """
        if not isinstance(code, str) or len(code) != TOTP_DIGITS or not code.isdigit():
            return None
        step = current_timestep()
        matched: Optional[int] = None
        for drift in range(-TOTP_DRIFT_STEPS, TOTP_DRIFT_STEPS + 1):
            expected = _totp_at(secret, step + drift)
            # No early exit: evaluate every window slot (timing-uniform).
            if hmac.compare_digest(expected, code):
                matched = step + drift
        return matched

    async def _burn_timestep(self, tenant_id: str, agent_id: str, timestep: int) -> bool:
        """
        One successful verification per CODE (its timestep): SET NX for the drift span.
        A second spend of the same code (replay) fails closed — including on Redis error.
        A different, fresher code (the next 30 s tick) burns a different key, so normal
        consecutive ceremonies (confirm now, reveal next tick) are never blocked.
        """
        key = f"{_USED_PREFIX}{tenant_id}:{agent_id}:{timestep}"
        ttl = TOTP_PERIOD_S * (2 * TOTP_DRIFT_STEPS + 1)
        try:
            return bool(await self._redis.set(key, "1", nx=True, ex=ttl))
        except RedisError:
            return False

    async def _admit_attempt(self, tenant_id: str, agent_id: str) -> bool:
        """Fixed-window online-guessing gate — O(1) Redis, refuses BEFORE any decrypt."""
        key = f"{_FAIL_PREFIX}{tenant_id}:{agent_id}"
        try:
            raw = await self._redis.get(key)
        except RedisError:
            return False
        try:
            return int(raw) < MAX_TOTP_ATTEMPTS if raw is not None else True
        except (TypeError, ValueError):
            return False

    async def _record_failure(self, tenant_id: str, agent_id: str) -> None:
        key = f"{_FAIL_PREFIX}{tenant_id}:{agent_id}"
        try:
            count = await self._redis.incr(key)
            if count == 1:
                await self._redis.expire(key, TOTP_ATTEMPT_WINDOW_S)
        except RedisError:
            # The limiter is itself fail-closed at admit time; a lost increment only
            # under-counts, and admit() already refuses on transport error.
            return


def _parse_fields(raw: Any) -> Optional[dict[str, Any]]:
    if raw is None:
        return None
    try:
        text = raw.decode() if isinstance(raw, (bytes, bytearray)) else str(raw)
        fields = json.loads(text)
    except (ValueError, UnicodeDecodeError):
        return None
    return fields if isinstance(fields, dict) else None


def _glob_escape(value: str) -> str:
    """Escape Redis glob metacharacters so a hostile id cannot widen a SCAN."""
    out = []
    for ch in value:
        if ch in "*?[]\\":
            out.append("\\")
        out.append(ch)
    return "".join(out)


__all__ = [
    "AuthenticatorEnrollmentStore",
    "EnrollmentBegin",
    "EnrollmentStatus",
    "current_timestep",
]
