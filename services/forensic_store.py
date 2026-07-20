"""
MCPIP V2 — Service: forensic payload capture store (admin/investigator side-channel).

    ◐ "The agent wire stays opaque. The investigator's ledger does not have to be —
       but only an investigator, and only under audit, ever reads it."

The agent boundary is deliberately opaque: an agent only ever sees ``MCPIPDenied`` +
a ``correlation_id``, and the operator decision feed omits the arguments a request
carried. That leaves a gap for an incident investigator who needs to reconstruct the
REAL query an agent sent — the alias, the normalized arguments, and the non-secret
identity context — for a specific ``correlation_id``.

``ForensicCaptureStore`` closes that gap WITHOUT touching the agent boundary. It mirrors
``services.secret_vault.SecretVault`` exactly:

  * AES-256-GCM at rest under a DEDICATED master key held OUTSIDE Redis (a key file,
    like the WORM signing key and the vault key). Dumping Redis yields only ciphertext.
  * The (tenant, correlation_id) identity is bound as length-prefixed AAD, so a
    ciphertext blob transplanted onto another tenant's / correlation's row refuses to
    decrypt (no cross-tenant read, no exists-elsewhere oracle).
  * TTL-bounded (``FORENSIC_TTL_SECONDS``): captures expire; a stale id is an honest
    miss; no agent-side path can extend the TTL.
  * Secrets NEVER captured: the arguments (and the whole snapshot) are run through the
    reused WORM ``_redact`` discipline before encryption; the caller never places
    pin/jwt/pop_proof/vended-credential/challenge_id/lock_code/payload_hash/target into
    the snapshot to begin with.
  * A SINGLE fail-closed reader ``retrieve()``: any miss/transport/corrupt/wrong-key
    outcome returns ``None`` (deny-by-default), never an error the caller can distinguish
    from "not found".

Capture is best-effort: ``capture()`` raises on a genuine transport/encryption error so
the fire-and-forget side-channel in the pipeline can swallow it — a capture failure must
never block or flip an authorization decision.
"""

from __future__ import annotations

import base64
import json
import os
import struct
from dataclasses import dataclass
from typing import Any, Optional

import redis.asyncio as redis
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from redis.exceptions import RedisError

from audit.worm_logger import _redact
from interfaces import FORENSIC_TTL_SECONDS, MAX_FORENSIC_PAYLOAD_BYTES

_KEY_PREFIX = "mcpip:forensic:"
_NONCE_LEN = 12  # AES-GCM standard nonce size.


@dataclass(frozen=True)
class ForensicRecord:
    """
    The reconstructed, REDACTED view of one captured request — the investigator surface.

    Carries the agent's QUERY (alias + already-normalized, secret-scrubbed arguments)
    and non-secret identity context ONLY. It NEVER carries the hidden real ``target``,
    the ``payload_hash``, a PIN/JWT/proof, or any vended credential — those are excluded
    at capture time and scrubbed by ``_redact`` as defence-in-depth.
    """

    correlation_id: str
    tenant_id: str
    agent_id: str
    role: str
    issuer: str
    alias: str
    arguments: dict[str, Any]
    source_format: str
    decision: str
    deny_reason: Optional[str]
    act_sub: Optional[str]
    captured_at: float

    def public_view(self) -> dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "role": self.role,
            "issuer": self.issuer,
            "alias": self.alias,
            "arguments": self.arguments,
            "source_format": self.source_format,
            "decision": self.decision,
            "deny_reason": self.deny_reason,
            "act_sub": self.act_sub,
            "captured_at": self.captured_at,
        }


class ForensicCaptureStore:
    """
    Redis-backed, per-(tenant, correlation_id), AES-256-GCM-encrypted capture store.

    The master key is held by the process (loaded from a key file at boot) and never
    persisted alongside the data: Redis holds ciphertext only. The store has exactly
    two operations — ``capture`` (best-effort write) and ``retrieve`` (fail-closed read).
    """

    def __init__(self, redis_client: "redis.Redis", master_key: bytes) -> None:
        if len(master_key) != 32:
            raise RuntimeError("forensic master key must be exactly 32 bytes (AES-256)")
        self._redis = redis_client
        self._aead = AESGCM(master_key)

    @staticmethod
    def _key(tenant_id: str, correlation_id: str) -> str:
        return f"{_KEY_PREFIX}{tenant_id}:{correlation_id}"

    @staticmethod
    def _aad(tenant_id: str, correlation_id: str) -> bytes:
        # Length-prefixed so (tenant, correlation_id) is UNAMBIGUOUS — no delimiter-
        # collision class where two distinct identity pairs share the same AAD.
        t, c = tenant_id.encode(), correlation_id.encode()
        return struct.pack(">II", len(t), len(c)) + t + c

    async def capture(
        self, tenant_id: str, correlation_id: str, snapshot: dict[str, Any]
    ) -> None:
        """
        Redact, encrypt, and persist one capture with a TTL. Best-effort: raises on a
        genuine transport/encryption failure (the caller swallows it). Silently SKIPS an
        oversize snapshot (returns without writing) rather than truncating a payload.

        The snapshot is run through the WORM ``_redact`` discipline BEFORE encryption, so
        any secret-shaped key that ever reached it is scrubbed even inside the ciphertext.
        """
        redacted = _redact(snapshot)
        plaintext = json.dumps(
            redacted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        if len(plaintext) > MAX_FORENSIC_PAYLOAD_BYTES:
            # Best-effort ceiling: an oversize snapshot is dropped, not stored truncated.
            return
        nonce = os.urandom(_NONCE_LEN)
        blob = nonce + self._aead.encrypt(
            nonce, plaintext, self._aad(tenant_id, correlation_id)
        )
        payload = base64.b64encode(blob).decode()
        try:
            await self._redis.set(
                self._key(tenant_id, correlation_id),
                payload,
                ex=FORENSIC_TTL_SECONDS,
            )
        except RedisError as exc:
            raise RuntimeError("forensic transport failure during capture") from exc

    async def retrieve(
        self, tenant_id: str, correlation_id: str
    ) -> Optional[ForensicRecord]:
        """
        Decrypt and return one capture — the SINGLE reader, fail-closed. Returns ``None``
        on ANY failure (missing, transport, corrupt, wrong key, AAD mismatch): a
        cross-tenant / wrong-correlation blob is an indistinguishable miss, never an
        exists-elsewhere oracle.
        """
        try:
            raw: Any = await self._redis.get(self._key(tenant_id, correlation_id))
        except RedisError:
            return None
        if not isinstance(raw, str) or not raw:
            return None
        try:
            blob = base64.b64decode(raw)
            nonce, ciphertext = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
            plaintext = self._aead.decrypt(
                nonce, ciphertext, self._aad(tenant_id, correlation_id)
            )
            data = json.loads(plaintext)
        except Exception:  # noqa: BLE001 — any decrypt/decode failure is a miss.
            return None
        if not isinstance(data, dict):
            return None
        return _decode_record(correlation_id, tenant_id, data)


def _decode_record(
    correlation_id: str, tenant_id: str, data: dict[str, Any]
) -> Optional[ForensicRecord]:
    """Rehydrate a ForensicRecord from decrypted fields; fail-closed to None on shape."""
    args = data.get("arguments")
    if not isinstance(args, dict):
        args = {}
    try:
        return ForensicRecord(
            correlation_id=correlation_id,
            tenant_id=tenant_id,
            agent_id=str(data.get("agent_id", "")),
            role=str(data.get("role", "")),
            issuer=str(data.get("issuer", "")),
            alias=str(data.get("alias", "")),
            arguments=args,
            source_format=str(data.get("source_format", "")),
            decision=str(data.get("decision", "")),
            deny_reason=(
                str(data["deny_reason"]) if data.get("deny_reason") is not None else None
            ),
            act_sub=(str(data["act_sub"]) if data.get("act_sub") is not None else None),
            captured_at=float(data.get("captured_at", 0.0)),
        )
    except (TypeError, ValueError):
        return None


__all__ = [
    "ForensicCaptureStore",
    "ForensicRecord",
]
