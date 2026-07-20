"""
MCPIP V2 — Service: authenticator delivery channels (out-of-band OTP delivery).

    ◐ Auth: "The code is minted and locked once; only its DELIVERY is pluggable."

The payload-bound one-time PIN is minted and registered by ``AuthEngine.register_lock``
(unchanged: ``secrets`` mint + ``PinValidator.register`` — scrypt/canonical_json/register/
consume and the Rust mirror are all untouched). This module owns ONLY the delivery seam:
how the freshly-minted code reaches the operator's out-of-band authenticator / approver.
A channel receives an immutable ``AuthenticatorNotice`` and must get the code to that
factor; it NEVER influences how the OTP is derived or bound — it is strictly downstream
of register, so the register↔consume and Python↔Rust byte-identity is not in scope here.

Two concrete channels ship:

  * ``SandboxRedisAuthenticatorChannel`` — the runnable-demo channel. Stashes the raw OTP
    in Redis under the tenant-scoped ``mcpip:otp:{tenant}:{challenge}`` key with the lock
    TTL, exactly as the old in-engine sandbox stash did (zero demo behavior change), and
    exposes ``peek`` for the sandbox authenticator endpoint to read it back. SANDBOX ONLY:
    the composition root constructs it only in sandbox mode, so a production Redis dump
    never contains a plaintext code.

  * ``WebhookAuthenticatorChannel`` — the one REAL production channel. PUSHES the notice
    (including the raw code) to a tenant-configured authenticator/approver sink over an
    SSRF-guarded, HMAC-SHA256-signed HTTPS request. It persists NO OTP in Redis at all —
    strictly better than storing even ciphertext — and adds no new inbound endpoint. On
    any failure (guard rejection, transport error, non-2xx) it RAISES, and the engine maps
    that to a fail-closed ``OTP_DELIVERY_FAILED`` deny — never a silent allow.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import socket
import time
from typing import Any, Final
from urllib.parse import urlsplit

import httpx
import redis.asyncio as redis

from interfaces import (
    AuthenticatorNotice,
    BaseAuthenticatorChannel,
    MAX_AUTHN_WEBHOOK_RESPONSE_BYTES,
    MAX_AUTHN_WEBHOOK_TIMEOUT_S,
    MIN_AUTHN_WEBHOOK_TIMEOUT_S,
    PIN_TTL_SECONDS,
)


class AuthenticatorDeliveryError(Exception):
    """
    A channel could not deliver the notice.

    Raised by a concrete channel's ``deliver`` on any failure. ``AuthEngine`` catches it
    (and any other exception from ``deliver``) and re-raises the fail-closed
    ``GatewayDeny(OTP_DELIVERY_FAILED)`` — the concrete cause stays engine/WORM-side and
    never crosses the agent boundary. Carries a short operator-facing reason only (never
    the URL, the secret, or the OTP).
    """


# ---------------------------------------------------------------------------
# Sandbox channel — the runnable-demo out-of-band stand-in (Redis stash + peek).
# ---------------------------------------------------------------------------


class SandboxRedisAuthenticatorChannel(BaseAuthenticatorChannel):
    """
    SANDBOX-ONLY delivery channel: stash the OTP in Redis, read it back via ``peek``.

    Stands in for an enrolled authenticator surfacing the code to the operator. The
    stash key + TTL are byte-identical to the previous in-engine sandbox behavior, so
    the demo (and the ``/v1/authenticator/{challenge_id}`` endpoint) are unchanged. The
    composition root constructs this ONLY in sandbox mode, so production Redis never
    holds a plaintext code.
    """

    def __init__(self, redis_client: "redis.Redis") -> None:
        self._redis = redis_client

    async def deliver(self, notice: AuthenticatorNotice) -> None:
        """Stash the raw OTP under the tenant-scoped key with the lock TTL."""
        await self._redis.set(
            self._otp_key(notice.tenant_id, notice.challenge_id),
            notice.otp,
            ex=PIN_TTL_SECONDS,
        )

    async def peek(self, tenant_id: str, challenge_id: str) -> str | None:
        """
        Read back the stashed OTP for a staged challenge (the sandbox authenticator
        endpoint's sole source). Returns None if unknown or expired.
        """
        value: Any = await self._redis.get(self._otp_key(tenant_id, challenge_id))
        if value is None:
            return None
        # decode_responses=True yields str; normalize defensively for the checker.
        return str(value)

    @staticmethod
    def _otp_key(tenant_id: str, challenge_id: str) -> str:
        """Tenant-scoped Redis key for the sandbox out-of-band OTP channel."""
        return f"mcpip:otp:{tenant_id}:{challenge_id}"


# ---------------------------------------------------------------------------
# Production channel — SSRF-guarded, HMAC-signed HTTPS push (no OTP persisted).
# ---------------------------------------------------------------------------

# Header names for the signed push. The receiver reconstructs
# ``HMAC-SHA256(secret, timestamp + "." + body)`` and constant-time-compares the hex.
_SIG_HEADER: Final[str] = "X-MCPIP-Signature"
_TS_HEADER: Final[str] = "X-MCPIP-Timestamp"


class WebhookAuthenticatorChannel(BaseAuthenticatorChannel):
    """
    Production delivery channel: SSRF-guarded, HMAC-SHA256-signed HTTPS push.

    ``deliver`` serializes the notice (including the raw code) to a canonical JSON body,
    signs ``timestamp + "." + body`` with the configured secret, and POSTs it to the
    tenant's authenticator/approver sink. Nothing is persisted in Redis — the code exists
    only in flight to the legitimate delivery target (TLS + HMAC-signed), never at rest.

    SSRF guard (all enforced per delivery, so a rotated DNS record cannot bypass it):
      1. scheme MUST be https;
      2. the host is resolved (``getaddrinfo``) and EVERY resolved address is checked —
         an IPv4-mapped IPv6 address is unwrapped first — and delivery is refused if any
         is private / loopback / link-local (covers 169.254.169.254 cloud metadata) /
         reserved / multicast / unspecified; an IP-literal host in those ranges is caught
         the same way;
      3. the connection is PINNED to the exact validated IP (DNS is not re-resolved by the
         client), defeating a DNS-rebinding TOCTOU, while the original hostname drives SNI
         and certificate verification;
      4. redirects are NOT followed (a 3xx is a failure — it could point back inside);
      5. connect+read are bounded by ``timeout_s`` (clamped to the interfaces band);
      6. a non-2xx status is a failure; the response body is ignored and bounded-read.

    The signing secret is held as raw bytes and used only to compute the signature header
    — it is never logged, never a metric label, and never placed in the notice body.
    """

    def __init__(self, url: str, secret: bytes, timeout_s: float) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise ValueError("authenticator webhook URL must be https")
        if not parts.hostname:
            raise ValueError("authenticator webhook URL must have a host")
        if not secret:
            raise ValueError("authenticator webhook signing secret must be non-empty")
        self._url = url
        self._host: str = parts.hostname
        self._port: int = parts.port or 443
        self._secret = secret
        # Clamp the operator timeout into the interfaces-defined safety band so a
        # misconfiguration can neither hang a staging request nor set a sub-threshold
        # value that always fails closed.
        self._timeout_s = max(
            MIN_AUTHN_WEBHOOK_TIMEOUT_S, min(MAX_AUTHN_WEBHOOK_TIMEOUT_S, timeout_s)
        )

    async def deliver(self, notice: AuthenticatorNotice) -> None:
        """Sign and push the notice to the configured sink; raise on any failure."""
        validated_ip = await self._resolve_and_validate()
        body = self._serialize(notice)
        timestamp = str(int(time.time()))
        signature = hmac.new(
            self._secret, timestamp.encode("ascii") + b"." + body, hashlib.sha256
        ).hexdigest()
        # Authority for the Host header: preserve a non-default port so the receiver's
        # virtual-host routing still matches.
        authority = self._host if self._port == 443 else f"{self._host}:{self._port}"
        headers = {
            "Content-Type": "application/json",
            "Host": authority,
            _TS_HEADER: timestamp,
            _SIG_HEADER: f"sha256={signature}",
        }
        # Pin the connection to the exact validated IP; keep the original hostname for
        # SNI + certificate verification (the ``sni_hostname`` request extension drives
        # both), so DNS is not re-resolved and rebinding cannot swing us to a private IP.
        ip_url = httpx.URL(self._url).copy_with(host=validated_ip)
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout_s),
                follow_redirects=False,
                verify=True,
                # Hermetic by construction: a secret-delivery client that hand-rolls
                # SSRF validation + connection IP-pinning must NOT also honor ambient
                # env. trust_env=True (httpx default) would let HTTPS_PROXY reroute the
                # push through an unvalidated intermediary (voiding the IP pin and the
                # loopback/private-IP guard), SSL_CERT_FILE trust that proxy's CA
                # (voiding the TLS pin), and SSLKEYLOGFILE leak session keys — any of
                # which discloses the raw one-time code. trust_env=False + no proxy
                # forces the direct, validated, pinned TLS connection the guard promises.
                trust_env=False,
                proxy=None,
            ) as client:
                request = client.build_request(
                    "POST",
                    ip_url,
                    content=body,
                    headers=headers,
                    extensions={"sni_hostname": self._host},
                )
                response = await client.send(request, stream=True)
                try:
                    status = response.status_code
                    # Drain a bounded amount so a hostile sink cannot stream an unbounded
                    # body into us; the content is a delivery ACK only and is discarded.
                    read = 0
                    async for chunk in response.aiter_raw():
                        read += len(chunk)
                        if read >= MAX_AUTHN_WEBHOOK_RESPONSE_BYTES:
                            break
                finally:
                    await response.aclose()
        except AuthenticatorDeliveryError:
            raise
        except Exception as exc:  # noqa: BLE001 — any transport failure is fail-closed.
            raise AuthenticatorDeliveryError("authenticator webhook transport failure") from exc
        if not 200 <= status < 300:
            raise AuthenticatorDeliveryError(
                f"authenticator webhook returned non-2xx status {status}"
            )

    async def _resolve_and_validate(self) -> str:
        """
        Resolve the host and validate EVERY resolved address; return one validated IP to
        pin the connection to. Raises ``AuthenticatorDeliveryError`` if resolution fails
        or any resolved address is in a rejected range.
        """
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(
                self._host, self._port, type=socket.SOCK_STREAM
            )
        except Exception as exc:  # noqa: BLE001 — a resolution failure is fail-closed.
            raise AuthenticatorDeliveryError("authenticator webhook host did not resolve") from exc
        if not infos:
            raise AuthenticatorDeliveryError("authenticator webhook host did not resolve")
        chosen: str | None = None
        for info in infos:
            sockaddr = info[4]
            ip_text = sockaddr[0]
            if _is_blocked_ip(ip_text):
                # Any single blocked answer refuses the whole delivery — a mixed
                # public+private answer set cannot smuggle us onto an internal address.
                raise AuthenticatorDeliveryError(
                    "authenticator webhook host resolves to a disallowed address"
                )
            if chosen is None:
                chosen = ip_text
        assert chosen is not None  # non-empty infos with no block means a value was set.
        return chosen

    @staticmethod
    def _serialize(notice: AuthenticatorNotice) -> bytes:
        """Deterministic JSON body for the signed push (independent of the lock hash)."""
        payload = {
            "tenant_id": notice.tenant_id,
            "challenge_id": notice.challenge_id,
            "agent_id": notice.agent_id,
            "alias": notice.alias,
            "risk_tier": notice.risk_tier.value,
            "expires_in_s": notice.expires_in_s,
            "otp": notice.otp,
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _is_blocked_ip(ip_text: str) -> bool:
    """
    True if ``ip_text`` names an address MCPIP must never dial for a webhook push.

    Unwraps IPv4-mapped IPv6 first, then rejects private / loopback / link-local (which
    covers the 169.254.169.254 cloud-metadata address) / reserved / multicast /
    unspecified ranges. An unparseable address is treated as blocked (fail-closed).
    """
    try:
        addr: Any = ipaddress.ip_address(ip_text)
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


__all__ = [
    "AuthenticatorDeliveryError",
    "SandboxRedisAuthenticatorChannel",
    "WebhookAuthenticatorChannel",
]
