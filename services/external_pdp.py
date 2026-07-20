"""
MCPIP V2 — Service: the outbound COAZ PEP mode (external AuthZEN PDP consult).

    ◐ "As a PEP, MCPIP asks one more question — and only ever hears 'no'."

When MCPIP is configured as a COAZ Policy Enforcement Point it can consult an EXTERNAL
OpenID-AuthZEN Policy Decision Point as one additional DENY-ONLY term in the
community-gate deny chain (pipeline step 4c′). This module ships that as a REAL provider
(not a stub) that is INERT unless an operator opts in via ``MCPIP_EXTERNAL_PDP_ENABLED``
+ ``MCPIP_EXTERNAL_PDP_URL``:

  * ``ExternalPdpGateProvider`` implements :class:`CommunityGateProvider`. It POSTs the
    topology-free whitelisted ``CommunityGateContext`` (opaque alias + coarse transport
    class + risk tier + classification — NO target, NO secret, NO identity, NO arguments)
    to the external PDP and returns ``GateDecision(outcome='deny')`` iff the PDP replies
    ``{"decision": false}``. Any other reply (``{"decision": true}``) is ``continue``.
  * It is MONOTONIC: it can only ever ADD a deny — it never turns a DENY into an ALLOW.
  * It FAILS CLOSED to ``deny`` on ANY error (transport, non-2xx, SSRF-blocked host,
    parse) — availability of authorization never depends on the external PDP being
    reachable-and-permissive; an unreachable PDP denies, it never opens.

The dial-out reuses the same hermetic + SSRF-guarded discipline as the authenticator
webhook and the JWKS refresher (it lives in ``services/``, where ``httpx`` is permitted —
NEVER in ``bridge/connectors/``):
  1. scheme MUST be https;
  2. the host is resolved and EVERY resolved address is rejected if private / loopback /
     link-local (169.254.169.254 cloud metadata) / reserved / multicast / unspecified;
  3. the connection is PINNED to the validated IP (SNI/cert = original host) to defeat
     DNS-rebinding;
  4. redirects are NOT followed; connect+read are bounded; the response read is bounded;
  5. the client is HERMETIC (``trust_env=False``, ``proxy=None``) so no ambient
     HTTPS_PROXY / SSL_CERT_FILE can reroute or MITM the consult.

Crucially, composing this provider at the Components level (via
``services.community_gate.DenyOnlyGateChain``) does NOT call
``register_community_gate_engine`` — so ``community_gate_engine_registered()`` stays False
and the deferred CEL gate-manifest approval seam is NOT falsely unlocked. The external PDP
is a PEP consult, not the CEL engine + static prover that seam gates on.
"""

from __future__ import annotations

import asyncio
import json
import socket
from typing import Any, Final
from urllib.parse import urlsplit

import httpx

from interfaces import (
    CommunityGateContext,
    CommunityGateProvider,
    GateDecision,
    MAX_AUTHN_WEBHOOK_RESPONSE_BYTES,
    MAX_AUTHN_WEBHOOK_TIMEOUT_S,
    MIN_AUTHN_WEBHOOK_TIMEOUT_S,
)

# Reuse the authenticator-webhook SSRF primitive (resolve + reject internal ranges). A
# deferred/module-level import is safe here (``services`` already imports ``services``).
from services.authn_channel import _is_blocked_ip

# The AuthZEN action verb MCPIP asks the external PDP to decide on. Coarse + fixed.
_PEP_ACTION: Final[str] = "invoke"


class ExternalPdpGateProvider(CommunityGateProvider):
    """
    A DENY-ONLY community-gate provider that consults an external AuthZEN PDP.

    ``evaluate`` POSTs an AuthZEN-shaped decision request built ONLY from the whitelisted,
    topology-free ``CommunityGateContext`` and returns ``deny`` iff the PDP explicitly
    replies ``{"decision": false}``; a permit (or a missing/true decision) is ``continue``.
    Every failure mode fails closed to ``deny`` (monotonic — only ever ADDS a deny).
    """

    def __init__(self, *, url: str, timeout_s: float = MAX_AUTHN_WEBHOOK_TIMEOUT_S) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise ValueError("external PDP URL must be https")
        if not parts.hostname:
            raise ValueError("external PDP URL must have a host")
        self._url = url
        self._host: str = parts.hostname
        self._port: int = parts.port or 443
        # Clamp the timeout into the shared interfaces safety band (no duplicated limits).
        self._timeout_s = max(
            MIN_AUTHN_WEBHOOK_TIMEOUT_S, min(MAX_AUTHN_WEBHOOK_TIMEOUT_S, timeout_s)
        )

    async def evaluate(self, ctx: CommunityGateContext) -> GateDecision:
        """Consult the external PDP; ``deny`` on an explicit false OR any error."""
        try:
            decision = await self._consult(ctx)
        except Exception:  # noqa: BLE001 — ANY failure fails closed to deny (monotonic).
            return GateDecision(
                outcome="deny", detail="external PDP consult failed (fail-closed)"
            )
        if decision is False:
            return GateDecision(outcome="deny", detail="external PDP denied")
        return GateDecision(outcome="continue")

    async def _consult(self, ctx: CommunityGateContext) -> Any:
        """
        POST the whitelisted context to the PDP and return the parsed ``decision`` value.

        Returns the raw ``decision`` field (expected bool) or raises on any transport /
        guard / parse failure (the caller maps a raise → fail-closed deny).
        """
        validated_ip = await self._resolve_and_validate()
        body = self._serialize(ctx)
        authority = self._host if self._port == 443 else f"{self._host}:{self._port}"
        headers = {"Content-Type": "application/json", "Accept": "application/json", "Host": authority}
        # Pin the connection to the validated IP; original hostname drives SNI + cert.
        ip_url = httpx.URL(self._url).copy_with(host=validated_ip)
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout_s),
            follow_redirects=False,
            verify=True,
            # Hermetic: a guard that hand-rolls IP-pinning must NOT honor ambient env, or
            # HTTPS_PROXY would reroute the consult through an unvalidated intermediary and
            # SSL_CERT_FILE could trust a MITM CA (voiding the pin + TLS verification).
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
                chunks: list[bytes] = []
                read = 0
                async for chunk in response.aiter_raw():
                    read += len(chunk)
                    chunks.append(chunk)
                    if read >= MAX_AUTHN_WEBHOOK_RESPONSE_BYTES:
                        break
            finally:
                await response.aclose()
        if not 200 <= status < 300:
            raise RuntimeError(f"external PDP returned non-2xx status {status}")
        document = json.loads(b"".join(chunks)[:MAX_AUTHN_WEBHOOK_RESPONSE_BYTES])
        if not isinstance(document, dict):
            raise ValueError("external PDP response was not a JSON object")
        return document.get("decision")

    async def _resolve_and_validate(self) -> str:
        """Resolve the host, reject every internal address, return one validated IP."""
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(self._host, self._port, type=socket.SOCK_STREAM)
        if not infos:
            raise RuntimeError("external PDP host did not resolve")
        chosen: str | None = None
        for info in infos:
            ip_text = info[4][0]
            if _is_blocked_ip(ip_text):
                # Any single blocked answer refuses the whole consult (mixed-answer SSRF).
                raise RuntimeError("external PDP host resolves to a disallowed address")
            if chosen is None:
                chosen = ip_text
        assert chosen is not None
        return chosen

    @staticmethod
    def _serialize(ctx: CommunityGateContext) -> bytes:
        """
        AuthZEN-shaped request body from ONLY the topology-free whitelist.

        The alias is the opaque resource id; transport class / risk tier / classification
        ride as coarse advisory properties. No target, secret, identity, or argument is
        ever placed here — the same opacity the whole community-gate seam guarantees.
        """
        payload = {
            "resource": {
                "type": "mcpip.tool",
                "id": ctx.alias,
                "properties": {
                    "transport_class": ctx.transport_class,
                    "risk_tier": ctx.risk_tier.value,
                    "classification": ctx.classification.value,
                },
            },
            "action": {"name": _PEP_ACTION},
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


__all__ = ["ExternalPdpGateProvider"]
