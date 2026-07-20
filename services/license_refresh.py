"""
MCPIP V2 — Service: off-hot-path license REFRESH (opt-in, fail-open, verify-against-root).

    ◐ "The entitlement may be pulled — but only the vendor's OWN root can grant it."

The signed entitlement :class:`~core.licensing.License` gates PROCESS BOOT only — it is
NEVER consulted by the authorization pipeline (``core/licensing.py``). This module adds
the OTHER half of the offline-signed-license story: an OPTIONAL, off-the-hot-path pull
that fetches a CANDIDATE signed license from ``MCPIP_LICENSE_REFRESH_URL``, verifies it
against the EXISTING license-root Ed25519 public key with the boot-identical checks, and
atomically swaps in ONLY a fully-valid, STRICTLY-NEWER license.

Design (fail-open, additive — nothing about the boot gate changes):

  * :class:`LicenseRefresher` holds a getter for the CURRENT license and a setter callback
    that performs the atomic swap (one attribute store under the GIL — the
    ``JWKSRefresher._current`` discipline). :meth:`refresh_once` NEVER raises into serving
    and NEVER sets the license to ``None``: ANY failure (transport, SSRF rejection, non-2xx,
    oversized, malformed, bad/forged/wrong-root/expired signature, not-newer) is caught,
    counted to ``mcpip_license_refresh_total{event=…}``, and the last-good license is
    RETAINED. It never fails OPEN to an unlicensed state and never bricks a running gateway.

  * The candidate is verified with :func:`core.licensing.verify_license_bytes` — the SAME
    authoritative validator the boot gate uses (schema / license-root signature / closed
    tier / validity window). NO new trust root, NO widened verification, NO unsigned/forged
    acceptance. The public key is the EXISTING license-root PEM the boot gate loaded.

  * The refresh request body reports usage in the SAME round-trip: when a T1 beacon payload
    provider is wired it POSTs the beacon's CLOSED privacy-safe payload (install-id, license
    id/tier, version, an integer governed-agent cardinality, coarse allow/deny/staged totals,
    uptime, timestamp) — NEVER a tenant/agent/alias/target/capability/correlation/secret/
    argument. Without a provider it POSTs a MINIMAL identity subset of that same closed set
    ({license_id, version} — install-id only if already minted by the T1 beacon; this module
    NEVER mints one). Beacon-without-refresh and refresh-without-beacon both work.

  * The fetch reuses the authenticator-webhook / JWKS-refresher HERMETIC, SSRF-guarded,
    IP-pinned client discipline VERBATIM: https-only, resolve-and-reject every private /
    loopback / link-local / reserved IP, connection PINNED to the validated IP (original host
    drives SNI + cert), ``follow_redirects=False``, bounded timeout, bounded response read
    (``MAX_LICENSE_DOC_BYTES``), ``trust_env=False`` + ``proxy=None`` — a license fetch must
    not be reroutable through an unvalidated intermediary or a MITM could swap the entitlement.

Absent config (``MCPIP_LICENSE_REFRESH_URL`` unset) means no refresher is constructed and
the offline-signed-license behavior is byte-identical to today — strictly opt-in.
"""

from __future__ import annotations

import asyncio
import json
import socket
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Final, Optional
from urllib.parse import urlsplit

import httpx

from core.licensing import License, is_newer_license, verify_license_bytes
from core.metrics import LICENSE_REFRESH
from core.version import get_version
from interfaces import MAX_LICENSE_DOC_BYTES

# Reuse the authenticator-webhook SSRF primitive (resolve + reject internal ranges). A
# module-level import is safe here — ``services`` already imports ``services`` and
# ``services.authn_channel`` pulls in no ``auth``/``app`` code, so there is no cycle.
from services.authn_channel import _is_blocked_ip

# Default per-refresh wall-clock ceiling (connect + read). Off the hot path, so a modest
# fixed default is fine; a slow refresh never blocks an authorization (the current license
# keeps gating boot / serving operator reads), the only failure mode is "this attempt gives
# up and the last-good license is retained".
_DEFAULT_REFRESH_TIMEOUT_S: Final[float] = 10.0

# Floor on the background pull cadence so a misconfiguration cannot turn the best-effort
# daemon into a self-inflicted request storm against the vendor receiver.
_MIN_REFRESH_INTERVAL_S: Final[float] = 60.0


class LicenseRefreshError(Exception):
    """
    A refresh attempt could not complete; the CURRENT license is RETAINED.

    Raised INTERNALLY by the transport step on any fetch failure (SSRF rejection,
    transport error, non-2xx, oversized body). :meth:`LicenseRefresher.refresh_once`
    catches it (and every other exception) so it NEVER propagates into serving — the
    caller (the background daemon) keeps the last-good license. It carries a short reason
    only, never the URL body or any license/key material.
    """


class LicenseRefresher:
    """
    Pull + verify + atomically swap a signed license — off the per-request hot path.

    Constructed ONLY when ``MCPIP_LICENSE_REFRESH_URL`` is set AND the process booted with
    a license AND the license-root public key path is known (the composition root enforces
    that). Every :meth:`refresh_once` either swaps in a strictly-newer fully-valid license
    or RETAINS the current one — it can never empty, downgrade, or forge the entitlement.
    """

    def __init__(
        self,
        *,
        url: str,
        public_key_pem: bytes,
        current_getter: Callable[[], Optional[License]],
        license_setter: Callable[[License], None],
        interval_s: float,
        payload_provider: Optional[Callable[[], Awaitable[dict[str, Any]]]] = None,
        install_id: Optional[str] = None,
        timeout_s: float = _DEFAULT_REFRESH_TIMEOUT_S,
    ) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise ValueError("license refresh URL must be https")
        if not parts.hostname:
            raise ValueError("license refresh URL must have a host")
        if not public_key_pem:
            raise ValueError("license refresh needs the license-root public key")
        if timeout_s <= 0:
            raise ValueError("license refresh timeout must be positive")
        self._url = url
        self._host: str = parts.hostname
        self._port: int = parts.port or 443
        self._public_key_pem = public_key_pem
        self._current_getter = current_getter
        self._license_setter = license_setter
        # Floor the cadence (no ceiling: a rare pull never harms serving).
        self._interval_s = max(_MIN_REFRESH_INTERVAL_S, interval_s)
        self._payload_provider = payload_provider
        self._install_id = install_id
        self._timeout_s = timeout_s
        # Honest, never-fabricated status for the additive /v1/license surface. Set ONLY on
        # a real swap; None until the running license has actually been refreshed.
        self.last_refreshed_at: Optional[str] = None

    @property
    def interval_s(self) -> float:
        """The floored background pull cadence (seconds)."""
        return self._interval_s

    async def _build_body(self) -> bytes:
        """
        Build the refresh request body from the CLOSED privacy-safe field set.

        When a T1 beacon payload provider is wired, the body IS that closed beacon payload
        (a single authenticated round-trip both reports usage and pulls entitlement).
        Otherwise it is the MINIMAL identity subset ({license_id, version}, plus install_id
        ONLY if the beacon already minted one) — a strict SUBSET of the same closed set,
        never any tenant / agent / alias / target / argument / secret.
        """
        if self._payload_provider is not None:
            payload = await self._payload_provider()
        else:
            current = self._current_getter()
            payload = {
                "license_id": current.license_id if current is not None else None,
                "version": get_version(),
            }
            if self._install_id is not None:
                payload["install_id"] = self._install_id
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    async def refresh_once(self) -> None:
        """
        Fetch one candidate license and atomically swap it in ONLY if valid + strictly newer.

        NEVER raises into serving and NEVER sets the license to ``None``. Outcomes (each
        RETAINS the last-good license unless it is a genuine, strictly-newer, fully-valid
        swap):

          * transport/SSRF/non-2xx/oversized fetch failure -> ``transport_error``;
          * bad/forged/wrong-root/expired/malformed candidate -> ``verify_failed``;
          * valid but not strictly newer -> ``not_newer``;
          * valid + newer but a DIFFERENT customer/license_id -> ``identity_mismatch``
            (a refresh is a renewal of the SAME entitlement, never a cross-customer or
            cross-license swap — the tenant + license separation boundary);
          * valid AND strictly newer AND same customer+license_id -> ``refreshed``.
        """
        try:
            body = await self._build_body()
            raw = await self._fetch(body)
        except Exception:  # noqa: BLE001 — a refresh fetch can NEVER disturb serving.
            LICENSE_REFRESH.labels("transport_error").inc()
            return

        try:
            candidate = verify_license_bytes(raw, self._public_key_pem)
        except Exception:  # noqa: BLE001 — any content problem (LicenseError etc.): retain.
            LICENSE_REFRESH.labels("verify_failed").inc()
            return

        current = self._current_getter()
        # Only ever swap in a STRICTLY-NEWER license. A None current cannot happen (the
        # refresher is built only with a boot license) but is handled fail-safe: with
        # nothing to compare against we do NOT swap, so a refresh can never invent an
        # entitlement out of the unlicensed state either.
        if current is None or not is_newer_license(candidate, current):
            LICENSE_REFRESH.labels("not_newer").inc()
            return

        # LICENSE-IDENTITY BINDING (tenant + license separation). A refresh is a RENEWAL
        # of the SAME entitlement — never the adoption of a DIFFERENT customer's or a
        # different license's document. The single license-root keypair signs EVERY
        # customer, so "verify against the root" alone would accept a newer, validly-signed
        # license for another customer / license_id (a leaked or other-SKU document, or a
        # stale cross-tenant cached response from a shared license CDN) and silently
        # re-attest this deployment under the WRONG customer + a widened tier. Require the
        # candidate to carry the SAME license_id AND customer as the running license, so a
        # refresh can only ever move this one entitlement forward in time. On mismatch we
        # RETAIN the last-good license (never widen, never brick) and count it distinctly.
        if (
            candidate.license_id != current.license_id
            or candidate.customer != current.customer
        ):
            LICENSE_REFRESH.labels("identity_mismatch").inc()
            return

        # Atomic swap: a single attribute store via the setter (under the GIL) — a
        # concurrent /v1/license read sees the old-or-new License, never a half state.
        self._license_setter(candidate)
        self.last_refreshed_at = datetime.now(timezone.utc).isoformat()
        LICENSE_REFRESH.labels("refreshed").inc()

    # ------------------------------------------------------------------
    # SSRF-guarded, hermetic fetch — mirrors jwks_refresher._fetch_jwks_provider.
    # ------------------------------------------------------------------

    async def _fetch(self, body: bytes) -> bytes:
        """
        POST the report body, return the raw candidate license bytes. Fail-closed.

        SSRF guard (all per-fetch, so a rotated DNS record cannot bypass it): https only;
        resolve + reject any private / loopback / link-local (169.254.169.254 metadata) /
        reserved / multicast / unspecified address; PIN the connection to the validated IP
        (original host drives SNI + cert) to defeat DNS-rebinding; no redirects; bounded
        timeout; bounded response read (``MAX_LICENSE_DOC_BYTES``); require 2xx. The client
        is HERMETIC (``trust_env=False`` + ``proxy=None``) so no ambient HTTPS_PROXY /
        SSL_CERT_FILE / SSLKEYLOGFILE can reroute or MITM the pull. Raises
        :class:`LicenseRefreshError` on any failure.
        """
        validated_ip = await self._resolve_and_validate()
        ip_url = httpx.URL(self._url).copy_with(host=validated_ip)
        authority = self._host if self._port == 443 else f"{self._host}:{self._port}"
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout_s),
                follow_redirects=False,
                verify=True,
                # Hermetic by construction (see docstring): a fetch that hand-rolls SSRF
                # validation + IP-pinning must NOT also honor ambient proxy / CA env, or the
                # pin + TLS-verify are silently voided and the entitlement becomes
                # MITM-swappable.
                trust_env=False,
                proxy=None,
            ) as client:
                request = client.build_request(
                    "POST",
                    ip_url,
                    content=body,
                    # ``Accept-Encoding: identity`` disables response compression so the RAW
                    # stream we read (``aiter_raw``, which preserves the byte-size cap and
                    # never auto-decodes) IS the JSON license — otherwise a gzip/br-encoding
                    # receiver behind a CDN would hand us compressed bytes that
                    # verify_license_bytes rejects.
                    headers={
                        "Host": authority,
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                    },
                    extensions={"sni_hostname": self._host},
                )
                response = await client.send(request, stream=True)
                try:
                    status = response.status_code
                    chunks: list[bytes] = []
                    read = 0
                    async for chunk in response.aiter_raw():
                        read += len(chunk)
                        if read > MAX_LICENSE_DOC_BYTES:
                            raise LicenseRefreshError("license document exceeded size cap")
                        chunks.append(chunk)
                finally:
                    await response.aclose()
        except LicenseRefreshError:
            raise
        except Exception as exc:  # noqa: BLE001 — any transport failure is fail-closed.
            raise LicenseRefreshError("license refresh transport failure") from exc
        if not 200 <= status < 300:
            raise LicenseRefreshError(f"license receiver returned non-2xx status {status}")
        return b"".join(chunks)

    async def _resolve_and_validate(self) -> str:
        """
        Resolve the host and validate EVERY resolved address; return one validated IP to pin
        the connection to. Raises :class:`LicenseRefreshError` if resolution fails or any
        resolved address is in a rejected range (a mixed public+private answer set cannot
        smuggle us onto an internal address).
        """
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(
                self._host, self._port, type=socket.SOCK_STREAM
            )
        except Exception as exc:  # noqa: BLE001 — a resolution failure is fail-closed.
            raise LicenseRefreshError("license refresh host did not resolve") from exc
        if not infos:
            raise LicenseRefreshError("license refresh host did not resolve")
        chosen: str | None = None
        for info in infos:
            ip_text = info[4][0]
            if _is_blocked_ip(ip_text):
                raise LicenseRefreshError(
                    "license refresh host resolves to a disallowed address"
                )
            if chosen is None:
                chosen = ip_text
        assert chosen is not None
        return chosen


__all__ = [
    "LicenseRefreshError",
    "LicenseRefresher",
]
