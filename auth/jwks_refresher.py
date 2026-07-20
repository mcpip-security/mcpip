"""
MCPIP V2 — Auth: JWKS refresh helper (off-hot-path verification-key-set rotation).

    ◐ Auth: "The key set that verifies identity may rotate — but it never goes empty."

``JWKSKeyProvider`` (``auth/token_resolver.py``) is deliberately NOT network-fetching:
it is handed a JWKS document at construction and selects the verification key by the
token header's ``kid``, so the per-request auth path never takes a synchronous JWKS
round-trip (a fetch on the hot path would be a fail-closed single point of failure).
This module completes that provider with the OTHER half — the OFF-hot-path refresh that
pulls an updated JWKS document from the IdP / workload-identity STS and atomically swaps
the live key set — WITHOUT ever weakening the identity guarantees.

Design (fail-closed, additive — nothing about the existing provider changes):

  * ``JWKSRefresher`` is itself a ``KeyProvider`` that WRAPS a live ``JWKSKeyProvider``.
    ``resolve`` simply delegates to the current inner provider, so it drops straight into
    a ``TokenResolver`` in place of a bare ``JWKSKeyProvider``. The alg allow-list in
    ``TokenResolver`` remains the gate — a rotated key set can add/replace keys but never
    a permitted algorithm, so refresh can never widen ``{EdDSA, RS256}``.

  * The key set is SEEDED at construction with an already-valid, NON-EMPTY
    ``JWKSKeyProvider`` (the boot-seed policy — see ``bootstrap``), so the provider is
    never empty from birth.

  * ``refresh`` fetches a fresh document over an SSRF-guarded, hermetic HTTPS client
    (the SAME guard + ``trust_env=False`` discipline as the authenticator webhook push,
    ``services/authn_channel.py``), builds a NEW ``JWKSKeyProvider`` from it — which
    re-runs the authoritative non-empty / well-formed / no-private-material / no-duplicate-
    ``kid`` validation — and ONLY THEN rebinds the single ``self._current`` reference. The
    build happens BEFORE the swap, so any failure (transport, SSRF rejection, non-2xx,
    oversized body, empty / malformed / private-key-bearing document) raises and the swap
    never occurs: **the current key set is retained unchanged, never silently emptied.**
    An unknown ``kid`` after a failed refresh therefore still fails CLOSED against the last
    good set (``JWKSKeyProvider.resolve`` raises ``TokenError``) — exactly the pre-refresh
    behavior, never an open pass.

Absent config (no JWKS URL wired) means no ``JWKSRefresher`` is constructed and the
``StaticPEMKeyProvider`` / single-IdP path is entirely unchanged — this is strictly
opt-in for a rotating-STS deployment.
"""

from __future__ import annotations

import asyncio
import json
import socket
from typing import Any, Final
from urllib.parse import urlsplit

import httpx

from interfaces import MAX_JWKS_DOC_BYTES, MAX_JWKS_KEYS
from auth.token_resolver import JWKSKeyProvider, KeyProvider, TokenError

# Default per-refresh wall-clock ceiling (connect + read). Off the hot path, so a modest
# fixed default is fine; an operator may widen/narrow it per deployment. It is NOT clamped
# to an interfaces band because — unlike the step-up webhook — a slow refresh never blocks
# an authorization decision (the current key set keeps serving), so the only failure mode is
# "this refresh attempt gives up and the last good set is retained".
_DEFAULT_REFRESH_TIMEOUT_S: Final[float] = 5.0


class JWKSRefreshError(Exception):
    """
    A refresh attempt could not complete; the CURRENT verification key set is retained.

    Raised by ``JWKSRefresher.refresh`` on any failure (SSRF rejection, transport error,
    non-2xx, oversized / malformed / empty / private-key-bearing document). It is an
    operator-facing signal only — the caller (a boot step or a background refresh loop)
    logs / alerts on it and keeps serving the last good set. It carries a short reason
    only, never the URL body or any key material.
    """


class JWKSRefresher(KeyProvider):
    """
    A ``KeyProvider`` that wraps a live ``JWKSKeyProvider`` and can atomically REPLACE its
    key set from a remote JWKS endpoint — off the per-request hot path.

    Construct via :meth:`bootstrap` (which performs the initial fetch and REFUSES to
    produce a refresher without a valid, non-empty seed), or directly with an already-built
    ``seed`` provider (e.g. one loaded from a mounted JWKS file). Either way the provider is
    guaranteed non-empty from birth, and every subsequent :meth:`refresh` only ever replaces
    it with ANOTHER validated non-empty set — so the verification key set can never go empty.
    """

    def __init__(
        self,
        url: str,
        *,
        seed: JWKSKeyProvider,
        timeout_s: float = _DEFAULT_REFRESH_TIMEOUT_S,
    ) -> None:
        host, port = _validate_https_url(url)
        if timeout_s <= 0:
            raise ValueError("JWKS refresh timeout must be positive")
        self._url = url
        self._host: str = host
        self._port: int = port
        self._timeout_s = timeout_s
        # The single live reference. Rebinding it is the atomic swap (one attribute store
        # under the GIL); a concurrent ``resolve`` sees either the old or the new provider,
        # never a half-built map. Never assigned None / an empty provider.
        self._current: JWKSKeyProvider = seed

    @classmethod
    async def bootstrap(
        cls,
        url: str,
        *,
        timeout_s: float = _DEFAULT_REFRESH_TIMEOUT_S,
    ) -> "JWKSRefresher":
        """
        Fetch the INITIAL JWKS document and return a refresher seeded with it.

        This is the boot-seed policy in one call: the initial fetch MUST succeed and yield
        a valid, non-empty document, or ``bootstrap`` raises ``JWKSRefreshError`` and NO
        refresher (hence no empty key set) is ever produced. A deployment that wires a
        rotating STS therefore fails its boot CLOSED if the STS is unreachable at startup,
        rather than coming up with an empty verifier — the operator seeds from a mounted
        document (construct directly) if a startup fetch is undesirable.
        """
        host, port = _validate_https_url(url)
        if timeout_s <= 0:
            raise ValueError("JWKS refresh timeout must be positive")
        seed = await _fetch_jwks_provider(url, host, port, timeout_s)
        return cls(url, seed=seed, timeout_s=timeout_s)

    def resolve(self, header: dict[str, Any]) -> bytes | str:
        """Delegate to the current key set — the only per-request (hot-path) operation."""
        return self._current.resolve(header)

    async def refresh(self) -> None:
        """
        Fetch a fresh JWKS document and atomically swap in the new key set.

        Builds and fully validates the replacement provider BEFORE rebinding, so any failure
        leaves the current set untouched. Raises ``JWKSRefreshError`` on failure (the caller
        keeps serving the last good set); returns None on success.
        """
        provider = await _fetch_jwks_provider(
            self._url, self._host, self._port, self._timeout_s
        )
        # Atomic swap: a single attribute rebind. Only reached when the fetch + full
        # JWKSKeyProvider validation succeeded, so the set is never emptied by a bad refresh.
        self._current = provider


# ---------------------------------------------------------------------------
# SSRF-guarded, hermetic fetch — mirrors WebhookAuthenticatorChannel.deliver().
# ---------------------------------------------------------------------------


def _validate_https_url(url: str) -> tuple[str, int]:
    """Parse + require https with a host; return (host, port). Fail closed on anything else."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise ValueError("JWKS URL must be https")
    if not parts.hostname:
        raise ValueError("JWKS URL must have a host")
    return parts.hostname, (parts.port or 443)


async def _fetch_jwks_provider(
    url: str, host: str, port: int, timeout_s: float
) -> JWKSKeyProvider:
    """
    Fetch and parse a JWKS document, returning a fully-validated ``JWKSKeyProvider``.

    SSRF guard (all enforced per fetch, so a rotated DNS record cannot bypass it): https
    only; resolve the host and reject if ANY resolved address is private / loopback /
    link-local (169.254.169.254 metadata) / reserved / multicast / unspecified; PIN the
    connection to the validated IP (original host drives SNI + cert verification) to defeat
    DNS-rebinding; do not follow redirects; bound the timeout; bound the response read;
    require a 2xx. The client is HERMETIC (``trust_env=False`` + ``proxy=None``) so it never
    honors ambient ``HTTPS_PROXY`` / ``SSL_CERT_FILE`` — a verification-key fetch must not be
    reroutable through an unvalidated intermediary (that would void the IP pin and the TLS
    pin and let a MITM swap the key set). Any failure raises ``JWKSRefreshError``.
    """
    validated_ip = await _resolve_and_validate(host, port)
    # Pin the connection to the validated IP; keep the original hostname for SNI + cert
    # verification via the ``sni_hostname`` request extension, so DNS is not re-resolved.
    ip_url = httpx.URL(url).copy_with(host=validated_ip)
    authority = host if port == 443 else f"{host}:{port}"
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_s),
            follow_redirects=False,
            verify=True,
            # Hermetic by construction (see docstring): a fetch that hand-rolls SSRF
            # validation + IP-pinning must NOT also honor ambient proxy / CA env, or the
            # pin + TLS-verify are silently voided and the key set becomes MITM-swappable.
            trust_env=False,
            proxy=None,
        ) as client:
            request = client.build_request(
                "GET",
                ip_url,
                # ``Accept-Encoding: identity`` disables response compression so the
                # RAW stream we read (``aiter_raw``, which preserves the byte-size cap and
                # never auto-decodes) IS the JSON — otherwise a gzip/br-encoding JWKS
                # endpoint (common behind a CDN) would hand us compressed bytes that
                # ``json.loads`` rejects, breaking rotation (fail-closed, but a real
                # interop break). We accept the marginal bandwidth cost for a small doc.
                headers={
                    "Host": authority,
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
                extensions={"sni_hostname": host},
            )
            response = await client.send(request, stream=True)
            try:
                status = response.status_code
                chunks: list[bytes] = []
                read = 0
                async for chunk in response.aiter_raw():
                    read += len(chunk)
                    if read > MAX_JWKS_DOC_BYTES:
                        raise JWKSRefreshError("JWKS document exceeded size cap")
                    chunks.append(chunk)
            finally:
                await response.aclose()
    except JWKSRefreshError:
        raise
    except Exception as exc:  # noqa: BLE001 — any transport failure is fail-closed.
        raise JWKSRefreshError("JWKS fetch transport failure") from exc
    if not 200 <= status < 300:
        raise JWKSRefreshError(f"JWKS endpoint returned non-2xx status {status}")

    body = b"".join(chunks)
    try:
        doc: Any = json.loads(body)
    except ValueError as exc:
        raise JWKSRefreshError("JWKS document is not valid JSON") from exc
    if not isinstance(doc, dict):
        raise JWKSRefreshError("JWKS document must be a JSON object")
    # Enforce the key-count ceiling BEFORE constructing the provider — the provider does not
    # bound cardinality, so this is where an oversized document is refused (fail closed).
    keys = doc.get("keys")
    if isinstance(keys, list) and len(keys) > MAX_JWKS_KEYS:
        raise JWKSRefreshError("JWKS document carries too many keys")
    try:
        # JWKSKeyProvider is the authoritative validator: non-empty 'keys', every entry an
        # object with a unique non-empty 'kid', no private material, supported kty only. A
        # violation raises TokenError -> we surface it as a fail-closed refresh error, so the
        # caller retains the last good set rather than swapping in a degenerate one.
        return JWKSKeyProvider(doc)
    except TokenError as exc:
        raise JWKSRefreshError(f"fetched JWKS document is invalid: {exc}") from exc


async def _resolve_and_validate(host: str, port: int) -> str:
    """
    Resolve the host and validate EVERY resolved address; return one validated IP to pin the
    connection to. Raises ``JWKSRefreshError`` if resolution fails or any address is blocked.
    """
    # Deferred import: reuse the SSRF address guard from the authenticator webhook channel
    # WITHOUT pulling the `services` package (which imports `auth`) at module-import time,
    # which would create an auth <-> services import cycle. By call time both packages are
    # fully initialized. (Same cross-module private-helper reuse pattern as
    # services.quarantine._glob_escape shared by the relation/revocation stores.)
    from services.authn_channel import _is_blocked_ip

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception as exc:  # noqa: BLE001 — a resolution failure is fail-closed.
        raise JWKSRefreshError("JWKS host did not resolve") from exc
    if not infos:
        raise JWKSRefreshError("JWKS host did not resolve")
    chosen: str | None = None
    for info in infos:
        ip_text = info[4][0]
        if _is_blocked_ip(ip_text):
            # Any single blocked answer refuses the whole fetch — a mixed public+private
            # answer set cannot smuggle us onto an internal address.
            raise JWKSRefreshError("JWKS host resolves to a disallowed address")
        if chosen is None:
            chosen = ip_text
    assert chosen is not None  # non-empty infos with no block means a value was set.
    return chosen


__all__ = [
    "JWKSRefreshError",
    "JWKSRefresher",
]
