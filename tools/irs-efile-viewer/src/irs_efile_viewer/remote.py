"""Fetch an e-file return from a URL without becoming an SSRF primitive.

The web app fetches URLs on a user's behalf, so a URL must not reach anything a user
could not reach themselves: only ``http``/``https``, no credentials in the URL, and every
address the host resolves to must be public (loopback, private, link-local — which covers
cloud metadata at 169.254.169.254 — reserved, multicast and unspecified are refused,
after unwrapping IPv4-mapped IPv6; an address that does not parse is refused). The
connection then goes to the address that was checked, so DNS cannot change its answer
in between, and every redirect hop is checked the same way. Bodies are capped.

When an HTTP(S) proxy is configured for the scheme (``HTTPS_PROXY``/``HTTP_PROXY``, minus
``NO_PROXY``), the request goes through it by host name, because that is what proxies
apply policy to. The address checks above still run on the locally resolved addresses;
the pinning is then the proxy's job.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
import urllib.request
from typing import Any
from urllib.parse import urljoin, urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}
_REDIRECTS = {301, 302, 303, 307, 308}
_USER_AGENT = "irs-efile-viewer/1.0 (+https://github.com/mcpip-security/mcpip)"


class FetchError(RuntimeError):
    """The URL was unreachable or returned something unusable."""


class URLRefused(FetchError):
    """The URL is not one this fetcher will request (scheme, credentials, address)."""


def is_blocked_ip(ip_text: str) -> bool:
    """True for addresses a server-side fetch must never dial (fail-closed)."""
    try:
        addr: Any = ipaddress.ip_address(ip_text.split("%", 1)[0])
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


def fetch(
    url: str,
    *,
    max_bytes: int,
    timeout: float = 20.0,
    deadline: float = 120.0,
    allow_private: bool = False,
    max_redirects: int = 5,
) -> tuple[bytes, str]:
    """GET ``url``; returns ``(body, final_url)``. Raises :class:`FetchError`.

    ``timeout`` bounds each network operation; ``deadline`` bounds the whole fetch, so a
    server that trickles bytes cannot hold the caller indefinitely.
    """
    current = url.strip()
    give_up = time.monotonic() + deadline
    for _ in range(max_redirects + 1):
        if time.monotonic() > give_up:
            raise FetchError(f"gave up after {deadline:.0f} seconds")
        parts = urlsplit(current)
        scheme = parts.scheme.lower()
        if scheme not in _DEFAULT_PORTS:
            raise URLRefused("only http:// and https:// URLs can be fetched")
        if parts.username or parts.password:
            raise URLRefused("URLs with credentials are not fetched")
        host = parts.hostname
        if not host:
            raise URLRefused("the URL has no host")
        try:
            port = parts.port or _DEFAULT_PORTS[scheme]
        except ValueError as exc:
            raise URLRefused(f"invalid port: {exc}") from exc
        address = _checked_address(host, port, allow_private)
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query

        conn, absolute = _connection(scheme, host, port, address, timeout)
        if absolute:  # plain HTTP through a proxy: the request line carries the full URL
            target = f"{scheme}://{parts.netloc}{target}"
        try:
            conn.request(
                "GET",
                target,
                headers={
                    "Host": parts.netloc.rsplit("@", 1)[-1],
                    "User-Agent": _USER_AGENT,
                    "Accept": "application/xml, text/xml;q=0.9, */*;q=0.1",
                },
            )
            response = conn.getresponse()
            if response.status in _REDIRECTS:
                location = response.getheader("Location")
                if not location:
                    raise FetchError(f"HTTP {response.status} without a Location header")
                current = urljoin(current, location)
                continue
            if response.status != 200:
                raise FetchError(f"HTTP {response.status} {response.reason}")
            chunks: list[bytes] = []
            size = 0
            while chunk := response.read(min(1 << 16, max_bytes + 1 - size)):
                chunks.append(chunk)
                size += len(chunk)
                if size > max_bytes:
                    raise FetchError(f"the file is larger than {_size(max_bytes)}")
                if time.monotonic() > give_up:
                    raise FetchError(f"gave up after {deadline:.0f} seconds")
            return b"".join(chunks), current
        except (OSError, http.client.HTTPException) as exc:
            raise FetchError(f"could not fetch {host}: {exc}") from exc
        finally:
            conn.close()
    raise FetchError("too many redirects")


def _size(n: int) -> str:
    return f"{n // (1024 * 1024)} MB" if n >= 1024 * 1024 else f"{n} bytes"


def _checked_address(host: str, port: int, allow_private: bool) -> str:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchError(f"cannot resolve {host}: {exc}") from exc
    addresses = list(dict.fromkeys(str(info[4][0]) for info in infos))
    if not addresses:
        raise FetchError(f"{host} has no addresses")
    if not allow_private:
        blocked = [a for a in addresses if is_blocked_ip(a)]
        if blocked:
            raise URLRefused(f"{host} resolves to a non-public address ({blocked[0]}); refused")
    return addresses[0]


def _connection(
    scheme: str, host: str, port: int, address: str, timeout: float
) -> tuple[http.client.HTTPConnection, bool]:
    """A connection for one hop, and whether the request line needs the absolute URL."""
    context = ssl.create_default_context() if scheme == "https" else None
    proxy = _proxy_for(scheme, host)
    if proxy is not None:
        proxy_host, proxy_port = proxy
        if scheme == "https":
            tunnel = http.client.HTTPSConnection(proxy_host, proxy_port, timeout=timeout, context=context)
            tunnel.set_tunnel(host, port)  # TLS inside the tunnel verifies ``host``
            return tunnel, False
        return http.client.HTTPConnection(proxy_host, proxy_port, timeout=timeout), True
    if scheme == "https":
        return _PinnedHTTPSConnection(host, port, address, timeout=timeout, context=context), False
    return _PinnedHTTPConnection(host, port, address, timeout=timeout), False


def _proxy_for(scheme: str, host: str) -> tuple[str, int] | None:
    proxies = urllib.request.getproxies()
    proxy = proxies.get(scheme)
    if not proxy or urllib.request.proxy_bypass(host):
        return None
    parts = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
    if parts.scheme != "http" or not parts.hostname:
        return None
    return parts.hostname, parts.port or 80


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, *, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, *, timeout: float, context: ssl.SSLContext | None) -> None:
        self._tls = context or ssl.create_default_context()
        super().__init__(host, port, timeout=timeout, context=self._tls)
        self._address = address

    def connect(self) -> None:
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._tls.wrap_socket(sock, server_hostname=self.host)
