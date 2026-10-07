"""The URL fetcher: what it refuses, and that it still works for what it allows."""

from __future__ import annotations

import http.server
import threading
import time
from collections.abc import Iterator

import pytest

from irs_efile_viewer.remote import FetchError, URLRefused, fetch, is_blocked_ip


@pytest.mark.parametrize(
    "ip, blocked",
    [
        ("127.0.0.1", True),
        ("10.1.2.3", True),
        ("172.16.0.1", True),
        ("192.168.1.1", True),
        ("169.254.169.254", True),  # cloud metadata
        ("0.0.0.0", True),
        ("224.0.0.1", True),
        ("::1", True),
        ("fc00::1", True),
        ("fe80::1%eth0", True),
        ("::ffff:127.0.0.1", True),  # IPv4-mapped loopback
        ("not-an-ip", True),  # fail closed
        ("8.8.8.8", False),
        ("2606:4700:4700::1111", False),
    ],
)
def test_is_blocked_ip(ip: str, blocked: bool) -> None:
    assert is_blocked_ip(ip) is blocked


@pytest.mark.parametrize(
    "url, message",
    [
        ("file:///etc/passwd", "only http"),
        ("ftp://example.com/x.xml", "only http"),
        ("gopher://127.0.0.1:6379/_x", "only http"),
        ("https://user:pw@example.com/x.xml", "credentials"),
        ("http:///x.xml", "no host"),
        ("http://127.0.0.1/x.xml", "non-public"),
        ("http://localhost:6379/", "non-public"),
        ("http://169.254.169.254/latest/meta-data/", "non-public"),
        ("http://[::1]/x.xml", "non-public"),
    ],
)
def test_refuses(url: str, message: str) -> None:
    with pytest.raises(URLRefused, match=message):
        fetch(url, max_bytes=1000)


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if self.path == "/return.xml":
            body = b"<Return/>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/moved":
            self.send_response(302)
            self.send_header("Location", "/return.xml")
            self.end_headers()
        elif self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
        elif self.path == "/big":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"x" * 5000)
        elif self.path == "/slow":
            self.send_response(200)
            self.end_headers()
            for _ in range(30):
                self.wfile.write(b"x")
                self.wfile.flush()
                time.sleep(0.1)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def test_fetches_and_follows_redirects_when_private_is_allowed(server: str) -> None:
    body, final = fetch(f"{server}/moved", max_bytes=1000, allow_private=True)
    assert body == b"<Return/>" and final == f"{server}/return.xml"


def test_private_server_is_refused_by_default(server: str) -> None:
    with pytest.raises(URLRefused):
        fetch(f"{server}/return.xml", max_bytes=1000)


def test_size_cap(server: str) -> None:
    with pytest.raises(FetchError, match="larger than"):
        fetch(f"{server}/big", max_bytes=1000, allow_private=True)


def test_total_deadline(server: str) -> None:
    """Each byte arrives within the per-read timeout; the whole fetch still gives up."""
    with pytest.raises(FetchError, match="gave up after"):
        fetch(f"{server}/slow", max_bytes=1000, allow_private=True, timeout=5, deadline=0.5)


def test_redirect_loop(server: str) -> None:
    with pytest.raises(FetchError, match="too many redirects"):
        fetch(f"{server}/loop", max_bytes=1000, allow_private=True)


def test_http_errors(server: str) -> None:
    with pytest.raises(FetchError, match="HTTP 404"):
        fetch(f"{server}/missing", max_bytes=1000, allow_private=True)
