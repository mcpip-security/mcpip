"""The web viewer, driven over HTTP: upload, URL, browse, refuse, expire."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
try:
    import python_multipart  # noqa: F401
except ImportError:
    pytest.importorskip("multipart")

from fastapi.testclient import TestClient  # noqa: E402
from irs_efile_helpers import efile_xml  # noqa: E402

from irs_efile_viewer.mef import MefStore  # noqa: E402
from irs_efile_viewer.remote import URLRefused  # noqa: E402
from irs_efile_viewer.web import create_app  # noqa: E402

DOCS = (
    '<IRSTEST documentId="RetDoc1"><Txt>hello</Txt><AttachedRef referenceDocumentId="RetDoc2"/></IRSTEST>'
    '<OtherExpensesSchedule documentId="RetDoc2"><TotalAmt>15</TotalAmt></OtherExpensesSchedule>'
)


@pytest.fixture
def client(tree: Path) -> TestClient:
    return TestClient(create_app(MefStore(tree), max_bytes=200_000))


def _upload(client: TestClient, data: bytes, name: str = "201541349349307794_public.xml") -> str:
    response = client.post("/render", files={"file": (name, data, "text/xml")}, follow_redirects=False)
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    assert re.fullmatch(r"r/[A-Za-z0-9_-]{20,}/", location)
    return "/" + location


def test_home_page(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert 'action="render"' in response.text and "TY2014" in response.text
    assert "form-action 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_upload_then_browse(client: TestClient) -> None:
    base = _upload(client, efile_xml(documents=DOCS))
    index = client.get(base)
    assert index.status_code == 200
    assert 'href="IRSTEST.html"' in index.text and 'href="OtherExpensesSchedule.data.html"' in index.text
    assert "ObjectId" not in index.text and "201541349349307794" in index.text

    form = client.get(base + "IRSTEST.html")
    assert form.status_code == 200
    assert "EXAMPLE ORG" in form.text and "<script" not in form.text
    assert 'href="OtherExpensesSchedule.html"' in form.text  # attachment icon linked
    csp = form.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "form-action 'none'" in csp and "frame-ancestors 'none'" in csp

    data = client.get(base + "OtherExpensesSchedule.data.html")
    assert data.status_code == 200 and ">15<" in data.text
    assert client.get(base + "OtherExpensesSchedule.html").status_code == 200  # data view fallback
    assert client.get(base.rstrip("/")).status_code == 200  # redirected to the slash form


def test_url_render_uses_the_fetcher(tree: Path) -> None:
    calls = []

    def fake_fetch(url: str, *, max_bytes: int, allow_private: bool) -> tuple[bytes, str]:
        calls.append((url, allow_private))
        return efile_xml(documents=DOCS), "https://example.org/files/202442729349300109_public.xml"

    client = TestClient(create_app(MefStore(tree), fetcher=fake_fetch))
    response = client.post("/render", data={"url": " https://example.org/x "}, follow_redirects=True)
    assert response.status_code == 200 and "202442729349300109" in response.text
    assert calls == [("https://example.org/x", False)]


def test_url_refusals_are_client_errors(client: TestClient) -> None:
    response = client.post("/render", data={"url": "http://127.0.0.1:6379/"})
    assert response.status_code == 400 and "non-public" in response.text


def test_fetch_failures_are_gateway_errors(tree: Path) -> None:
    from irs_efile_viewer.remote import FetchError

    def failing(url: str, **_: object) -> tuple[bytes, str]:
        raise FetchError("HTTP 404 Not Found")

    client = TestClient(create_app(MefStore(tree), fetcher=failing))
    response = client.post("/render", data={"url": "https://example.org/x.xml"})
    assert response.status_code == 502 and "HTTP 404" in response.text


def test_private_urls_can_be_allowed_explicitly(tree: Path) -> None:
    seen = []

    def fetcher(url: str, *, max_bytes: int, allow_private: bool) -> tuple[bytes, str]:
        seen.append(allow_private)
        raise URLRefused("stop here")

    TestClient(create_app(MefStore(tree), allow_private_urls=True, fetcher=fetcher)).post(
        "/render", data={"url": "http://10.0.0.5/x.xml"}
    )
    assert seen == [True]


@pytest.mark.parametrize(
    "kwargs, status",
    [
        ({"files": {"file": ("x.xml", b"<html/>", "text/xml")}}, 422),
        ({"files": {"file": ("x.xml", b"not xml", "text/xml")}}, 422),
        ({"data": {"url": ""}}, 400),
    ],
)
def test_bad_input(client: TestClient, kwargs: dict, status: int) -> None:
    response = client.post("/render", **kwargs)
    assert response.status_code == status


def test_oversized_uploads_are_refused(client: TestClient) -> None:
    big = efile_xml(documents=DOCS).replace(b"hello", b"x" * 300_000)
    response = client.post("/render", files={"file": ("big.xml", big, "text/xml")})
    assert response.status_code == 413 and "limited to" in response.text
    assert response.headers["x-content-type-options"] == "nosniff"


def test_oversized_uploads_without_content_length_are_refused(client: TestClient) -> None:
    """A chunked body declares no size; the limit has to be enforced while reading."""
    boundary = "irs-test-boundary"
    head = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="big.xml"\r\n'
        "Content-Type: text/xml\r\n\r\n"
    ).encode()

    def body():  # a generator: sent chunked, with no Content-Length
        yield head
        for _ in range(40):
            yield b"x" * 10_000
        yield f"\r\n--{boundary}--\r\n".encode()

    response = client.post(
        "/render", content=body(), headers={"content-type": f"multipart/form-data; boundary={boundary}"}
    )
    assert response.status_code == 413 and "limited to" in response.text


def test_unknown_tokens_and_pages(client: TestClient) -> None:
    assert client.get("/r/not-a-token/").status_code == 404
    base = _upload(client, efile_xml(documents=DOCS))
    for name in ["Nope.html", "Nope.data.html", "../index.html", "IRSTEST.xml"]:
        assert client.get(base + name).status_code == 404, name


def test_sessions_are_bounded(tree: Path) -> None:
    client = TestClient(create_app(MefStore(tree), capacity=2))
    first = _upload(client, efile_xml(documents=DOCS))
    _upload(client, efile_xml(documents=DOCS))
    _upload(client, efile_xml(documents=DOCS))
    assert client.get(first).status_code == 404


def test_sessions_expire(tree: Path) -> None:
    client = TestClient(create_app(MefStore(tree), ttl_seconds=0))
    base = _upload(client, efile_xml(documents=DOCS))
    assert client.get(base).status_code == 404


def test_data_only_server(tree: Path) -> None:
    client = TestClient(create_app(None))
    assert "none — form views are unavailable" in client.get("/").text
    base = _upload(client, efile_xml(documents=DOCS))
    assert "There is no IRS stylesheet" in client.get(base + "IRSTEST.html").text
    assert client.get("/healthz").json() == {"ok": True, "stylesheet_years": []}


def test_body_limit_stops_reading_at_the_limit() -> None:
    """At the ASGI level: the app never sees more than the limit, and the client gets 413."""
    import asyncio

    from fastapi.responses import PlainTextResponse
    from starlette.types import Message, Receive, Scope, Send

    from irs_efile_viewer.web import _BodyLimit

    chunks_read = 0

    async def receive() -> Message:
        nonlocal chunks_read
        chunks_read += 1
        return {"type": "http.request", "body": b"x" * 100, "more_body": chunks_read < 1000}

    async def app(scope: Scope, receive_: Receive, send_: Send) -> None:
        while (await receive_())["more_body"]:
            pass
        await PlainTextResponse("accepted")(scope, receive_, send_)

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    limit = _BodyLimit(app, limit=1000, too_large=lambda: PlainTextResponse("too large", status_code=413))
    asyncio.run(limit({"type": "http", "headers": []}, receive, send))
    assert chunks_read == 11  # ten chunks fit; the eleventh trips the limit
    assert sent[0]["status"] == 413 and sent[1]["body"] == b"too large"
