"""The web viewer: upload or link an e-file return, then browse its forms.

The same flow as the original betson/irs-efile-viewer page — pick a file or a URL, get a
list of the forms inside, open one — with the transformation moved to the server, so it
does not depend on the browser's XSLT engine and is not limited by CORS when fetching.

Returns live in memory only, under an unguessable token, bounded by count, total size
and age. Forms are rendered on first view and cached with their return. Every response
carries a restrictive CSP; rendered forms additionally forbid all script and framing.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import pages, postprocess, remote
from .efile import EfileError, EfileReturn, parse_return
from .mef import MefStore
from .render import Renderer

_FORM_CSP = postprocess.PAGE_CSP + "; frame-ancestors 'none'"
_STATIC_CSP = pages.STATIC_CSP + "; frame-ancestors 'none'"


class _BodyTooLarge(Exception):
    pass


class _BodyLimit:
    """Stops reading a request body past ``limit`` bytes, ``Content-Length`` or not.

    Without it a chunked upload is spooled to disk in full before any handler can look at
    its size. Once the limit trips, whatever the app answers (FastAPI reports a body that
    failed to parse as a 400) is replaced by ``too_large``.
    """

    def __init__(self, app: ASGIApp, limit: int, too_large: Callable[[], Response]) -> None:
        self._app = app
        self._limit = limit
        self._too_large = too_large

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        length = dict(scope.get("headers") or []).get(b"content-length", b"")
        if length.isdigit() and int(length) > self._limit:
            await self._refuse(scope, send)
            return
        received = 0
        exceeded = responded = False

        async def counting_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self._limit:
                    exceeded = True
                    raise _BodyTooLarge
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal responded
            if exceeded:
                if not responded:
                    responded = True
                    await self._refuse(scope, send)
                return
            responded = responded or message["type"] == "http.response.start"
            await send(message)

        try:
            await self._app(scope, counting_receive, guarded_send)
        except _BodyTooLarge:
            if not responded:
                await self._refuse(scope, send)

    async def _refuse(self, scope: Scope, send: Send) -> None:
        async def disconnected() -> Message:
            return {"type": "http.disconnect"}

        await self._too_large()(scope, disconnected, send)


@dataclass
class _Session:
    ret: EfileReturn
    size: int
    created: float
    pages: dict[str, str] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


class _Sessions:
    """LRU of parsed returns, bounded by count, total source bytes and age."""

    def __init__(self, *, capacity: int, max_total_bytes: int, ttl_seconds: float) -> None:
        self._items: OrderedDict[str, _Session] = OrderedDict()
        self._lock = threading.Lock()
        self._capacity = capacity
        self._max_total = max_total_bytes
        self._ttl = ttl_seconds

    def add(self, ret: EfileReturn, size: int) -> str:
        token = secrets.token_urlsafe(16)
        with self._lock:
            self._items[token] = _Session(ret=ret, size=size, created=time.monotonic())
            self._evict()
        return token

    def get(self, token: str) -> _Session | None:
        with self._lock:
            self._expire()
            session = self._items.get(token)
            if session is not None:
                self._items.move_to_end(token)
            return session

    def _expire(self) -> None:
        cutoff = time.monotonic() - self._ttl
        for token in [t for t, s in self._items.items() if s.created < cutoff]:
            del self._items[token]

    def _evict(self) -> None:
        self._expire()
        while len(self._items) > self._capacity or (
            len(self._items) > 1 and sum(s.size for s in self._items.values()) > self._max_total
        ):
            self._items.popitem(last=False)


def create_app(
    store: MefStore | None,
    *,
    max_bytes: int = 64 * 1024 * 1024,
    allow_private_urls: bool = False,
    capacity: int = 32,
    max_total_bytes: int = 256 * 1024 * 1024,
    ttl_seconds: float = 3600.0,
    fetcher: Callable[..., tuple[bytes, str]] = remote.fetch,
) -> FastAPI:
    """The viewer as an ASGI app. ``store`` may be ``None``: data views only."""
    app = FastAPI(title="IRS e-File Viewer", docs_url=None, redoc_url=None, openapi_url=None)
    renderer = Renderer(store)
    sessions = _Sessions(capacity=capacity, max_total_bytes=max_total_bytes, ttl_seconds=ttl_seconds)
    max_mb = max(1, max_bytes // (1024 * 1024))

    @app.middleware("http")
    async def guard(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        return _secured(await call_next(request))

    @app.get("/", response_class=HTMLResponse)
    def home() -> Response:
        return _html(pages.home_page(years=store.years if store else (), max_mb=max_mb))

    @app.get("/healthz")
    def healthz() -> Response:
        return JSONResponse({"ok": True, "stylesheet_years": list(store.years) if store else []})

    @app.post("/render")
    def render(file: UploadFile | None = File(None), url: str = Form("")) -> Response:
        try:
            if file is not None and file.filename:
                data = file.file.read(max_bytes + 1)
                source = PurePosixPath(file.filename.replace("\\", "/")).name
                if len(data) > max_bytes:
                    return _error("File too large", f"Uploads are limited to {max_mb} MB.", 413)
            elif url.strip():
                data, final_url = fetcher(url.strip(), max_bytes=max_bytes, allow_private=allow_private_urls)
                source = PurePosixPath(urlsplit(final_url).path).name or final_url
            else:
                return _error("Nothing to render", "Choose an XML file or enter a URL.", 400)
            ret = parse_return(data, source_name=source)
        except remote.URLRefused as exc:
            return _error("That URL is not allowed", str(exc), 400)
        except remote.FetchError as exc:
            return _error("Could not fetch that URL", str(exc), 502)
        except EfileError as exc:
            return _error("Not an IRS e-file return", str(exc), 422)
        token = sessions.add(ret, len(data))
        return RedirectResponse(f"r/{token}/", status_code=303)

    @app.get("/r/{token}")
    def session_root(token: str) -> Response:
        return RedirectResponse(f"{token}/", status_code=307)

    @app.get("/r/{token}/")
    def index(token: str) -> Response:
        return view(token, "index.html")

    @app.get("/r/{token}/{name}")
    def view(token: str, name: str) -> Response:
        session = sessions.get(token)
        if session is None:
            return _error("Return not found", "It expired or the server restarted. Render it again.", 404, back="../../")
        ret = session.ret
        with session.lock:
            cached = session.pages.get(name)
            if cached is None:
                cached = _page(renderer, ret, name)
                if cached is None:
                    return _error("Page not found", f"This return has no page named {name}.", 404, back="./")
                session.pages[name] = cached
        csp = _STATIC_CSP if name == "index.html" or name.endswith(".data.html") else _FORM_CSP
        return _html(cached, headers={"Content-Security-Policy": csp})

    # Outermost, so it sees the body before anything parses it. Multipart framing adds a
    # little to the file itself, hence the allowance.
    app.add_middleware(
        _BodyLimit,
        limit=max_bytes + 64 * 1024,
        too_large=lambda: _secured(_error("File too large", f"Uploads are limited to {max_mb} MB.", 413)),
    )
    return app


def _page(renderer: Renderer, ret: EfileReturn, name: str) -> str | None:
    if name == "index.html":
        return pages.index_page(ret, renderer.index_rows(ret))
    if name.endswith(".data.html"):
        doc = ret.document(name[: -len(".data.html")])
        if doc is None:
            return None
        has_form = bool(renderer.candidates(ret, doc))
        return renderer.render_data(ret, doc, with_form_link=has_form)
    if name.endswith(".html"):
        doc = ret.document(name[: -len(".html")])
        return renderer.render_view(ret, doc).html if doc is not None else None
    return None


def _secured(response: Response) -> Response:
    response.headers.setdefault("Content-Security-Policy", pages.APP_CSP)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers.setdefault("Cache-Control", "no-store")
    return response


def _html(body: str, status: int = 200, headers: dict[str, str] | None = None) -> Response:
    return HTMLResponse(body, status_code=status, headers=headers)


def _error(title: str, message: str, status: int, *, back: str = "./") -> Response:
    return _html(pages.error_page(title, message, back=back), status)


def serve(store: MefStore | None, *, host: str, port: int, **options: Any) -> None:  # pragma: no cover
    import uvicorn

    uvicorn.run(create_app(store, **options), host=host, port=port)
