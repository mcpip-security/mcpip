"""Turn the IRS stylesheet's HTML into a page that stands on its own.

The stylesheets were written for the IRS's own display application, which supplies the
script (``FormDisplay.js``, ``SendRef`` to jump between documents) and serves the CSS and
images from its web root. Taken out of that application, a page needs three things:

* **self-contained** — CSS is inlined and images become ``data:`` URIs, so a page can be
  saved, mailed or served from anywhere and still look like the form;
* **inert** — every script, event handler and non-web URL is removed. The filing is
  untrusted input and pages are served under a CSP that blocks script anyway; this is
  the second wall. Nothing on a form needs script: with it gone, tables show every row;
* **linked** — the paper-clip icons that called ``SendRef('RetDoc…')`` become real links
  to the referenced document's page.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import urljoin, urlsplit

import lxml.html
from lxml import etree

from .mef import MefStore

#: The policy every rendered page carries (and the web app also sends as a header).
PAGE_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; "
    "base-uri 'none'; form-action 'none'"
)

_DOCTYPE = re.compile(r"^\s*(<!DOCTYPE[^>]*>)", re.I)
_SEND_REF = re.compile(r"SendRef\(\s*['\"]([^'\"]+)['\"]")
_RETURN_TO_FORM = re.compile(r"returnToWriteInImage", re.I)
_CSS_URL = re.compile(r"url\(\s*(['\"]?)(.*?)\1\s*\)", re.I | re.S)
_CSS_IMPORT = re.compile(r"@import[^;]*;?", re.I)
_CSS_DANGER = re.compile(r"expression\s*\(|behavior\s*:|-moz-binding", re.I)
_DROP = {"script", "noscript", "iframe", "frame", "frameset", "object", "embed", "applet", "base", "portal"}
_IMAGE_ATTRS = ("src", "background", "lowsrc", "dynsrc")
_OTHER_URL_ATTRS = ("action", "formaction", "poster", "data", "cite", "longdesc", "usemap", "srcset", "ping")
_WEB_SCHEMES = {"", "http", "https", "mailto"}
#: Browsers ignore ASCII whitespace and control characters inside a URL scheme.
_SCHEME_NOISE = re.compile(r"[\x00-\x20]+")
_SCRIPT_URL = re.compile(r"^(?:java|vb|live)script:", re.I)


def finalize(
    html_text: str,
    *,
    store: MefStore | None,
    year_hint: int | None,
    links: Mapping[str, str],
    toolbar: str = "",
) -> str:
    """Self-contained, script-free HTML for one rendered form.

    ``links`` maps a ``documentId`` to the file that shows it; ``toolbar`` is an HTML
    fragment placed at the top of the body (navigation, notes), hidden when printing.
    """
    doctype_match = _DOCTYPE.match(html_text)
    doc = lxml.html.document_fromstring(html_text)
    head = doc.find("head")
    if head is None:
        head = etree.Element("head")
        doc.insert(0, head)
    body = doc.find("body")
    if body is None:
        body = etree.SubElement(doc, "body")

    # Pass 1: remove what must not survive at all. Pass 2 then only sees what is left.
    for comment in list(doc.iter(etree.Comment)):
        _drop(comment)
    for el in list(doc.iter(*_DROP, "meta")):
        if el.tag != "meta" or _meta_is_dropped(el):
            _drop(el)

    assets = _Assets(store, year_hint)
    for el in list(doc.iter()):
        if not isinstance(el.tag, str):
            continue
        if el.tag == "link":
            _inline_stylesheet(el, assets)
            continue
        if el.tag == "style":
            el.text = assets.rewrite_css(el.text or "", base="")
        handlers = [name for name in el.attrib if name.lower().startswith("on")]
        handler = " ".join(el.attrib[name] for name in handlers)
        for name in handlers:
            del el.attrib[name]
        if handler:
            el = _rewire(el, handler, links)
        _sanitize_urls(el, el.tag, assets)

    for meta in [
        etree.Element("meta", charset="utf-8"),
        etree.Element("meta", {"http-equiv": "Content-Security-Policy", "content": PAGE_CSP}),
        etree.Element("meta", name="referrer", content="no-referrer"),
    ][::-1]:
        head.insert(0, meta)
    if toolbar:
        for fragment in reversed(lxml.html.fragments_fromstring(toolbar)):
            if isinstance(fragment, str):
                continue
            (head if fragment.tag == "style" else body).insert(0, fragment)

    return lxml.html.tostring(
        doc,
        doctype=doctype_match.group(1) if doctype_match else None,
        encoding="unicode",
        method="html",
    )


class _Assets:
    """Resolves ``/mef/...`` asset URLs to inline ``data:`` URIs and CSS text."""

    def __init__(self, store: MefStore | None, year_hint: int | None) -> None:
        self._store = store
        self._year_hint = year_hint

    def image(self, url: str) -> str | None:
        if url.lower().startswith("data:image/"):
            return url
        if self._store is None:
            return None
        path = self._store.asset(url, year_hint=self._year_hint)
        return self._store.data_uri(path) if path is not None else None

    def stylesheet(self, url: str) -> str | None:
        if self._store is None:
            return None
        path = self._store.asset(url, year_hint=self._year_hint)
        if path is None or path.suffix.lower() != ".css":
            return None
        css = self._store.read(path).decode("utf-8", "replace")
        return self.rewrite_css(css, base=urlsplit(url).path)

    def rewrite_css(self, css: str, *, base: str) -> str:
        css = _CSS_IMPORT.sub("", css)
        if _CSS_DANGER.search(css):
            css = _CSS_DANGER.sub("invalid-", css)

        def inline(match: re.Match[str]) -> str:
            target = match.group(2).strip()
            uri = self.image(urljoin(base, target) if base else target)
            return f'url("{uri}")' if uri else "none"

        return _CSS_URL.sub(inline, css)


def _inline_stylesheet(link: etree._Element, assets: _Assets) -> None:
    rel = (link.get("rel") or "").lower()
    css = assets.stylesheet(link.get("href") or "") if "stylesheet" in rel else None
    if css is None:
        _drop(link)
        return
    style = etree.Element("style")
    style.text = css
    style.tail = link.tail
    parent = link.getparent()
    if parent is not None:
        parent.replace(link, style)


def _rewire(el: etree._Element, handler: str, links: Mapping[str, str]) -> etree._Element:
    """Keep what a removed event handler was for, when that is navigation."""
    ref = _SEND_REF.search(handler)
    if ref:
        target = links.get(ref.group(1))
        if target is None:
            el.set("title", f"Referenced document {ref.group(1)} is not in this return")
            return el
        if el.tag.lower() == "a":
            el.set("href", target)
            return el
        anchor = etree.Element("a", href=target, title="Open the referenced document")
        anchor.set("class", "iev-attachment")
        parent = el.getparent()
        if parent is not None:
            anchor.tail, el.tail = el.tail, None
            parent.replace(el, anchor)
            anchor.append(el)
        return el
    if _RETURN_TO_FORM.search(handler) and el.tag.lower() == "input":
        anchor = etree.Element("a", href="#")
        anchor.set("class", el.get("class") or "")
        anchor.text = el.get("value") or "Return to Form"
        anchor.tail = el.tail
        parent = el.getparent()
        if parent is not None:
            parent.replace(el, anchor)
        return anchor
    return el


def _sanitize_urls(el: etree._Element, tag: str, assets: _Assets) -> None:
    for name, value in list(el.attrib.items()):  # any attribute: xlink:href, formaction, …
        if _SCRIPT_URL.match(_SCHEME_NOISE.sub("", value)):
            del el.attrib[name]
    for name in _IMAGE_ATTRS:
        value = el.get(name)
        if value is not None:
            uri = assets.image(value.strip())
            if uri is None:
                del el.attrib[name]
            else:
                el.set(name, uri)
    for name in _OTHER_URL_ATTRS:
        if name in el.attrib:
            del el.attrib[name]
    href = el.get("href")
    if href is not None:
        if tag in ("a", "area") and _is_web_url(href):
            if urlsplit(href.strip()).scheme in ("http", "https"):
                el.set("rel", "noopener noreferrer")
        else:
            del el.attrib["href"]
    style = el.get("style")
    if style is not None:
        el.set("style", assets.rewrite_css(style, base=""))


def _is_web_url(value: str) -> bool:
    try:
        return urlsplit(value.strip()).scheme.lower() in _WEB_SCHEMES
    except ValueError:
        return False


def _meta_is_dropped(meta: etree._Element) -> bool:
    if meta.get("charset") is not None:
        return True
    equiv = (meta.get("http-equiv") or "").lower()
    return equiv in {"refresh", "content-type", "content-security-policy", "set-cookie"}


def _drop(el: etree._Element) -> None:
    parent = el.getparent()
    if parent is None:
        return
    if el.tail:
        previous = el.getprevious()
        if previous is not None:
            previous.tail = (previous.tail or "") + el.tail
        else:
            parent.text = (parent.text or "") + el.tail
    parent.remove(el)
