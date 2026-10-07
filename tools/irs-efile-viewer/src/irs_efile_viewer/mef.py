"""The IRS stylesheet tree, and how it is read.

MeF stylesheets come as a tree: ``Stylesheets/<tax year>/<Document>.xsl`` plus the assets
they reference under ``rrprd/`` (``common/images`` shared by every year, and
``sdi/versioned/<tax year>/{images,scripts,styles}`` per year). Two layouts of that tree
are accepted, because the stylesheets reach people two ways:

* **IRS archive** — the per-tax-year ZIP published at irs.gov. Asset URLs are
  root-relative (``/mef/rrprd/...``).
* **betson/irs-efile-viewer** — the same files as served by GitHub Pages through Jekyll.
  Every file that carries an asset URL gained an empty YAML front-matter block and a
  ``{{ site.github.url }}`` prefix, and is not well-formed XML until both are gone.

Both are normalised when a file is read, so everything downstream sees the IRS form.
Every file the XSLT engine asks for goes through :class:`_TreeResolver`, which refuses
anything outside the tree: the stylesheets are trusted, but ``xsl:include`` and
``document()`` must not become a way to read other files on the host.
"""

from __future__ import annotations

import base64
import os
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname

from lxml import etree

#: Points the tools at a stylesheet tree (``.../mef`` or a directory containing ``mef/``).
ENV_VAR = "IRS_EFILE_MEF_DIR"

_FRONT_MATTER = re.compile(rb"\A(?:\xef\xbb\xbf)?---[ \t]*\r?\n(?:.*?\r?\n)??---[ \t]*\r?\n", re.S)
_LIQUID_SITE_URL = re.compile(rb"\{\{\s*site\.github\.url\s*\}\}")
_LEGACY_ASSET_DIR = re.compile(rb"/mef/rrdprd/", re.I)
_SAFE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")
_YEAR_DIR = re.compile(r"\d{4}")
_VERSIONED = re.compile(r"^rrprd/sdi/versioned/(\d{4})/(.+)$")
_IMAGE_TYPES = {
    ".gif": "image/gif",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".bmp": "image/bmp",
    ".ico": "image/x-icon",
    ".svg": "image/svg+xml",
}
#: Compiled stylesheets kept in memory. A busy server renders many forms from few years.
_COMPILED_CACHE_SIZE = 64

#: libxslt's own guard rails, beneath the resolver: no network, never write.
_ACCESS = etree.XSLTAccessControl(
    read_file=True, write_file=False, create_dir=False, read_network=False, write_network=False
)


class MefError(RuntimeError):
    """The stylesheet tree is missing or unusable."""


@dataclass(frozen=True)
class StylesheetChoice:
    path: Path
    year: int
    #: True when the stylesheet is for the return's own schema year.
    exact: bool


def default_dir() -> Path:
    """Where ``fetch`` installs by default: ``$XDG_CACHE_HOME/irs-efile-viewer/mef``."""
    base = os.environ.get("XDG_CACHE_HOME")
    return (Path(base) if base else Path.home() / ".cache") / "irs-efile-viewer" / "mef"


def normalize(data: bytes) -> bytes:
    """Undo the GitHub Pages packaging: front matter off, asset URLs back to ``/mef/``."""
    match = _FRONT_MATTER.match(data)
    if match:
        data = data[match.end():]
    data = _LIQUID_SITE_URL.sub(b"", data)
    return _LEGACY_ASSET_DIR.sub(b"/mef/rrprd/", data)


class MefStore:
    """A stylesheet tree on disk: picks, compiles and caches stylesheets, serves assets."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        path = Path(root).expanduser()
        if (path / "mef" / "Stylesheets").is_dir():
            path = path / "mef"
        if not (path / "Stylesheets").is_dir():
            raise MefError(f"{path} is not an IRS stylesheet tree (no Stylesheets/ directory)")
        self.root = path.resolve()
        self.years: tuple[int, ...] = _year_dirs(self.root / "Stylesheets")
        self._asset_years: tuple[int, ...] = _year_dirs(self.root / "rrprd" / "sdi" / "versioned")
        self._compiled: OrderedDict[Path, tuple[etree.XSLT, threading.Lock]] = OrderedDict()
        self._compile_lock = threading.Lock()
        self._listings: dict[Path, dict[str, Path]] = {}
        self._data_uris: dict[Path, str] = {}

    @classmethod
    def locate(cls, explicit: str | os.PathLike[str] | None = None) -> MefStore:
        """An explicit path, else ``$IRS_EFILE_MEF_DIR``, else the default install."""
        if explicit:
            return cls(explicit)
        configured = os.environ.get(ENV_VAR)
        if configured:
            return cls(configured)
        try:
            return cls(default_dir())
        except MefError:
            raise MefError(
                "no IRS stylesheets installed: run `irs-efile-viewer fetch`, "
                f"pass --mef DIR, or set {ENV_VAR}"
            ) from None

    # -- stylesheets ---------------------------------------------------------------

    def candidates(self, name: str, year: int) -> list[StylesheetChoice]:
        """Stylesheets for document ``name``: the return's year first, then the nearest
        earlier years, then later ones."""
        if not _SAFE_NAME.fullmatch(name):
            return []
        older = sorted((y for y in self.years if y < year), reverse=True)
        newer = sorted(y for y in self.years if y > year)
        found = []
        for y in [year, *older, *newer]:
            path = self.root / "Stylesheets" / str(y) / f"{name}.xsl"
            if path.is_file():
                found.append(StylesheetChoice(path=path, year=y, exact=y == year))
        return found

    def compile(self, choice: StylesheetChoice) -> tuple[etree.XSLT, threading.Lock]:
        """The compiled stylesheet and the lock to hold while applying it."""
        with self._compile_lock:
            hit = self._compiled.get(choice.path)
            if hit is not None:
                self._compiled.move_to_end(choice.path)
                return hit
            parser = etree.XMLParser(resolve_entities=False, no_network=True)
            parser.resolvers.add(_TreeResolver(self))
            doc = etree.fromstring(self.read(choice.path), parser, base_url=choice.path.as_uri())
            hit = (etree.XSLT(doc, access_control=_ACCESS), threading.Lock())
            self._compiled[choice.path] = hit
            while len(self._compiled) > _COMPILED_CACHE_SIZE:
                self._compiled.popitem(last=False)
            return hit

    def read(self, path: Path) -> bytes:
        return normalize(path.read_bytes())

    def contained(self, path: Path) -> Path | None:
        """``path`` resolved, if it stays inside the tree."""
        try:
            resolved = path.resolve()
        except OSError:
            return None
        return resolved if resolved.is_relative_to(self.root) else None

    def path_for_url(self, url: str) -> Path | None:
        parts = urlsplit(url)
        if parts.scheme == "file":
            raw = url2pathname(unquote(parts.path))
        elif parts.scheme == "" and not parts.netloc:
            raw = unquote(url)
        else:
            return None
        return self.contained(Path(raw))

    # -- assets ----------------------------------------------------------------------

    def asset(self, url: str, *, year_hint: int | None = None) -> Path | None:
        """The file behind a root-relative asset URL (``/mef/rrprd/...``), if any.

        A versioned asset missing from its own year (the TY2023 return rendered with the
        TY2021 stylesheet asks for ``versioned/2023/...``) is taken from ``year_hint``,
        then the nearest year that has it.
        """
        path = unquote(urlsplit(url).path)
        if not path.lower().startswith("/mef/"):
            return None
        rel = re.sub(r"^rrdprd/", "rrprd/", path[len("/mef/"):], flags=re.I)
        hit = self._find(rel)
        if hit is not None:
            return hit
        match = _VERSIONED.match(rel)
        if match is None:
            return None
        asked = int(match.group(1))
        older = sorted((y for y in self._asset_years if y < asked), reverse=True)
        newer = sorted(y for y in self._asset_years if y > asked)
        hint = [year_hint] if year_hint is not None else []
        for y in [*hint, *older, *newer]:
            hit = self._find(f"rrprd/sdi/versioned/{y}/{match.group(2)}")
            if hit is not None:
                return hit
        return None

    def data_uri(self, path: Path) -> str | None:
        """A ``data:`` URI for an image asset; ``None`` for anything that is not an image."""
        cached = self._data_uris.get(path)
        if cached is None:
            mime = _IMAGE_TYPES.get(path.suffix.lower())
            if mime is None:
                return None
            cached = f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode('ascii')}"
            self._data_uris[path] = cached
        return cached

    def _find(self, rel: str) -> Path | None:
        candidate = self.contained(self.root / rel)
        if candidate is None:
            return None
        if candidate.is_file():
            return candidate
        # The stylesheets were written for a case-insensitive web server (941SSPR_NextES.GIF).
        listing = self._listing(candidate.parent)
        return listing.get(candidate.name.lower())

    def _listing(self, directory: Path) -> dict[str, Path]:
        listing = self._listings.get(directory)
        if listing is None:
            listing = {}
            if directory.is_dir():
                listing = {p.name.lower(): p for p in directory.iterdir() if p.is_file()}
            self._listings[directory] = listing
        return listing


class _TreeResolver(etree.Resolver):
    """Serves ``xsl:include``/``xsl:import``/``document()`` from the tree, normalised.

    Everything else resolves to an empty document, which fails the include loudly rather
    than letting libxml2 fall back to reading the path itself.
    """

    def __init__(self, store: MefStore) -> None:
        super().__init__()
        self._store = store

    def resolve(self, system_url: str, public_id: str, context: object) -> object:
        path = self._store.path_for_url(system_url)
        if path is None or not path.is_file():
            return self.resolve_empty(context)
        return self.resolve_string(self._store.read(path), context, base_url=path.as_uri())


def _year_dirs(directory: Path) -> tuple[int, ...]:
    if not directory.is_dir():
        return ()
    return tuple(sorted(int(p.name) for p in directory.iterdir() if p.is_dir() and _YEAR_DIR.fullmatch(p.name)))
