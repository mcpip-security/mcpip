"""``irs-efile-viewer``: render returns to static HTML, install stylesheets, serve the UI.

    irs-efile-viewer fetch                         # IRS stylesheets TY2008–2021, once
    irs-efile-viewer render 201541349349307794_public.xml -o out/
    irs-efile-viewer render https://…/202442729349300109_public.xml
    irs-efile-viewer import-irs-zip ~/Downloads/TY2023_MeF_Stylesheets.zip
    irs-efile-viewer serve --port 8000
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from . import remote, sources
from .efile import EfileError, parse_return
from .mef import MefError, MefStore, default_dir
from .render import Renderer

_EXIT_OK, _EXIT_STRICT, _EXIT_USAGE = 0, 1, 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="irs-efile-viewer",
        description="Render IRS Modernized e-File XML returns as the IRS forms they were filed on.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    render = sub.add_parser("render", help="render e-file XML to HTML pages")
    render.add_argument("inputs", nargs="+", help="XML file, http(s) URL, or - for standard input")
    render.add_argument("-o", "--out", default="irs-efile-html", help="output directory (default: %(default)s)")
    render.add_argument("--mef", help="IRS stylesheet tree (default: $IRS_EFILE_MEF_DIR, then the fetch cache)")
    render.add_argument("--only", nargs="+", metavar="DOCUMENT", help="render only these documents, e.g. IRS990")
    render.add_argument("--data-only", action="store_true", help="write data views only; no IRS stylesheets")
    render.add_argument(
        "--strict", action="store_true",
        help="exit 1 unless every document got a form view from its own tax year's stylesheet",
    )
    render.add_argument("--max-mb", type=int, default=200, help="largest input accepted (default: %(default)s)")

    fetch = sub.add_parser("fetch", help="install IRS stylesheets TY2008–2021 (pinned betson/irs-efile-viewer)")
    fetch.add_argument("--dest", help=f"install directory (default: {default_dir()})")
    fetch.add_argument("--years", nargs="+", type=int, metavar="YEAR", help="only these tax years")

    imp = sub.add_parser("import-irs-zip", help="merge irs.gov MeF stylesheet ZIPs (TY2022+) into the tree")
    imp.add_argument("archives", nargs="+", help="ZIP files, oldest tax year first")
    imp.add_argument("--dest", help=f"stylesheet tree (default: {default_dir()})")

    years = sub.add_parser("years", help="list the tax years of the installed stylesheets")
    years.add_argument("--mef")

    serve = sub.add_parser("serve", help="run the web viewer")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--mef")
    serve.add_argument("--max-mb", type=int, default=64, help="largest upload or download (default: %(default)s)")
    serve.add_argument(
        "--allow-private-urls", action="store_true",
        help="let the URL form reach private and loopback addresses (only on a trusted network)",
    )

    args = parser.parse_args(argv)
    try:
        if args.command == "render":
            return _render(args)
        if args.command == "fetch":
            summary = sources.fetch_betson(args.dest or default_dir(), args.years)
            print(f"installed {summary.files} files (TY{', TY'.join(map(str, summary.years))}) into {summary.destination}")
            return _EXIT_OK
        if args.command == "import-irs-zip":
            for archive in args.archives:
                summary = sources.import_irs_zip(archive, args.dest or default_dir())
                print(f"{archive}: {summary.files} files, TY{', TY'.join(map(str, summary.years)) or ' (assets only)'}")
            return _EXIT_OK
        if args.command == "years":
            store = MefStore.locate(args.mef)
            print(f"{store.root}: {' '.join(map(str, store.years))}")
            return _EXIT_OK
        if args.command == "serve":
            return _serve(args)
    except (MefError, sources.SourceError) as exc:
        print(f"irs-efile-viewer: {exc}", file=sys.stderr)
        return _EXIT_USAGE
    parser.error(f"unknown command {args.command}")
    return _EXIT_USAGE


def _render(args: argparse.Namespace) -> int:
    store: MefStore | None = None
    if not args.data_only:
        try:
            store = MefStore.locate(args.mef)
        except MefError as exc:
            if args.mef:
                raise
            print(f"irs-efile-viewer: {exc}; writing data views only", file=sys.stderr)
    renderer = Renderer(store)
    out_root = Path(args.out)
    max_bytes = args.max_mb * 1024 * 1024
    status = _EXIT_OK
    for item in args.inputs:
        try:
            data, source = _read_input(item, max_bytes)
            ret = parse_return(data, source_name=source)
        except (OSError, EfileError, remote.FetchError) as exc:
            print(f"{item}: {exc}", file=sys.stderr)
            status = _EXIT_USAGE
            continue
        target = out_root if len(args.inputs) == 1 else out_root / _slug(source, item)
        rendering = renderer.render_all(ret, only=args.only or ())
        rendering.write(target)
        exact = sum(1 for r in rendering.rows if r.stylesheet_year is not None and r.exact and not r.error)
        print(
            f"{item}: {ret.title}\n"
            f"  {len(rendering.rows)} documents: {exact} with their own year's IRS stylesheet, "
            f"{len(rendering.approximations)} approximated, {len(rendering.failures)} failed\n"
            f"  -> {target / 'index.html'}"
        )
        for row in rendering.rows:
            if row.error:
                print(f"  ! {row.document.stem}: {row.error}", file=sys.stderr)
        if args.strict and (rendering.failures or rendering.approximations):
            status = max(status, _EXIT_STRICT)
    return status


def _read_input(item: str, max_bytes: int) -> tuple[bytes, str]:
    if item == "-":
        data = sys.stdin.buffer.read(max_bytes + 1)
        source = "stdin"
    elif urlsplit(item).scheme.lower() in ("http", "https"):
        # The CLI fetches for the person running it, so private addresses are fine here.
        data, final = remote.fetch(item, max_bytes=max_bytes, allow_private=True)
        return data, PurePosixPath(urlsplit(final).path).name or final
    else:
        path = Path(item)
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
        source = path.name
    if len(data) > max_bytes:
        raise OSError(f"larger than {max_bytes // (1024 * 1024)} MB (raise --max-mb)")
    return data, source


def _slug(source: str, item: str) -> str:
    stem = Path(source).stem or Path(item).stem or "return"
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in stem)


def _serve(args: argparse.Namespace) -> int:  # pragma: no cover - blocks
    try:
        from .web import serve
    except ImportError:
        print("irs-efile-viewer: the web viewer needs `pip install 'irs-efile-viewer[web]'`", file=sys.stderr)
        return _EXIT_USAGE
    try:
        store: MefStore | None = MefStore.locate(args.mef)
    except MefError as exc:
        if args.mef:
            raise
        print(f"irs-efile-viewer: {exc}; serving data views only", file=sys.stderr)
        store = None
    serve(
        store,
        host=args.host,
        port=args.port,
        max_bytes=args.max_mb * 1024 * 1024,
        allow_private_urls=args.allow_private_urls,
    )
    return _EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
