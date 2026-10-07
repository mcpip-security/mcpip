# irs-efile-viewer

Render an IRS Modernized e-File (MeF) XML return as the IRS forms it was filed on, end
to end: XML in, a folder of self-contained HTML pages out. Command line, library and web
UI. Tested on Form 990, 990-EZ, 990-PF and 990-T filings from TY2010–2023; other MeF
returns (1040, 1120, 1065, …) go through the same IRS stylesheet mechanism.

It does what [betson/irs-efile-viewer](https://betson.github.io/irs-efile-viewer/) does —
wrap one document of the return in the IRS display application's `<AppData>` envelope and
run the IRS's own XSLT stylesheet for that tax year — but on the server, with libxslt,
rather than in the browser. Chrome is removing XSLT (`XSLTProcessor`) from its stable
channel in November 2026; this does not depend on it.

```console
$ pip install -e 'tools/irs-efile-viewer[web]'
$ irs-efile-viewer fetch                      # IRS stylesheets TY2008–2021, ~640 MB, once
$ irs-efile-viewer render 201541349349307794_public.xml -o out/
201541349349307794_public.xml: VOICE OF SAN DIEGO — Form 990, tax year 2014
  6 documents: 6 with their own year's IRS stylesheet, 0 approximated, 0 failed
  -> out/index.html
$ irs-efile-viewer serve                      # http://127.0.0.1:8000
```

`render` takes files, `http(s)` URLs or `-` for standard input, several at once (one
sub-directory each). Public 990-series filings can be fetched by IRS object id from
GivingTuesday's mirror of the IRS data set, e.g.
`https://gt990datalake-rawdata.s3.amazonaws.com/EfileData/XmlFiles/202442729349300109_public.xml`
(the IRS's original AWS bucket no longer serves them).

## What you get

For a return with documents `IRS990`, `IRS990ScheduleA`, …:

| File | Contents |
| --- | --- |
| `index.html` | Filer, EIN, tax period, version; every document with links and the stylesheet used |
| `IRS990.html` | The form view: the IRS stylesheet's rendering of that document |
| `IRS990.data.html` | The data view: every element and attribute of the document, labelled |

Every page is **self-contained** (CSS inlined, images as `data:` URIs — save it, mail it,
serve it from anywhere), **inert** (no script, no event handlers, no non-web URLs, and a
`default-src 'none'` Content-Security-Policy on top) and **linked**: the paper-clip icons
the IRS display app wired to `SendRef('RetDoc…')` link to the attached document's page.
With script gone, scrolling tables show all their rows.

## Stylesheets and tax years

A form view needs the IRS stylesheet for the return's tax year (`returnVersion`, e.g.
`2014v5.0` → TY2014). Stylesheets live in a tree — `Stylesheets/<year>/*.xsl` plus assets
under `rrprd/` — found via `--mef DIR`, else `$IRS_EFILE_MEF_DIR`, else the `fetch` cache
(`~/.cache/irs-efile-viewer/mef`).

* `irs-efile-viewer fetch [--years 2014 2021 …]` installs TY2008–2021 from
  betson/irs-efile-viewer, pinned to one commit (`sources.py`), sparse and blob-filtered so
  a year costs ~45 MB. Where it came from is recorded in `irs-efile-viewer-sources.json`.
* TY2022 onward are published only by the IRS, as one ZIP per tax year on the
  [MeF stylesheets page](https://www.irs.gov/node/9947).
  `irs-efile-viewer import-irs-zip FILE.zip …` merges them in (oldest year first; each IRS
  archive carries only what changed, so it is merged file by file, never replaced).

Both layouts are read as they are: the IRS's root-relative `/mef/…` asset URLs, and the
GitHub Pages copy whose files carry Jekyll front matter and `{{ site.github.url }}`.

When the return's own year is missing, the nearest earlier year's stylesheet draws it
(then later ones). That page, the index and the CLI summary all say so — lines that differ
between the two years may be missing from it — and `--strict` turns it into exit status 1.
The data view never depends on a stylesheet: it is complete for every document, and is
what `<stem>.html` shows (with the reason) when no stylesheet exists or all of them fail.

## Web viewer

`irs-efile-viewer serve [--host --port --mef --max-mb]` — the betson viewer's flow
(upload a file or give a URL, pick a form) as a FastAPI app. `irs_efile_viewer.web.create_app()`
returns the ASGI app for any server.

* Returns are kept in memory only, under an unguessable token, bounded by count, total
  size and age (defaults: 32, 256 MB, one hour). Forms render on first view and are cached.
* Uploads and downloads are capped (`--max-mb`, default 64). The upload cap is enforced
  while the body is read, so a chunked upload with no `Content-Length` cannot get past it;
  a URL fetch also has an overall deadline, so a server trickling bytes cannot hold it.
* URLs are fetched server-side, so CORS does not matter. Only `http`/`https`, no
  credentials, and every resolved address must be public — loopback, private, link-local
  (cloud metadata), reserved, multicast and unspecified addresses are refused, after
  unwrapping IPv4-mapped IPv6, on every redirect hop; the connection is pinned to the
  checked address. Through an `HTTPS_PROXY`, the proxy's policy governs the last hop.
  `--allow-private-urls` lifts the address check for trusted networks.
* Every response carries `nosniff`, `no-referrer`, `DENY` framing and a CSP; form pages
  allow no script, no network and no form submission.

## As a library

```python
from irs_efile_viewer import MefStore, Renderer, parse_return

ret = parse_return(xml_bytes, source_name="201541349349307794_public.xml")
renderer = Renderer(MefStore.locate())        # or Renderer(None): data views only
rendering = renderer.render_all(ret)          # .pages {file name: html}, .rows, .failures
rendering.write("out/")
html, stylesheet = renderer.render_form(ret, ret.documents[0])
```

## Hardening

* **Input XML** is parsed with entity resolution, DTD loading and network access off.
* **Stylesheets** load through a resolver confined to the tree: `xsl:include` and
  `document()` cannot read anything outside it, and libxslt may not write or touch the
  network.
* **Output** is re-parsed and stripped of `script`/`iframe`/`object`/`embed`/`base`,
  every `on*` attribute, and every URL that is not `http(s)`, `mailto` or local — even
  though the IRS stylesheets escape filing data, some use `disable-output-escaping`, and
  the tests feed a hostile stylesheet to prove the strip holds.

## Compared with the browser viewer

Reverse-engineering betson/irs-efile-viewer for this found, and this fixes:

* Returns before TY2013 could not be opened: the viewer looked up `ReturnHeader/TaxYr`,
  which those schemas call `TaxYear`, and the null lookup threw before the form opened.
* The namespace was removed with a regex that only matched a double-quoted `xmlns`
  written first; this removes it from the parsed tree.
* A return with two documents of one type showed the first twice; each is separate here.
* URL loading needed CORS headers from the host; loaded files were cached by file name
  only, so two URLs ending in the same name showed the same return.
* Attachment icons called a function that does not exist outside the IRS app.

## Tests

```console
$ pip install -e 'tools/irs-efile-viewer[web,dev]'
$ irs-efile-viewer fetch --years 2010 2011 2012 2014 2017 2019 2020 2021
$ cd tools/irs-efile-viewer && IRS_EFILE_REQUIRE_MEF=1 python -m pytest -q
```

Most tests are hermetic (a synthetic stylesheet tree, a local HTTP server, a local git
repository). `test_irs_efile_e2e.py` renders ten public filings, TY2010–2023, through
the real stylesheets; without a tree they are skipped, unless `IRS_EFILE_REQUIRE_MEF=1`.
CI runs everything in the `irs-efile-viewer` job.

## Credits and licences

The IRS MeF stylesheets and assets are works of the U.S. Government. The stylesheet tree
for TY2008–2021, and the approach of rendering e-files with them, come from
[betson/irs-efile-viewer](https://github.com/betson/irs-efile-viewer) (MIT). The test
fixtures are public IRS Form 990-series filings (see `tests/fixtures/filings/README.md`).
