"""HTML for the pages this tool writes itself: the return index, the toolbar on form
pages, and the web front end. Everything is static: no script, styles inline."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from html import escape

from .efile import Document, EfileReturn

#: Static pages: nothing loads, nothing runs, nothing submits.
STATIC_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
    "base-uri 'none'; form-action 'none'"
)
#: The web app's own pages may submit their forms back to the app.
APP_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)

BASE_CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1d2330;--muted:#5c6577;--line:#d9dde5;--soft:#f4f6f9;
--accent:#1f5fbf;--ok-bg:#e6f4ea;--ok-fg:#1e5b2f;--warn-bg:#fff4d6;--warn-fg:#6b4a00;--bad-bg:#fde8e8;--bad-fg:#9b1c1c}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e6e9ef;--muted:#9aa3b2;--line:#2c323c;--soft:#1c2027;
--accent:#8ab4ff;--ok-bg:#163322;--ok-fg:#9be0b0;--warn-bg:#3a2f12;--warn-fg:#f4d58a;--bad-bg:#3d1717;--bad-fg:#ffb4b4}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1080px;margin:0 auto;padding:24px 16px 56px}
a{color:var(--accent)}
h1{font-size:1.6rem;line-height:1.25;margin:.2rem 0 .3rem}
h2{font-size:1.15rem;margin:2rem 0 .6rem}
code{font:12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.eyebrow{margin:0;color:var(--muted);font-size:.8rem;letter-spacing:.06em;text-transform:uppercase}
.sub{margin:0;color:var(--muted)}
.muted{color:var(--muted)}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px 24px;margin:20px 0 0;padding:14px 16px;
background:var(--soft);border:1px solid var(--line);border-radius:8px}
.facts div{min-width:0}.facts dt{color:var(--muted);font-size:.78rem}.facts dd{margin:0;overflow-wrap:anywhere}
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;vertical-align:top;padding:9px 12px;border-bottom:1px solid var(--line)}
tbody tr:last-child td{border-bottom:0}
th{font-size:.78rem;color:var(--muted);font-weight:600;background:var(--soft)}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:.78rem;white-space:nowrap}
.ok{background:var(--ok-bg);color:var(--ok-fg)}.warn{background:var(--warn-bg);color:var(--warn-fg)}
.bad{background:var(--bad-bg);color:var(--bad-fg)}.none{background:var(--soft);color:var(--muted);border:1px solid var(--line)}
.note{padding:10px 14px;border-radius:8px;background:var(--warn-bg);color:var(--warn-fg);margin:16px 0}
.error{padding:10px 14px;border-radius:8px;background:var(--bad-bg);color:var(--bad-fg);margin:16px 0}
.nav{display:flex;flex-wrap:wrap;gap:6px 18px;align-items:center;padding:10px 16px;border-bottom:1px solid var(--line);
background:var(--soft);font-size:.9rem}
.nav .here{color:var(--muted)}
.foot{margin-top:28px;font-size:.82rem;color:var(--muted)}
"""

#: Placed at the top of every IRS form page. Light only: the forms are paper.
_FORM_BAR_CSS = (
    "#iev-bar{display:block;float:none;width:auto;margin:0 0 10px;padding:8px 12px;text-align:left;"
    "background:#f3f5f8;border-bottom:1px solid #c9ced8;color:#1d2330;"
    "font:13px/1.45 system-ui,-apple-system,'Segoe UI',sans-serif}"
    "#iev-bar a{color:#1f5fbf;text-decoration:none;margin-right:16px;font:inherit}"
    "#iev-bar a:hover{text-decoration:underline}#iev-bar .iev-where{color:#5c6577}"
    "#iev-bar .iev-note{margin-top:6px;padding:6px 9px;border:1px solid #e8cf8a;border-radius:4px;"
    "background:#fff6e0;color:#5a3e00}"
    "a.iev-attachment img{outline:1px solid transparent}a.iev-attachment:hover img{outline-color:#1f5fbf}"
    "@media print{#iev-bar{display:none}}"
)


@dataclass(frozen=True)
class IndexRow:
    document: Document
    form_file: str
    data_file: str
    #: Tax year of the stylesheet used (or planned); ``None`` when there is none.
    stylesheet_year: int | None
    exact: bool
    error: str | None = None


def page(title: str, body: str, *, csp: str = STATIC_CSP, css: str = "") -> str:
    return (
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<meta http-equiv=\"Content-Security-Policy\" content=\"{escape(csp)}\">"
        "<meta name=\"referrer\" content=\"no-referrer\">"
        f"<title>{escape(title)}</title><style>{BASE_CSS}{css}</style></head>"
        f"<body>{body}</body></html>\n"
    )


def stylesheet_badge(row: IndexRow, ret: EfileReturn) -> str:
    if row.error:
        return f'<span class="badge bad" title="{escape(row.error)}">Form view failed</span>'
    if row.stylesheet_year is None:
        return '<span class="badge none">No IRS stylesheet</span>'
    if row.exact:
        return f'<span class="badge ok">IRS TY{row.stylesheet_year}</span>'
    return (
        f'<span class="badge warn" title="No TY{ret.schema_year} stylesheet is installed">'
        f"IRS TY{row.stylesheet_year} (nearest)</span>"
    )


def index_page(ret: EfileReturn, rows: Sequence[IndexRow], *, csp: str = STATIC_CSP) -> str:
    facts = [
        (ret.tin_kind or "TIN", ret.tin),
        ("Tax period", " – ".join(x for x in (ret.tax_period_begin, ret.tax_period_end) if x)),
        ("Return version", ret.return_version),
        ("Submitted", ret.timestamp),
        ("IRS object id", ret.object_id or ""),
        ("Source", ret.source_name),
    ]
    facts_html = "".join(
        f"<div><dt>{escape(k)}</dt><dd>{escape(v)}</dd></div>" for k, v in facts if v
    )
    body_rows = []
    for row in rows:
        doc = row.document
        body_rows.append(
            "<tr>"
            f"<td><strong>{escape(doc.title)}</strong><br><code>{escape(doc.name)}</code>"
            f' <span class="muted">{escape(doc.document_id)}</span></td>'
            f'<td><a href="{escape(row.form_file)}">Form view</a></td>'
            f'<td><a href="{escape(row.data_file)}">Data view</a></td>'
            f"<td>{stylesheet_badge(row, ret)}</td>"
            "</tr>"
        )
    fallback = [r for r in rows if r.stylesheet_year is not None and not r.exact and not r.error]
    note = ""
    if fallback:
        years = sorted({r.stylesheet_year for r in fallback if r.stylesheet_year is not None})
        note = (
            f'<p class="note">No TY{ret.schema_year} IRS stylesheet is installed for '
            f"{len(fallback)} document(s); they are drawn with the nearest year's "
            f"(TY{', TY'.join(map(str, years))}), so lines that differ between the years may be "
            "missing from those form views. The data views show every value as filed. Import the "
            "IRS stylesheet ZIP for this year with <code>irs-efile-viewer import-irs-zip</code>.</p>"
        )
    body = (
        '<main><p class="eyebrow">IRS e-file return</p>'
        f"<h1>{escape(ret.filer_name or 'Unknown filer')}</h1>"
        f'<p class="sub">{escape(ret.form_name)} · tax year {escape(ret.tax_year)}</p>'
        f'<dl class="facts">{facts_html}</dl>{note}'
        f"<h2>Documents ({len(rows)})</h2>"
        '<div class="table-wrap"><table><thead><tr><th>Document</th><th>Form</th><th>Data</th>'
        f"<th>Stylesheet</th></tr></thead><tbody>{''.join(body_rows)}</tbody></table></div>"
        '<p class="foot">Form views are drawn with the IRS Modernized e-File stylesheets for the '
        "return's tax year, the same transformation the IRS uses to display e-filed returns. "
        "Data views list every element of the filed XML.</p></main>"
    )
    return page(ret.title, body, csp=csp)


def form_toolbar(ret: EfileReturn, doc: Document, *, data_file: str, note: str = "") -> str:
    """The navigation strip placed above an IRS form (a ``<style>`` plus a ``<div>``)."""
    note_html = f'<div class="iev-note">{escape(note)}</div>' if note else ""
    return (
        f"<style>{_FORM_BAR_CSS}</style>"
        '<div id="iev-bar"><a href="index.html">&#8592; All documents</a>'
        f'<a href="{escape(data_file)}">Data view</a>'
        f'<span class="iev-where">{escape(ret.filer_name)} · {escape(doc.title)}</span>'
        f"{note_html}</div>"
    )


def home_page(*, years: Sequence[int], max_mb: int, error: str = "") -> str:
    installed = _year_ranges(years) if years else "none — form views are unavailable"
    error_html = f'<p class="error">{escape(error)}</p>' if error else ""
    example = "https://gt990datalake-rawdata.s3.amazonaws.com/EfileData/XmlFiles/201541349349307794_public.xml"
    body = (
        '<main><p class="eyebrow">IRS e-File Viewer</p><h1>See an e-filed return as the forms it was filed on</h1>'
        '<p class="sub">Upload or link an IRS Modernized e-File XML return — Form 990, 990-EZ, 990-PF, '
        "990-T, 1040, 1120, 1065 and more — and get every form and schedule rendered with the IRS's own "
        "stylesheets, plus a complete data view.</p>"
        f"{error_html}"
        '<h2>Upload a file</h2><form method="post" action="render" enctype="multipart/form-data">'
        '<p><input type="file" name="file" accept=".xml,application/xml,text/xml" required> '
        "<button type=\"submit\">Render</button></p></form>"
        '<h2>Or fetch from a URL</h2><form method="post" action="render">'
        f'<p><input type="url" name="url" required placeholder="{example}" '
        'style="width:min(100%,640px)"> <button type="submit">Render</button></p></form>'
        f'<p class="muted">Public 990-series filings by IRS object id: <code>{escape(example)}</code></p>'
        f'<p class="foot">Installed IRS stylesheets: {escape(installed)}. Uploads up to {max_mb} MB. '
        "Files are kept in memory only, for this server process.</p></main>"
    )
    return page("IRS e-File Viewer", body, csp=APP_CSP)


def error_page(title: str, message: str, *, back: str = "./") -> str:
    body = (
        f'<main><p class="eyebrow">IRS e-File Viewer</p><h1>{escape(title)}</h1>'
        f'<p class="error">{escape(message)}</p><p><a href="{escape(back)}">Back</a></p></main>'
    )
    return page(title, body, csp=APP_CSP)


def _year_ranges(years: Sequence[int]) -> str:
    ordered = sorted(set(years))
    spans: list[tuple[int, int]] = []
    for year in ordered:
        if spans and year == spans[-1][1] + 1:
            spans[-1] = (spans[-1][0], year)
        else:
            spans.append((year, year))
    return ", ".join(f"TY{a}" if a == b else f"TY{a}–TY{b}" for a, b in spans)
