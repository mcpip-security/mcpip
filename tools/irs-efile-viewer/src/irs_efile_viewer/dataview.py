"""A complete, readable view of one e-file document, straight from the XML.

The IRS stylesheet is the authoritative picture of a form, but it only shows what its tax
year's form has a line for: a TY2023 return drawn with the TY2021 stylesheet silently
loses anything added since, and some documents have no stylesheet at all. This view needs
none. Every element and attribute is shown, labelled from its element name (which stays
available as a tooltip), with amounts grouped, check-box indicators drawn as boxes and
repeating groups laid out as tables.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from html import escape

from lxml import etree

from . import pages
from .efile import Document, EfileReturn, format_tin

_TOKENS = re.compile(r"\d+[a-z]+\d*|[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|[A-Z]+|\d+")
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")
_AMOUNT = re.compile(r"(?:Amt|Amount)$")
_INDICATOR = re.compile(r"(?:Ind|Indicator)$")
#: IRS schema abbreviations, spelled out. An empty string drops a type suffix.
_WORDS = {
    "Amt": "", "Txt": "", "Ind": "", "Grp": "", "Cd": "code", "Dt": "date", "Nm": "name",
    "Num": "number", "Cnt": "count", "Pct": "percent", "Rt": "rate", "Qty": "quantity",
    "Desc": "description", "CY": "current year", "PY": "prior year", "BOY": "beginning of year",
    "EOY": "end of year", "Org": "organization", "Orgs": "organizations", "Expns": "expenses",
    "Rev": "revenue", "Govt": "government", "Oth": "other", "Tot": "total", "Prgm": "program",
    "Srvc": "service", "Svc": "service", "Addr": "address", "Ln": "line", "Sch": "schedule",
    "Pymt": "payment", "Pymts": "payments", "Contri": "contribution", "Contrib": "contribution",
    "Comp": "compensation", "Empl": "employee", "Ofcr": "officer", "Prsn": "person",
    "Rltd": "related", "Bnft": "benefit", "Bnfts": "benefits", "Invst": "investment",
    "Liab": "liabilities", "Mbr": "member", "Mgmt": "management", "Fndtn": "foundation",
    "Fdtn": "foundation", "Acct": "account", "Avg": "average", "Hrs": "hours", "Wk": "week",
    "Prev": "previous", "Yr": "year", "Yrs": "years", "Ttl": "title", "Explntn": "explanation",
    "Expln": "explanation", "Dsclsr": "disclosure", "Rcvd": "received", "Rcpts": "receipts",
    "Info": "information", "Prep": "preparer", "Indiv": "individual", "Natl": "national",
    "Sec": "section", "Dpst": "deposit", "Distrib": "distribution", "Excs": "excess",
}
_CSS = """
.wrap{max-width:1080px;margin:0 auto;padding:20px 16px 56px}
dl.fields{display:grid;grid-template-columns:minmax(180px,38%) 1fr;margin:0;border-top:1px solid var(--line)}
dl.fields>div{display:contents}
dl.fields dt,dl.fields dd{margin:0;padding:6px 10px;border-bottom:1px solid var(--line)}
dl.fields dt{color:var(--muted);overflow-wrap:anywhere}
dl.fields dd{white-space:pre-wrap;overflow-wrap:anywhere}
section.group{margin:14px 0 0;padding:0 0 0 12px;border-left:3px solid var(--line)}
section.group>h3{font-size:.95rem;margin:0 0 6px;padding-top:4px}
.attr{display:inline-block;margin-left:8px;font-size:.75rem;color:var(--muted);font-weight:400}
.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.box{font-size:1.05em}
caption{text-align:left;font-weight:600;padding:8px 12px}
td.cell{white-space:pre-wrap;overflow-wrap:anywhere}
.empty{color:var(--muted)}
@media (max-width:640px){dl.fields{grid-template-columns:1fr}dl.fields dt{border-bottom:0;padding-bottom:0}}
"""


def render(
    ret: EfileReturn,
    doc: Document,
    *,
    links: Mapping[str, str],
    form_file: str | None,
    note: str = "",
) -> str:
    """The data view page for ``doc``."""
    nav = ['<a href="index.html">&#8592; All documents</a>']
    if form_file:
        nav.append(f'<a href="{escape(form_file)}">Form view</a>')
    nav.append(f'<span class="here">{escape(ret.filer_name)} · {escape(doc.title)}</span>')
    facts = [
        (ret.tin_kind or "TIN", ret.tin),
        ("Tax year", ret.tax_year),
        ("Document", f"{doc.name} · {doc.document_id}"),
        ("Return version", ret.return_version),
    ]
    facts_html = "".join(f"<div><dt>{escape(k)}</dt><dd>{escape(v)}</dd></div>" for k, v in facts if v)
    note_html = f'<p class="note">{escape(note)}</p>' if note else ""
    body = (
        f'<nav class="nav">{"".join(nav)}</nav><div class="wrap">'
        f'<p class="eyebrow">Data view — every value as filed</p><h1>{escape(doc.title)}</h1>'
        f'<p class="sub">{escape(ret.filer_name)}</p><dl class="facts">{facts_html}</dl>{note_html}'
        f"{_attributes(doc.element, links, skip={'documentId'})}"
        f"<h2>Contents</h2>{_children(doc.element, links)}</div>"
    )
    return pages.page(f"{doc.title} — {ret.filer_name} (data)", body, css=_CSS)


def label(name: str) -> str:
    """``CYTotalRevenueAmt`` → ``Current year total revenue``."""
    words = []
    for token in _TOKENS.findall(name):
        word = _WORDS.get(token, token if token.isupper() or token[0].isdigit() else token.lower())
        if word:
            words.append(word)
    text = " ".join(words) or name
    return text[0].upper() + text[1:]


def value_html(name: str, text: str) -> str:
    value = text.strip()
    if not value:
        return '<span class="empty">—</span>'
    if _AMOUNT.search(name) and _NUMBER.fullmatch(value):
        whole, _, fraction = value.partition(".")
        grouped = f"{int(whole):,}" + (f".{fraction}" if fraction else "")
        return f'<span class="num">{grouped}</span>'
    if _INDICATOR.search(name):
        lowered = value.lower()
        if lowered in {"x", "1", "true", "yes"}:
            return '<span class="box" aria-label="checked">&#9746;</span> Yes'
        if lowered in {"0", "false", "no"}:
            return '<span class="box" aria-label="unchecked">&#9744;</span> No'
    if name.endswith("EIN"):
        return escape(format_tin(value, "EIN"))
    if name.endswith("SSN"):
        return escape(format_tin(value, "SSN"))
    return escape(value)


def _children(el: etree._Element, links: Mapping[str, str]) -> str:
    children = _elements(el)
    out: list[str] = []
    fields: list[str] = []

    def flush() -> None:
        if fields:
            out.append(f'<dl class="fields">{"".join(fields)}</dl>')
            fields.clear()

    i = 0
    while i < len(children):
        run = [children[i]]
        while i + len(run) < len(children) and children[i + len(run)].tag == children[i].tag:
            run.append(children[i + len(run)])
        if len(run) > 1 and any(_elements(c) for c in run):
            flush()
            out.append(_table(run, links))
        else:
            for child in run:
                if _elements(child):
                    flush()
                    out.append(
                        f'<section class="group"><h3 title="{escape(child.tag)}">{escape(label(child.tag))}'
                        f"{_attributes(child, links)}</h3>{_children(child, links)}</section>"
                    )
                else:
                    fields.append(_field(child, links))
        i += len(run)
    flush()
    return "".join(out) or '<p class="empty">No content.</p>'


def _field(el: etree._Element, links: Mapping[str, str]) -> str:
    return (
        f'<div><dt title="{escape(el.tag)}">{escape(label(el.tag))}</dt>'
        f"<dd>{value_html(el.tag, el.text or '')}{_attributes(el, links)}</dd></div>"
    )


def _table(rows: list[etree._Element], links: Mapping[str, str]) -> str:
    columns: list[str] = []
    for row in rows:
        for child in _elements(row):
            if child.tag not in columns:
                columns.append(child.tag)
    head = "".join(f'<th title="{escape(c)}">{escape(label(c))}</th>' for c in columns)
    body = []
    for n, row in enumerate(rows, 1):
        cells = [f'<td class="num">{n}{_attributes(row, links)}</td>']
        for column in columns:
            values = [_compact(c) for c in _elements(row) if c.tag == column]
            cells.append(f'<td class="cell">{"<br>".join(values)}</td>')
        body.append(f"<tr>{''.join(cells)}</tr>")
    caption = f"{escape(label(rows[0].tag))} ({len(rows)})"
    return (
        f'<div class="table-wrap" style="margin-top:14px"><table><caption title="{escape(rows[0].tag)}">'
        f"{caption}</caption><thead><tr><th>#</th>{head}</tr></thead><tbody>{''.join(body)}</tbody></table></div>"
    )


def _compact(el: etree._Element) -> str:
    """A nested group in a table cell: its leaf values, comma-joined (addresses, names)."""
    if not _elements(el):
        return value_html(el.tag, el.text or "")
    leaves = [e for e in el.iter() if isinstance(e.tag, str) and not _elements(e) and (e.text or "").strip()]
    return ", ".join(value_html(e.tag, e.text or "") for e in leaves) or '<span class="empty">—</span>'


def _attributes(el: etree._Element, links: Mapping[str, str], *, skip: set[str] | None = None) -> str:
    parts = []
    for name, value in el.attrib.items():
        if skip and name in skip:
            continue
        if name == "referenceDocumentId":
            refs = []
            for ref in value.split():
                target = links.get(ref)
                refs.append(f'<a href="{escape(target)}">{escape(ref)}</a>' if target else escape(ref))
            parts.append(f'<span class="attr">attachment: {" ".join(refs)}</span>')
        else:
            parts.append(f'<span class="attr">{escape(str(name))}={escape(value)}</span>')
    return "".join(parts)


def _elements(el: etree._Element) -> list[etree._Element]:
    return [c for c in el if isinstance(c.tag, str)]
