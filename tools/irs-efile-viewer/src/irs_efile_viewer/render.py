"""Render an e-file return: each document through its IRS stylesheet, plus a data view.

The IRS stylesheets do not read a return directly. They expect the envelope of the IRS
display application, ``<AppData>``, with the header and the one document being shown
under ``SubmissionHeaderAndDocument`` and display parameters beside them (CommonPathRef.xsl
binds ``$RtnHdrData`` and ``$RtnDoc`` to exactly those paths). :func:`build_envelope`
builds that envelope; libxslt then runs the stylesheet on the server, so nothing here
depends on a browser's XSLT engine — Chrome removes its own in November 2026.

Every document gets two pages: ``<stem>.html`` (the form view, or the data view with an
explanation when no stylesheet can draw it, so links never dangle) and
``<stem>.data.html`` (every value as filed). ``index.html`` lists them.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from lxml import etree

from . import dataview, pages, postprocess
from .efile import Document, EfileReturn
from .mef import MefStore, StylesheetChoice
from .pages import IndexRow

#: Display preferences the stylesheets may consult; values from the IRS default profile.
_VIEW_PREFERENCES = (
    ("ShowReturnSummaryOnStartup", "true"),
    ("DefaultZoomLevel", "100%"),
    ("ReturnTreeMouseoverBgColor", "khaki"),
    ("ReturnTreeSelectedItemBgColor", "gold"),
    ("ErrorFieldBgColor", "Tomato"),
    ("ChangedFieldBgColor", "Khaki"),
    ("TableHeaderBgColor", "slategray"),
    ("TableRow1BgColor", "#8cdaff"),
    ("TableRow2BgColor", "#d9f2ff"),
    ("SingleReturnAutoDisplay", "true"),
    ("StartUpDataStage", "Latest"),
)


class RenderError(RuntimeError):
    """No stylesheet could draw a document."""


@dataclass
class FormResult:
    html: str
    stylesheet: StylesheetChoice | None
    error: str | None = None


@dataclass
class Rendering:
    """All pages of one rendered return, keyed by file name."""

    ret: EfileReturn
    pages: dict[str, str]
    rows: list[IndexRow] = field(default_factory=list)

    def write(self, directory: str | Path) -> list[Path]:
        out = Path(directory)
        out.mkdir(parents=True, exist_ok=True)
        written = []
        for name, html in self.pages.items():
            path = out / name
            path.write_text(html, encoding="utf-8")
            written.append(path)
        return written

    @property
    def failures(self) -> list[IndexRow]:
        return [r for r in self.rows if r.error]

    @property
    def approximations(self) -> list[IndexRow]:
        """Documents drawn without a stylesheet of their own tax year."""
        return [r for r in self.rows if not r.error and (r.stylesheet_year is None or not r.exact)]


def form_file(doc: Document) -> str:
    return f"{doc.stem}.html"


def data_file(doc: Document) -> str:
    return f"{doc.stem}.data.html"


def build_envelope(ret: EfileReturn, doc: Document) -> etree._ElementTree:
    """The ``<AppData>`` document the IRS stylesheets transform, for one document."""
    app = etree.Element("AppData")
    props = etree.SubElement(app, "ApplicationProperties")
    if ret.object_id:
        original, mode = f"ObjectId: {ret.object_id}", f"Submission: {ret.submission_date}"
    else:
        original, mode = "Submission Date", ret.submission_date
    _text(props, "FormHeaderGeneric", " efile Public Visual Render ")
    _text(props, "FormHeaderOriginalData", original)
    _text(props, "SystemMode", mode)
    _text(props, "PrintoutWindowResizable", "false")

    view = etree.SubElement(etree.SubElement(app, "UserPreferences"), "View")
    for name, value in _VIEW_PREFERENCES:
        _text(view, name, value)

    params = etree.SubElement(app, "Parameters")
    version = ret.return_version or str(ret.schema_year)
    for name, value in (
        ("Stage", "original"),
        ("DLN", ""),
        ("DLNLatest", ""),
        ("DLNChanged", ""),
        ("TIN", ret.tin),
        ("TINLatest", ret.tin),
        ("TINChanged", ""),
        ("TaxpayerPrint", "false"),
        ("Print", ""),
        ("DocumentId", doc.document_id),
        ("ReturnVersion", version),
        ("ZoomLevel", "100%"),
        ("DisplayName", "IRS e-File Viewer"),
        ("Regulation", ""),
        ("Location", "RET"),
        ("LocationSeq", "1"),
        ("SubmissionVersion", version),
        ("TaxYear", ret.tax_year),
        ("SubmissionType", ret.return_type),
    ):
        _text(params, name, value)

    holder = etree.SubElement(app, "SubmissionHeaderAndDocument")
    header = copy.deepcopy(ret.header)
    header.tail = None
    holder.append(header)
    document = copy.deepcopy(doc.element)
    document.tail = None
    etree.SubElement(holder, "SubmissionDocument").append(document)
    return etree.ElementTree(app)


class Renderer:
    """Renders documents of returns against one stylesheet tree (or none: data only)."""

    def __init__(self, store: MefStore | None) -> None:
        self.store = store

    def candidates(self, ret: EfileReturn, doc: Document) -> list[StylesheetChoice]:
        return self.store.candidates(doc.name, ret.schema_year) if self.store else []

    def links(self, ret: EfileReturn) -> dict[str, str]:
        """``documentId`` → the page that shows it (cross-references point here)."""
        return {doc.document_id: form_file(doc) for doc in ret.documents}

    def render_form(self, ret: EfileReturn, doc: Document) -> tuple[str, StylesheetChoice]:
        """The IRS form view. Tries the best stylesheet first, then the next-nearest years
        if one fails to compile or to transform. Raises :class:`RenderError`."""
        if self.store is None:
            raise RenderError("no IRS stylesheets are installed")
        errors = []
        for choice in self.candidates(ret, doc):
            try:
                xslt, lock = self.store.compile(choice)
                with lock:
                    result = xslt(build_envelope(ret, doc))
                text = str(result)
            except (etree.XSLTError, etree.XMLSyntaxError, OSError) as exc:
                errors.append(f"TY{choice.year}: {_first_line(exc)}")
                continue
            if not text.strip():
                errors.append(f"TY{choice.year}: the stylesheet produced no output")
                continue
            note = ""
            if not choice.exact:
                note = (
                    f"No TY{ret.schema_year} IRS stylesheet for this form is installed, so it is drawn "
                    f"with the TY{choice.year} one: lines that differ between the two years may be "
                    "missing here. The data view has every value as filed."
                )
            try:
                html = postprocess.finalize(
                    text,
                    store=self.store,
                    year_hint=choice.year,
                    links=self.links(ret),
                    toolbar=pages.form_toolbar(ret, doc, data_file=data_file(doc), note=note),
                )
            except (etree.LxmlError, ValueError) as exc:
                errors.append(f"TY{choice.year}: unusable output ({_first_line(exc)})")
                continue
            return html, choice
        if not errors:
            raise RenderError(f"no IRS stylesheet named {doc.name}.xsl is installed")
        raise RenderError("; ".join(errors))

    def render_data(self, ret: EfileReturn, doc: Document, *, note: str = "", with_form_link: bool = True) -> str:
        return dataview.render(
            ret, doc, links=self.links(ret), form_file=form_file(doc) if with_form_link else None, note=note
        )

    def render_view(self, ret: EfileReturn, doc: Document) -> FormResult:
        """What ``<stem>.html`` shows: the form view, or the data view and why."""
        try:
            html, choice = self.render_form(ret, doc)
            return FormResult(html=html, stylesheet=choice)
        except RenderError as exc:
            if self.store is None or not self.candidates(ret, doc):
                reason = f"There is no IRS stylesheet for {doc.name}; showing the data view."
                return FormResult(self.render_data(ret, doc, note=reason, with_form_link=False), None)
            reason = f"The IRS stylesheet could not draw this document ({exc}); showing the data view."
            return FormResult(self.render_data(ret, doc, note=reason, with_form_link=False), None, str(exc))

    def index_rows(self, ret: EfileReturn) -> list[IndexRow]:
        """Index rows from the stylesheet plan, before anything is rendered."""
        rows = []
        for doc in ret.documents:
            best = next(iter(self.candidates(ret, doc)), None)
            rows.append(
                IndexRow(
                    document=doc,
                    form_file=form_file(doc),
                    data_file=data_file(doc),
                    stylesheet_year=best.year if best else None,
                    exact=bool(best and best.exact),
                )
            )
        return rows

    def render_all(self, ret: EfileReturn, *, only: Iterable[str] = ()) -> Rendering:
        """Every page of the return (or of the documents named in ``only``)."""
        wanted = set(only)
        rendering = Rendering(ret=ret, pages={})
        for doc in ret.documents:
            if wanted and doc.name not in wanted and doc.stem not in wanted:
                continue
            view = self.render_view(ret, doc)
            rendering.pages[form_file(doc)] = view.html
            rendering.pages[data_file(doc)] = self.render_data(
                ret, doc, with_form_link=view.stylesheet is not None
            )
            rendering.rows.append(
                IndexRow(
                    document=doc,
                    form_file=form_file(doc),
                    data_file=data_file(doc),
                    stylesheet_year=view.stylesheet.year if view.stylesheet else None,
                    exact=bool(view.stylesheet and view.stylesheet.exact),
                    error=view.error,
                )
            )
        rendering.pages["index.html"] = pages.index_page(ret, rendering.rows)
        return rendering


def _text(parent: etree._Element, name: str, value: str) -> None:
    etree.SubElement(parent, name).text = value


def _first_line(exc: BaseException) -> str:
    text = str(exc).strip() or type(exc).__name__
    return text.splitlines()[0][:300]
