"""Read an IRS Modernized e-File (MeF) return.

An e-file return is one ``<Return>`` document: a ``<ReturnHeader>`` describing the filer
and the submission, and a ``<ReturnData>`` holding one element per form, schedule or
supporting statement. The IRS stylesheets address that data with unqualified XPath, so
the default ``http://www.irs.gov/efile`` namespace has to go. It is removed here on the
parsed tree, not with a regex over the text, so the result does not depend on attribute
order, quote style or a namespace prefix.

Header element names changed with the TY2013 schemas (``TaxYear`` became ``TaxYr``,
``Timestamp`` became ``ReturnTs``, ``ReturnType`` became ``ReturnTypeCd``, the filer's
``Name/BusinessNameLine1`` became ``BusinessName/BusinessNameLine1Txt``). Every lookup
below accepts both spellings: a 2010 return has to read as well as a 2023 one.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from lxml import etree

EFILE_NAMESPACE = "http://www.irs.gov/efile"
_EFILE_PREFIX = "{" + EFILE_NAMESPACE + "}"

#: IRS object ids are the digits in a public file name: ``201541349349307794_public.xml``.
_OBJECT_ID = re.compile(r"(\d{9,})_public")
_FORM_NAME = re.compile(r"^IRS(?P<form>\d+[A-Z]*?)(?:Schedule(?P<schedule>[A-Z0-9]+))?$")


class EfileError(ValueError):
    """The input is not an IRS e-file return this tool can read."""


@dataclass(frozen=True, eq=False)
class Document:
    """One form, schedule or statement inside ``<ReturnData>``."""

    #: Element name, which is also the IRS stylesheet's file name (``IRS990ScheduleO``).
    name: str
    #: The ``documentId`` attribute: unique within a return, and what cross-references use.
    document_id: str
    #: Output file stem, unique within a return even when a document type repeats.
    stem: str
    element: etree._Element = field(repr=False)

    @property
    def title(self) -> str:
        return display_name(self.name)


@dataclass(frozen=True, eq=False)
class EfileReturn:
    """A parsed, namespace-free return plus the header facts rendering needs."""

    root: etree._Element = field(repr=False)
    header: etree._Element = field(repr=False)
    documents: tuple[Document, ...]
    #: ``returnVersion`` as filed, e.g. ``2014v5.0``.
    return_version: str
    #: The schema year that picks the stylesheet directory, e.g. ``2014``.
    schema_year: int
    tax_year: str
    return_type: str
    filer_name: str
    #: Formatted EIN (``20-1585919``) or SSN (``123-45-6789``); empty when absent.
    tin: str
    #: ``"EIN"``, ``"SSN"`` or ``""``.
    tin_kind: str
    timestamp: str
    tax_period_begin: str
    tax_period_end: str
    #: The IRS object id when the source name carries one (``…_public.xml``).
    object_id: str | None
    source_name: str

    @property
    def submission_date(self) -> str:
        return self.timestamp.split("T", 1)[0].strip()

    @property
    def form_name(self) -> str:
        return display_name("IRS" + self.return_type) if self.return_type else "Return"

    @property
    def title(self) -> str:
        return f"{self.filer_name or 'Unknown filer'} — {self.form_name}, tax year {self.tax_year}"

    def document(self, stem: str) -> Document | None:
        return next((d for d in self.documents if d.stem == stem), None)

    def by_document_id(self, document_id: str) -> Document | None:
        return next((d for d in self.documents if d.document_id == document_id), None)


def parse_return(data: bytes, *, source_name: str = "") -> EfileReturn:
    """Parse e-file XML bytes. Raises :class:`EfileError` for anything else.

    The parser never resolves entities, loads a DTD or touches the network, so a hostile
    upload cannot use XML features to read files or expand into gigabytes.
    """
    parser = etree.XMLParser(
        resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False
    )
    try:
        parsed = etree.fromstring(data, parser)
    except etree.XMLSyntaxError as exc:
        raise EfileError(f"not well-formed XML: {exc}") from exc
    if parsed is None:
        raise EfileError("empty document")

    _strip_efile_namespace(parsed)
    ret = parsed if parsed.tag == "Return" else parsed.find(".//Return")
    if ret is None:
        raise EfileError(
            f"expected an IRS e-file <Return> document, found <{_local(parsed.tag)}>"
        )
    header = ret.find("ReturnHeader")
    return_data = ret.find("ReturnData")
    if header is None or return_data is None:
        raise EfileError("the <Return> has no ReturnHeader/ReturnData")

    filer = header.find("Filer")
    return_version = (ret.get("returnVersion") or "").strip()
    tax_year = _first_text(header, "TaxYr", "TaxYear")
    year_match = re.match(r"\s*(\d{4})", return_version) or re.match(r"(\d{4})", tax_year)
    if year_match is None:
        raise EfileError("the return carries neither returnVersion nor a tax year")
    schema_year = int(year_match.group(1))

    match = _OBJECT_ID.search(source_name)
    tin, tin_kind = _filer_tin(filer)
    return EfileReturn(
        root=ret,
        header=header,
        documents=_documents(return_data),
        return_version=return_version,
        schema_year=schema_year,
        tax_year=tax_year or str(schema_year),
        return_type=_first_text(header, "ReturnTypeCd", "ReturnType"),
        filer_name=_filer_name(filer),
        tin=tin,
        tin_kind=tin_kind,
        timestamp=_first_text(header, "ReturnTs", "Timestamp"),
        tax_period_begin=_first_text(header, "TaxPeriodBeginDt", "TaxPeriodBeginDate"),
        tax_period_end=_first_text(header, "TaxPeriodEndDt", "TaxPeriodEndDate"),
        object_id=match.group(1) if match else None,
        source_name=source_name,
    )


def display_name(name: str) -> str:
    """``IRS990ScheduleA`` → ``Schedule A (Form 990)``; ``OtherExpensesSchedule`` →
    ``Other Expenses Schedule``."""
    match = _FORM_NAME.match(name)
    if match:
        form = re.sub(r"^(\d+)([A-Z]+)$", r"\1-\2", match.group("form"))
        schedule = match.group("schedule")
        if schedule:
            schedule = re.sub(r"^([A-Z]+)(\d+)$", r"\1-\2", schedule)
            return f"Schedule {schedule} (Form {form})"
        return f"Form {form}"
    words = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[A-Za-z])(?=\d)", " ", name)
    return words


def format_tin(digits: str, kind: str) -> str:
    raw = re.sub(r"\D", "", digits)
    if kind == "EIN" and len(raw) == 9:
        return f"{raw[:2]}-{raw[2:]}"
    if kind == "SSN" and len(raw) == 9:
        return f"{raw[:3]}-{raw[3:5]}-{raw[5:]}"
    return digits.strip()


def _strip_efile_namespace(root: etree._Element) -> None:
    for el in root.iter():
        if not isinstance(el.tag, str):  # comments and processing instructions
            continue
        if el.tag.startswith(_EFILE_PREFIX):
            el.tag = el.tag[len(_EFILE_PREFIX):]
        for name in [n for n in el.attrib if n.startswith(_EFILE_PREFIX)]:
            value = el.attrib.pop(name)
            el.attrib[name[len(_EFILE_PREFIX):]] = value
    etree.cleanup_namespaces(root)


def _documents(return_data: etree._Element) -> tuple[Document, ...]:
    seen: Counter[str] = Counter()
    ids: set[str] = set()
    documents = []
    for child in return_data:
        if not isinstance(child.tag, str):
            continue
        name = _local(child.tag)
        seen[name] += 1
        stem = name if seen[name] == 1 else f"{name}-{seen[name]}"
        document_id = (child.get("documentId") or "").strip() or stem
        if document_id in ids:  # malformed, but a cross-reference must stay unambiguous
            document_id = f"{document_id}-{stem}"
        ids.add(document_id)
        documents.append(Document(name=name, document_id=document_id, stem=stem, element=child))
    return tuple(documents)


def _filer_name(filer: etree._Element | None) -> str:
    if filer is None:
        return ""
    return _first_text(
        filer,
        "BusinessName/BusinessNameLine1Txt",
        "Name/BusinessNameLine1",
        "BusinessName/BusinessNameLine1",
        "NameLine1Txt",
        "Name/NameLine1",
        ".//BusinessNameLine1Txt",
        ".//BusinessNameLine1",
        ".//NameLine1Txt",
        ".//PersonNm",
    )


def _filer_tin(filer: etree._Element | None) -> tuple[str, str]:
    if filer is None:
        return "", ""
    ein = _first_text(filer, "EIN")
    if ein:
        return format_tin(ein, "EIN"), "EIN"
    ssn = _first_text(filer, "PrimarySSN", "SSN")
    return (format_tin(ssn, "SSN"), "SSN") if ssn else ("", "")


def _first_text(base: etree._Element, *paths: str) -> str:
    for path in paths:
        el = base.find(path)
        if el is not None:
            text = "".join(el.itertext()).strip()
            if text:
                return text
    return ""


def _local(tag: object) -> str:
    text = str(tag)
    return text.split("}", 1)[1] if text.startswith("{") else text
