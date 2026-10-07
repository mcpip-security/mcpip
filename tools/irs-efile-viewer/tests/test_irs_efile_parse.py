"""Reading e-file returns: header names across schema eras, namespaces, hostile XML."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from irs_efile_helpers import efile_xml

from irs_efile_viewer.efile import EfileError, display_name, parse_return


def test_reads_a_modern_header() -> None:
    ret = parse_return(efile_xml(), source_name="201541349349307794_public.xml")
    assert ret.filer_name == "EXAMPLE ORG"
    assert (ret.tin, ret.tin_kind) == ("20-1585919", "EIN")
    assert (ret.return_version, ret.schema_year, ret.tax_year) == ("2014v5.0", 2014, "2014")
    assert ret.return_type == "990"
    assert ret.submission_date == "2015-05-14"
    assert (ret.tax_period_begin, ret.tax_period_end) == ("2014-01-01", "2014-12-31")
    assert ret.object_id == "201541349349307794"
    assert ret.title == "EXAMPLE ORG — Form 990, tax year 2014"
    assert [(d.name, d.document_id, d.stem) for d in ret.documents] == [("IRSTEST", "RetDoc1", "IRSTEST")]


def test_reads_pre_2013_header_names() -> None:
    """TY2012 and earlier say TaxYear/Timestamp/ReturnType/Name/BusinessNameLine1. The
    original browser viewer only knew TaxYr, so it could not open these returns at all."""
    header = (
        "<Timestamp>2011-11-14T10:00:00-05:00</Timestamp><TaxPeriodEndDate>2010-12-31</TaxPeriodEndDate>"
        "<ReturnType>990</ReturnType><TaxPeriodBeginDate>2010-01-01</TaxPeriodBeginDate>"
        "<Filer><EIN>123456789</EIN><Name><BusinessNameLine1>OLD SCHEMA ORG</BusinessNameLine1></Name></Filer>"
        "<TaxYear>2010</TaxYear>"
    )
    ret = parse_return(efile_xml(version="2010v3.2", header=header))
    assert (ret.filer_name, ret.tin, ret.tax_year, ret.return_type) == ("OLD SCHEMA ORG", "12-3456789", "2010", "990")
    assert ret.submission_date == "2011-11-14"
    assert (ret.tax_period_begin, ret.tax_period_end) == ("2010-01-01", "2010-12-31")


def test_individual_filer_ssn() -> None:
    header = "<ReturnTypeCd>1040</ReturnTypeCd><Filer><PrimarySSN>123456789</PrimarySSN><NameLine1Txt>JANE DOE</NameLine1Txt></Filer><TaxYr>2021</TaxYr>"
    ret = parse_return(efile_xml(version="2021v5.2", header=header))
    assert (ret.tin, ret.tin_kind, ret.filer_name, ret.form_name) == ("123-45-6789", "SSN", "JANE DOE", "Form 1040")


@pytest.mark.parametrize(
    "xml",
    [
        # xmlns after another attribute and single-quoted: the browser viewer's regex missed both
        b"<Return returnVersion='2014v5.0' xmlns='http://www.irs.gov/efile'><ReturnHeader><TaxYr>2014</TaxYr>"
        b"</ReturnHeader><ReturnData><IRSTEST documentId='RetDoc1'/></ReturnData></Return>",
        # prefixed namespace
        b'<efile:Return xmlns:efile="http://www.irs.gov/efile" returnVersion="2014v5.0"><efile:ReturnHeader>'
        b"<efile:TaxYr>2014</efile:TaxYr></efile:ReturnHeader><efile:ReturnData><efile:IRSTEST documentId='RetDoc1'/>"
        b"</efile:ReturnData></efile:Return>",
        # no namespace at all
        b"<Return returnVersion='2014v5.0'><ReturnHeader/><ReturnData><IRSTEST documentId='RetDoc1'/></ReturnData></Return>",
        # byte order mark
        b"\xef\xbb\xbf" + efile_xml(),
    ],
)
def test_namespace_is_removed_however_it_is_written(xml: bytes) -> None:
    ret = parse_return(xml)
    assert ret.root.tag == "Return" and ret.documents[0].element.tag == "IRSTEST"
    assert all("}" not in el.tag for el in ret.root.iter() if isinstance(el.tag, str))
    assert ret.schema_year == 2014


def test_repeated_document_types_get_distinct_stems_and_ids() -> None:
    docs = (
        '<IRS1099 documentId="A"/><IRS1099 documentId="B"/><IRS1099 documentId="B"/><Other/>'
    )
    ret = parse_return(efile_xml(documents=docs))
    assert [d.stem for d in ret.documents] == ["IRS1099", "IRS1099-2", "IRS1099-3", "Other"]
    ids = [d.document_id for d in ret.documents]
    assert len(set(ids)) == len(ids) and ids[:2] == ["A", "B"]
    assert ret.by_document_id("A") is ret.documents[0]


@pytest.mark.parametrize(
    "data, message",
    [
        (b"<html><body>hi</body></html>", "expected an IRS e-file <Return>"),
        (b"<Return><ReturnHeader/></Return>", "no ReturnHeader/ReturnData"),
        (b"not xml at all", "not well-formed"),
        (b"<Return><ReturnHeader/><ReturnData/></Return>", "neither returnVersion nor a tax year"),
    ],
)
def test_rejects_what_is_not_a_return(data: bytes, message: str) -> None:
    with pytest.raises(EfileError, match=message):
        parse_return(data)


def test_external_entities_are_never_resolved(tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-VALUE")
    xml = (
        f'<?xml version="1.0"?><!DOCTYPE Return [<!ENTITY x SYSTEM "{secret.as_uri()}">]>'
        '<Return returnVersion="2014v5.0"><ReturnHeader><Filer><BusinessName><BusinessNameLine1Txt>&x;'
        "</BusinessNameLine1Txt></BusinessName></Filer></ReturnHeader><ReturnData/></Return>"
    ).encode()
    ret = parse_return(xml)
    from lxml import etree

    assert "TOP-SECRET-VALUE" not in etree.tostring(ret.root, encoding="unicode")
    assert "TOP-SECRET-VALUE" not in ret.filer_name


def test_entity_expansion_bomb_is_inert() -> None:
    entities = '<!ENTITY a0 "xxxxxxxxxx">' + "".join(
        f'<!ENTITY a{i} "{("&a" + str(i - 1) + ";") * 10}">' for i in range(1, 10)
    )
    xml = (
        f'<?xml version="1.0"?><!DOCTYPE Return [{entities}]><Return returnVersion="2014v5.0">'
        "<ReturnHeader><Filer><EIN>&a9;</EIN></Filer></ReturnHeader><ReturnData/></Return>"
    ).encode()
    started = time.monotonic()
    try:
        ret = parse_return(xml)
    except EfileError:
        return  # refusing it is fine too
    assert time.monotonic() - started < 2
    assert len(ret.tin) < 1000


@pytest.mark.parametrize(
    "name, expected",
    [
        ("IRS990", "Form 990"),
        ("IRS990EZ", "Form 990-EZ"),
        ("IRS990PF", "Form 990-PF"),
        ("IRS990T", "Form 990-T"),
        ("IRS990ScheduleA", "Schedule A (Form 990)"),
        ("IRS1065ScheduleK1", "Schedule K-1 (Form 1065)"),
        ("IRS1120SScheduleK1", "Schedule K-1 (Form 1120-S)"),
        ("IRS1120ScheduleM3", "Schedule M-3 (Form 1120)"),
        ("OtherExpensesSchedule", "Other Expenses Schedule"),
        ("InvestmentsOtherSchedule2", "Investments Other Schedule 2"),
    ],
)
def test_display_names(name: str, expected: str) -> None:
    assert display_name(name) == expected
