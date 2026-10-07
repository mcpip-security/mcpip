"""The data view: every value, readable labels, tables for repeating groups, escaping."""

from __future__ import annotations

import lxml.html
import pytest
from irs_efile_helpers import efile_xml

from irs_efile_viewer import dataview
from irs_efile_viewer.efile import parse_return

DOC = (
    '<IRS990 documentId="RetDoc1">'
    "<CYTotalRevenueAmt>1726766</CYTotalRevenueAmt><NetIncomeAmt>-2500.50</NetIncomeAmt>"
    "<Organization501c3Ind>X</Organization501c3Ind><GroupReturnForAffiliatesInd>0</GroupReturnForAffiliatesInd>"
    "<MissionDesc>Line one\nLine two &lt;b&gt;not bold&lt;/b&gt;</MissionDesc>"
    "<PreparerFirmEIN>330885895</PreparerFirmEIN>"
    '<OtherExpensesGrp referenceDocumentId="RetDoc2"><TotalAmt>15</TotalAmt></OtherExpensesGrp>'
    "<Form990PartVIISectionAGrp><PersonNm>ANN ALPERT</PersonNm><TitleTxt>CFO</TitleTxt>"
    "<ReportableCompFromOrgAmt>120000</ReportableCompFromOrgAmt></Form990PartVIISectionAGrp>"
    "<Form990PartVIISectionAGrp><PersonNm>SCOTT LEWIS</PersonNm><TitleTxt>CEO</TitleTxt>"
    "<ReportableCompFromOrgAmt>150000</ReportableCompFromOrgAmt>"
    "<USAddress><CityNm>SAN DIEGO</CityNm><StateAbbreviationCd>CA</StateAbbreviationCd></USAddress>"
    "</Form990PartVIISectionAGrp>"
    "</IRS990>"
    '<OtherExpensesSchedule documentId="RetDoc2"/>'
)


@pytest.fixture
def page() -> lxml.html.HtmlElement:
    ret = parse_return(efile_xml(documents=DOC))
    html = dataview.render(
        ret, ret.documents[0], links={"RetDoc2": "OtherExpensesSchedule.html"}, form_file="IRS990.html"
    )
    return lxml.html.document_fromstring(html)


def _field(page: lxml.html.HtmlElement, element: str) -> str:
    (dd,) = page.xpath(f"//dt[@title='{element}']/following-sibling::dd[1]")
    return dd.text_content()


def test_values_are_formatted_by_type(page: lxml.html.HtmlElement) -> None:
    assert _field(page, "CYTotalRevenueAmt") == "1,726,766"
    assert _field(page, "NetIncomeAmt") == "-2,500.50"
    assert _field(page, "Organization501c3Ind") == "☒ Yes"
    assert _field(page, "GroupReturnForAffiliatesInd") == "☐ No"
    assert _field(page, "PreparerFirmEIN") == "33-0885895"


def test_text_is_escaped_and_keeps_its_lines(page: lxml.html.HtmlElement) -> None:
    assert _field(page, "MissionDesc") == "Line one\nLine two <b>not bold</b>"
    assert page.xpath("//b") == []


def test_labels_spell_out_the_schema_names(page: lxml.html.HtmlElement) -> None:
    assert page.xpath("//dt[@title='CYTotalRevenueAmt']")[0].text_content() == "Current year total revenue"
    assert page.xpath("//dt[@title='Organization501c3Ind']")[0].text_content() == "Organization 501c3"


def test_repeating_groups_become_a_table(page: lxml.html.HtmlElement) -> None:
    (table,) = page.xpath("//table[caption[@title='Form990PartVIISectionAGrp']]")
    headers = [th.get("title") for th in table.xpath(".//th[@title]")]
    assert headers == ["PersonNm", "TitleTxt", "ReportableCompFromOrgAmt", "USAddress"]
    rows = [[td.text_content() for td in tr.xpath("td")] for tr in table.xpath(".//tbody/tr")]
    assert rows == [
        ["1", "ANN ALPERT", "CFO", "120,000", ""],
        ["2", "SCOTT LEWIS", "CEO", "150,000", "SAN DIEGO, CA"],
    ]


def test_references_link_to_the_attached_document(page: lxml.html.HtmlElement) -> None:
    assert page.xpath("//a[text()='RetDoc2']/@href") == ["OtherExpensesSchedule.html"]


def test_navigation(page: lxml.html.HtmlElement) -> None:
    assert page.xpath("//nav/a/@href") == ["index.html", "IRS990.html"]
    assert page.xpath("//script") == []


@pytest.mark.parametrize(
    "name, expected",
    [
        ("TotalAssetsEOYAmt", "Total assets end of year"),
        ("BusinessNameLine1Txt", "Business name line 1"),
        ("USAddress", "US address"),
        ("PrincipalOfficerNm", "Principal officer name"),
        ("GrossReceipts", "Gross receipts"),
    ],
)
def test_label(name: str, expected: str) -> None:
    assert dataview.label(name) == expected
