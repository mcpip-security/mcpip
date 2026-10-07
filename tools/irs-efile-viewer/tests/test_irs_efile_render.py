"""Rendering against a synthetic stylesheet tree: envelope, inert output, fallbacks."""

from __future__ import annotations

from pathlib import Path

import lxml.html
import pytest
from irs_efile_helpers import build_tree, efile_xml

from irs_efile_viewer.efile import parse_return
from irs_efile_viewer.mef import MefStore
from irs_efile_viewer.postprocess import PAGE_CSP
from irs_efile_viewer.render import Renderer, build_envelope

HOSTILE = (
    '<IRSTEST documentId="RetDoc1"><Txt>&lt;script&gt;alert("txt")&lt;/script&gt; plain</Txt>'
    '<Raw>&lt;img src=x onerror="alert(1)"&gt;&lt;script&gt;alert("raw")&lt;/script&gt;'
    '&lt;a href="javascript:alert(2)"&gt;x&lt;/a&gt;</Raw>'
    '<AttachedRef referenceDocumentId="RetDoc2"/></IRSTEST>'
    '<OtherExpensesSchedule documentId="RetDoc2"><TotalAmt>1234567</TotalAmt></OtherExpensesSchedule>'
)


def _render(tree: Path, documents: str = HOSTILE, version: str = "2014v5.0"):
    ret = parse_return(efile_xml(documents=documents, version=version), source_name="201541349349307794_public.xml")
    return ret, Renderer(MefStore(tree)).render_all(ret)


def test_envelope_matches_what_the_irs_stylesheets_read() -> None:
    ret = parse_return(efile_xml(), source_name="201541349349307794_public.xml")
    env = build_envelope(ret, ret.documents[0]).getroot()
    text = lambda path: env.findtext(path)  # noqa: E731
    assert env.tag == "AppData"
    assert text("Parameters/TIN") == text("Parameters/TINLatest") == "20-1585919"
    assert text("Parameters/TaxYear") == "2014"
    assert text("Parameters/SubmissionVersion") == text("Parameters/ReturnVersion") == "2014v5.0"
    assert text("Parameters/SubmissionType") == "990"
    assert text("Parameters/DocumentId") == "RetDoc1"
    assert text("ApplicationProperties/FormHeaderOriginalData") == "ObjectId: 201541349349307794"
    assert text("ApplicationProperties/SystemMode") == "Submission: 2015-05-14"
    assert env.find("SubmissionHeaderAndDocument/ReturnHeader/Filer/EIN").text == "201585919"
    assert [c.tag for c in env.find("SubmissionHeaderAndDocument/SubmissionDocument")] == ["IRSTEST"]
    # The return itself is untouched: the envelope holds copies.
    assert ret.documents[0].element.getparent() is not None


def test_envelope_without_object_id_shows_submission_date() -> None:
    ret = parse_return(efile_xml(), source_name="return.xml")
    env = build_envelope(ret, ret.documents[0]).getroot()
    assert env.findtext("ApplicationProperties/FormHeaderOriginalData") == "Submission Date"
    assert env.findtext("ApplicationProperties/SystemMode") == "2015-05-14"


def test_form_page_carries_the_filing(tree: Path) -> None:
    _, rendering = _render(tree)
    doc = lxml.html.document_fromstring(rendering.pages["IRSTEST.html"])
    assert doc.get_element_by_id("filer").text_content() == "EXAMPLE ORG"
    assert doc.get_element_by_id("tin").text_content() == "20-1585919"
    assert doc.get_element_by_id("taxyear").text_content() == "2014"
    assert doc.get_element_by_id("docid").text_content() == "RetDoc1"
    assert "ObjectId: 201541349349307794" in doc.get_element_by_id("hdr").text_content()
    assert rendering.pages["IRSTEST.html"].startswith("<!DOCTYPE html>")


def test_form_page_is_inert(tree: Path) -> None:
    _, rendering = _render(tree)
    html = rendering.pages["IRSTEST.html"]
    doc = lxml.html.document_fromstring(html)
    assert doc.xpath("//script | //iframe | //object | //embed | //base") == []
    assert [
        (el.tag, name) for el in doc.iter() if isinstance(el.tag, str) for name in el.attrib if name.startswith("on")
    ] == []
    assert "alert" not in html.replace('alert("txt")', "")  # only the escaped text survives as text
    assert doc.get_element_by_id("txt").text_content() == '<script>alert("txt")</script> plain'
    assert doc.get_element_by_id("bad").get("href") is None
    assert doc.get_element_by_id("web").get("href") == "https://www.irs.gov/form990"
    assert doc.get_element_by_id("web").get("rel") == "noopener noreferrer"
    for el in doc.iter():
        if not isinstance(el.tag, str):
            continue
        for name in ("src", "background"):
            if el.get(name) is not None:
                assert el.get(name).startswith("data:image/"), (el.tag, el.get(name))
    metas = {m.get("http-equiv"): m.get("content") for m in doc.xpath("//meta[@http-equiv]")}
    assert metas == {"Content-Security-Policy": PAGE_CSP}
    assert doc.xpath("//meta/@charset") == ["utf-8"]


def test_assets_are_inlined(tree: Path) -> None:
    _, rendering = _render(tree)
    doc = lxml.html.document_fromstring(rendering.pages["IRSTEST.html"])
    css = " ".join(s.text or "" for s in doc.xpath("//style"))
    assert ".styBodyClass" in css and 'url("data:image/gif;base64,' in css
    assert "example.com" not in css and "@import" not in css
    assert doc.xpath("//link") == []
    logo = doc.xpath("//img[@alt='logo']")[0]
    assert logo.get("src").startswith("data:image/gif;base64,")  # Logo.GIF found as logo.gif
    assert 'url("data:image/gif' in doc.get_element_by_id("bg").get("style")


def test_attachment_icons_become_links_and_buttons_become_anchors(tree: Path) -> None:
    _, rendering = _render(tree)
    doc = lxml.html.document_fromstring(rendering.pages["IRSTEST.html"])
    (anchor,) = doc.xpath("//a[@class='iev-attachment']")
    assert anchor.get("href") == "OtherExpensesSchedule.html"
    assert anchor[0].tag == "img" and anchor[0].get("onclick") is None
    (back,) = doc.xpath("//a[contains(@class, 'styLeftoverTableBtn')]")
    assert back.get("href") == "#" and back.text == "Return to Form"


def test_toolbar_links_index_and_data_view(tree: Path) -> None:
    _, rendering = _render(tree)
    doc = lxml.html.document_fromstring(rendering.pages["IRSTEST.html"])
    bar = doc.get_element_by_id("iev-bar")
    assert [a.get("href") for a in bar.xpath(".//a")] == ["index.html", "IRSTEST.data.html"]
    assert doc.body[0] is bar


def test_document_without_a_stylesheet_falls_back_to_its_data_view(tree: Path) -> None:
    _, rendering = _render(tree)
    view = rendering.pages["OtherExpensesSchedule.html"]
    assert "There is no IRS stylesheet for OtherExpensesSchedule" in view
    assert "1,234,567" in view and "Form view</a>" not in view
    row = next(r for r in rendering.rows if r.document.name == "OtherExpensesSchedule")
    assert (row.stylesheet_year, row.error) == (None, None)
    assert "No IRS stylesheet" in rendering.pages["index.html"]


def test_nearest_year_is_used_and_said(tmp_path: Path) -> None:
    tree = build_tree(tmp_path, years=(2012, 2014))
    ret, rendering = _render(tree, version="2016v3.0")
    row = rendering.rows[0]
    assert (row.stylesheet_year, row.exact) == (2014, False)
    page = rendering.pages["IRSTEST.html"]
    assert "No TY2016 IRS stylesheet for this form is installed" in page
    assert "IRS TY2014 (nearest)" in rendering.pages["index.html"]
    assert rendering.approximations and not rendering.failures


def test_a_broken_stylesheet_falls_back_to_the_next_year(tmp_path: Path) -> None:
    tree = build_tree(tmp_path, years=(2014, 2016))
    (tree / "Stylesheets" / "2016" / "IRSTEST.xsl").write_text("<xsl:stylesheet broken")
    _, rendering = _render(tree, version="2016v3.0")
    row = rendering.rows[0]
    assert (row.stylesheet_year, row.exact, row.error) == (2014, False, None)


def test_when_every_stylesheet_fails_the_error_is_reported(tree: Path) -> None:
    (tree / "Stylesheets" / "2014" / "IRSTEST.xsl").write_text("<xsl:stylesheet broken")
    _, rendering = _render(tree)
    row = rendering.rows[0]
    assert row.error and "TY2014" in row.error
    assert "could not draw this document" in rendering.pages["IRSTEST.html"]
    assert "Form view failed" in rendering.pages["index.html"]


def test_without_stylesheets_everything_is_a_data_view() -> None:
    ret = parse_return(efile_xml(documents=HOSTILE))
    rendering = Renderer(None).render_all(ret)
    assert set(rendering.pages) == {
        "index.html", "IRSTEST.html", "IRSTEST.data.html",
        "OtherExpensesSchedule.html", "OtherExpensesSchedule.data.html",
    }
    assert all(r.stylesheet_year is None for r in rendering.rows)


def test_only_renders_the_named_documents(tree: Path) -> None:
    ret = parse_return(efile_xml(documents=HOSTILE))
    rendering = Renderer(MefStore(tree)).render_all(ret, only=["OtherExpensesSchedule"])
    assert set(rendering.pages) == {"index.html", "OtherExpensesSchedule.html", "OtherExpensesSchedule.data.html"}


def test_write_puts_every_page_on_disk(tree: Path, tmp_path: Path) -> None:
    _, rendering = _render(tree)
    written = rendering.write(tmp_path / "out")
    assert sorted(p.name for p in written) == sorted(rendering.pages)
    assert (tmp_path / "out" / "index.html").read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


@pytest.mark.parametrize("bad", ["javascript:alert(1)", "JaVaScRiPt:alert(1)", "java\nscript:alert(1)", "data:text/html,x", "vbscript:x"])
def test_script_urls_are_removed_in_any_spelling(tmp_path: Path, bad: str) -> None:
    from irs_efile_viewer.postprocess import finalize

    html = finalize(f'<html><body><a id="x" href="{bad}">x</a></body></html>', store=None, year_hint=None, links={})
    assert lxml.html.document_fromstring(html).get_element_by_id("x").get("href") is None


def test_script_urls_are_removed_from_any_attribute() -> None:
    from irs_efile_viewer.postprocess import finalize

    html = finalize(
        '<html><body><svg><a id="s" xlink:href=" java\tscript:alert(1)">x</a></svg>'
        '<button id="b" formaction="javascript:alert(2)">b</button>'
        '<div id="d" data-x="vbscript:msgbox">d</div></body></html>',
        store=None, year_hint=None, links={},
    )
    doc = lxml.html.document_fromstring(html)
    assert "script:" not in html
    assert doc.get_element_by_id("s").attrib.get("xlink:href") is None
    assert doc.get_element_by_id("b").get("formaction") is None
    assert doc.get_element_by_id("d").get("data-x") is None
