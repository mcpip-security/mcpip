"""The stylesheet tree: both layouts, year selection, confinement, assets."""

from __future__ import annotations

from pathlib import Path

import pytest
from irs_efile_helpers import build_tree
from lxml import etree

from irs_efile_viewer.mef import ENV_VAR, MefError, MefStore, StylesheetChoice, normalize


@pytest.mark.parametrize(
    "raw, expected",
    [
        (b"---\n---\n<?xml version='1.0'?><a/>", b"<?xml version='1.0'?><a/>"),
        (b"---\r\n---\r\n<?xml version='1.0'?><a/>", b"<?xml version='1.0'?><a/>"),
        (b"---\ntitle: x\n---\n<a/>", b"<a/>"),
        (b"<a href='{{ site.github.url }}/mef/rrprd/x.gif'/>", b"<a href='/mef/rrprd/x.gif'/>"),
        (b"<a href='{{site.github.url}}/mef/rrprd/x.gif'/>", b"<a href='/mef/rrprd/x.gif'/>"),
        (b"<a href='/mef/rrdprd/common/x.gif'/>", b"<a href='/mef/rrprd/common/x.gif'/>"),
        (b"<?xml version='1.0'?><a>--- not front matter ---</a>", b"<?xml version='1.0'?><a>--- not front matter ---</a>"),
    ],
)
def test_normalize_undoes_the_github_pages_packaging(raw: bytes, expected: bytes) -> None:
    assert normalize(raw) == expected


def test_accepts_the_mef_dir_or_its_parent(tree: Path) -> None:
    assert MefStore(tree).root == MefStore(tree.parent).root == tree.resolve()
    assert MefStore(tree).years == (2014,)


def test_rejects_a_directory_without_stylesheets(tmp_path: Path) -> None:
    with pytest.raises(MefError, match="not an IRS stylesheet tree"):
        MefStore(tmp_path)


def test_locate_prefers_explicit_then_environment(tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_VAR, str(tree))
    assert MefStore.locate().root == tree.resolve()
    other = build_tree(tmp_path / "other", years=(2019,))
    assert MefStore.locate(other).years == (2019,)
    monkeypatch.delenv(ENV_VAR)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "empty-cache"))
    with pytest.raises(MefError, match="irs-efile-viewer fetch"):
        MefStore.locate()


def test_candidates_prefer_the_exact_year_then_nearest_earlier_then_later(tmp_path: Path) -> None:
    store = MefStore(build_tree(tmp_path, years=(2012, 2014, 2016, 2021)))
    assert [(c.year, c.exact) for c in store.candidates("IRSTEST", 2016)] == [
        (2016, True), (2014, False), (2012, False), (2021, False)
    ]
    assert [c.year for c in store.candidates("IRSTEST", 2023)] == [2021, 2016, 2014, 2012]
    assert [c.year for c in store.candidates("IRSTEST", 2008)] == [2012, 2014, 2016, 2021]
    assert store.candidates("NoSuchForm", 2016) == []


@pytest.mark.parametrize("name", ["../IRSTEST", "IRSTEST/../../x", "/etc/passwd", "", ".hidden"])
def test_candidates_refuse_names_that_are_not_element_names(tree: Path, name: str) -> None:
    assert MefStore(tree).candidates(name, 2014) == []


def test_compiles_through_front_matter_and_caches(tree: Path) -> None:
    store = MefStore(tree)
    choice = store.candidates("IRSTEST", 2014)[0]
    xslt, lock = store.compile(choice)
    assert store.compile(choice)[0] is xslt
    assert lock is not None


def test_includes_outside_the_tree_are_refused(tree: Path) -> None:
    outside = tree.parent / "outside.xsl"
    outside.write_text(
        '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
        '<xsl:template match="/">LEAKED</xsl:template></xsl:stylesheet>'
    )
    evil = tree / "Stylesheets" / "2014" / "Evil.xsl"
    evil.write_text(
        '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
        '<xsl:include href="../../../outside.xsl"/></xsl:stylesheet>'
    )
    store = MefStore(tree)
    with pytest.raises((etree.XSLTParseError, etree.XMLSyntaxError)):
        store.compile(StylesheetChoice(path=evil, year=2014, exact=True))


def test_document_function_cannot_read_outside_the_tree(tree: Path) -> None:
    secret = tree.parent / "secret.xml"
    secret.write_text("<s>TOP-SECRET-VALUE</s>")
    sheet = tree / "Stylesheets" / "2014" / "Peek.xsl"
    sheet.write_text(
        '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
        f'<xsl:template match="/"><out><xsl:value-of select="document(\'{secret.as_uri()}\')"/>'
        "<xsl:value-of select=\"document('../../../secret.xml')\"/></out></xsl:template></xsl:stylesheet>"
    )
    # Control: compiled without the store's resolver, the same stylesheet does read it.
    unguarded = etree.XSLT(etree.XML(sheet.read_bytes(), base_url=sheet.as_uri()))
    assert "TOP-SECRET-VALUE" in str(unguarded(etree.XML("<x/>")))

    store = MefStore(tree)
    xslt, _ = store.compile(StylesheetChoice(path=sheet, year=2014, exact=True))
    assert "TOP-SECRET-VALUE" not in str(xslt(etree.XML("<x/>")))


def test_assets_resolve_with_year_fallback_and_any_case(tree: Path) -> None:
    store = MefStore(tree)
    logo = store.asset("/mef/rrprd/sdi/versioned/2014/images/Logo.GIF")
    assert logo is not None and logo.name == "logo.gif"
    assert store.asset("/mef/rrprd/sdi/versioned/2023/images/logo.gif", year_hint=2014) == logo
    assert store.asset("/mef/rrdprd/common/images/attach.gif") is not None
    assert store.asset("/mef/rrprd/sdi/versioned/2014/images/missing.gif") is None


@pytest.mark.parametrize(
    "url",
    ["/mef/../../etc/passwd", "/mef/rrprd/../../../etc/passwd", "https://example.com/mef/x.gif", "/etc/passwd", "x.gif"],
)
def test_assets_never_leave_the_tree(tree: Path, url: str) -> None:
    assert MefStore(tree).asset(url) is None


def test_data_uris_only_for_images(tree: Path) -> None:
    store = MefStore(tree)
    gif = store.asset("/mef/rrprd/common/images/attach.gif")
    css = store.asset("/mef/rrprd/sdi/versioned/2014/styles/body.css")
    assert gif is not None and css is not None
    assert (store.data_uri(gif) or "").startswith("data:image/gif;base64,R0lGOD")
    assert store.data_uri(css) is None
