"""End to end: real IRS filings, TY2010–2023, through the real IRS stylesheets.

Needs an installed stylesheet tree (``irs-efile-viewer fetch``); see conftest.py. The
fixtures are public 990-series filings, chosen to span the schema eras: two from before
the TY2013 renaming of header elements, one per later era, and two from tax years whose
stylesheets are not in the public TY2008–2021 set, which must fall back to the nearest.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import lxml.html
import pytest

from irs_efile_viewer.efile import parse_return
from irs_efile_viewer.mef import MefStore
from irs_efile_viewer.postprocess import PAGE_CSP
from irs_efile_viewer.render import Renderer, Rendering

FILINGS = Path(__file__).resolve().parent / "fixtures" / "filings"
SRC = Path(__file__).resolve().parents[1] / "src"
#: Tax years whose stylesheets the fixtures need (CI fetches exactly these).
REQUIRED_YEARS = (2010, 2011, 2012, 2014, 2017, 2019, 2020, 2021)

# object id -> (form, schema year, is the form view exact for that year?)
CASES = {
    "201142599349300414": ("IRS990", 2010, True),
    "201221359349101502": ("IRS990PF", 2011, True),
    "201311739349200301": ("IRS990EZ", 2012, True),
    "201541349349307794": ("IRS990", 2014, True),
    "201830649349200703": ("IRS990EZ", 2017, True),
    "202022649349100002": ("IRS990PF", 2019, True),
    "202123199339302152": ("IRS990T", 2020, True),
    "202233259349300103": ("IRS990", 2021, True),
    "202302769349101400": ("IRS990PF", 2022, False),
    "202442729349300109": ("IRS990", 2023, False),
}

_cache: dict[str, Rendering] = {}


def _rendering(store: MefStore, object_id: str) -> Rendering:
    if object_id not in _cache:
        path = FILINGS / f"{object_id}_public.xml"
        ret = parse_return(path.read_bytes(), source_name=path.name)
        _cache[object_id] = Renderer(store).render_all(ret)
    return _cache[object_id]


def test_the_tree_has_the_years_the_fixtures_need(real_store: MefStore) -> None:
    assert set(REQUIRED_YEARS) <= set(real_store.years), real_store.years


@pytest.mark.parametrize("object_id", sorted(CASES))
def test_every_document_renders(real_store: MefStore, object_id: str) -> None:
    form, year, exact = CASES[object_id]
    rendering = _rendering(real_store, object_id)
    ret = rendering.ret
    assert ret.schema_year == year and ret.documents[0].name == form
    assert rendering.failures == []
    assert rendering.rows[0].exact is exact
    for row in rendering.rows:
        assert row.stylesheet_year is not None, f"{row.document.name} has no stylesheet"
        if not exact:
            assert row.stylesheet_year == 2021  # the nearest year with a full set
    assert set(rendering.pages) == {"index.html"} | {
        name for doc in ret.documents for name in (f"{doc.stem}.html", f"{doc.stem}.data.html")
    }


@pytest.mark.parametrize("object_id", sorted(CASES))
def test_main_form_shows_the_filing(real_store: MefStore, object_id: str) -> None:
    rendering = _rendering(real_store, object_id)
    ret = rendering.ret
    main = ret.documents[0]
    html = rendering.pages[f"{main.stem}.html"]
    assert ret.filer_name.split()[0] in html
    assert ret.tin in html
    # The form shows (comma-grouped) most of the large numbers in the document.
    numbers = {
        e.text.strip()
        for e in main.element.iter()
        if isinstance(e.tag, str) and e.text and e.text.strip().isdigit() and len(e.text.strip()) >= 5
        and not e.tag.endswith(("EIN", "PhoneNum", "Phone", "ZIPCd", "ZIPCode", "Num", "SSN"))
    }
    shown = {n for n in numbers if f"{int(n):,}" in html}
    assert numbers and len(shown) >= 0.8 * len(numbers), sorted(numbers - shown)[:10]


@pytest.mark.parametrize("object_id", sorted(CASES))
def test_every_page_is_self_contained_and_inert(real_store: MefStore, object_id: str) -> None:
    rendering = _rendering(real_store, object_id)
    for name, html in rendering.pages.items():
        doc = lxml.html.document_fromstring(html)
        assert doc.xpath("//script | //iframe | //object | //embed | //base | //link") == [], name
        handlers = [a for el in doc.iter() if isinstance(el.tag, str) for a in el.attrib if a.startswith("on")]
        assert handlers == [], (name, handlers[:5])
        for el in doc.iter():
            if not isinstance(el.tag, str):
                continue
            for attr in ("src", "background"):
                value = el.get(attr)
                assert value is None or value.startswith("data:image/"), (name, el.tag, value)
            href = el.get("href")
            if href and not href.startswith(("http://", "https://", "#", "mailto:")):
                assert href in rendering.pages, (name, href)  # every local link resolves
        csp = doc.xpath("//meta[@http-equiv='Content-Security-Policy']/@content")
        assert len(csp) == 1 and csp[0].startswith("default-src 'none'"), (name, csp)
        if name.endswith(".html") and not name.endswith(".data.html") and name != "index.html":
            assert csp == [PAGE_CSP], name
            assert "/mef/" not in " ".join(s.text or "" for s in doc.xpath("//style")), name


def test_attachment_icons_link_to_the_attached_documents(real_store: MefStore) -> None:
    rendering = _rendering(real_store, "201541349349307794")
    doc = lxml.html.document_fromstring(rendering.pages["IRS990.html"])
    targets = set(doc.xpath("//a[@class='iev-attachment']/@href"))
    assert {"IRS990ScheduleA.html", "IRS990ScheduleB.html", "IRS990ScheduleD.html"} <= targets


def test_demo_filing_values(real_store: MefStore) -> None:
    """The betson/irs-efile-viewer demo filing: the values its screenshots show."""
    html = _rendering(real_store, "201541349349307794").pages["IRS990.html"]
    for text in ["VOICE OF SAN DIEGO", "20-1585919", "1,726,766", "866,826",
                 "ObjectId: 201541349349307794", "Submission: 2015-05-14"]:
        assert text in html, text


def test_pre_2013_returns_render_with_their_own_year(real_store: MefStore) -> None:
    """The original viewer threw on these (it only looked for TaxYr)."""
    rendering = _rendering(real_store, "201142599349300414")
    assert rendering.ret.tax_year == "2010" and rendering.rows[0].exact
    assert "395,004" in rendering.pages["IRS990.html"]  # GrossReceipts


def test_fallback_years_say_so(real_store: MefStore) -> None:
    rendering = _rendering(real_store, "202442729349300109")
    assert "No TY2023 IRS stylesheet for this form is installed" in rendering.pages["IRS990.html"]
    assert "IRS TY2021 (nearest)" in rendering.pages["index.html"]


def test_a_later_year_draws_a_schedule_its_own_year_lacks(real_store: MefStore) -> None:
    """TY2020 has the Form 990-T stylesheet but not the one for its Schedule A."""
    rows = {r.document.name: r for r in _rendering(real_store, "202123199339302152").rows}
    assert (rows["IRS990T"].stylesheet_year, rows["IRS990T"].exact) == (2020, True)
    assert (rows["IRS990TScheduleA"].stylesheet_year, rows["IRS990TScheduleA"].exact) == (2021, False)


def test_cli_renders_every_fixture(real_store: MefStore, tmp_path: Path) -> None:
    env = {**os.environ, "PYTHONPATH": str(SRC), "IRS_EFILE_MEF_DIR": str(real_store.root)}
    files = sorted(str(p) for p in FILINGS.glob("*.xml"))
    proc = subprocess.run(
        [sys.executable, "-m", "irs_efile_viewer", "render", *files, "-o", str(tmp_path)],
        capture_output=True, text=True, env=env,
    )
    assert proc.returncode == 0, proc.stderr
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(f"{oid}_public" for oid in CASES)
    assert proc.stdout.count(", 0 failed") == len(CASES), proc.stdout


def test_web_renders_an_upload(real_store: MefStore) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from irs_efile_viewer.web import create_app

    client = TestClient(create_app(real_store))
    path = FILINGS / "201830649349200703_public.xml"
    response = client.post("/render", files={"file": (path.name, path.read_bytes(), "text/xml")})
    assert response.status_code == 200 and "Schedule A (Form 990)" in response.text
    form = client.get(str(response.url) + "IRS990EZ.html")
    assert form.status_code == 200 and "PREVENTION FIRST FOUNDATION" in form.text
