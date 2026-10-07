"""Installing stylesheets: IRS ZIP import (with its hazards) and the pinned git fetch."""

from __future__ import annotations

import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from irs_efile_viewer.mef import MefStore
from irs_efile_viewer.sources import PROVENANCE_FILE, SourceError, fetch_betson, import_irs_zip

XSL = b'<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"/>'


def _zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def test_imports_an_irs_archive_into_the_tree(tmp_path: Path) -> None:
    archive = _zip(
        tmp_path / "TY2023.zip",
        {
            "PY2023R01/mef/Stylesheets/2023/IRS990.xsl": XSL,
            "PY2023R01/mef/rrprd/common/images/attach.gif": b"GIF89a",
            "PY2023R01/mef/rrdprd/sdi/versioned/2023/styles/body.css": b".a{}",
            "PY2023R01/ReleaseNotes.pdf": b"%PDF",
        },
    )
    dest = tmp_path / "mef"
    summary = import_irs_zip(archive, dest)
    assert (summary.files, summary.years) == (3, [2023])
    assert (dest / "Stylesheets/2023/IRS990.xsl").read_bytes() == XSL
    assert (dest / "rrprd/sdi/versioned/2023/styles/body.css").is_file()  # legacy dir name mapped
    assert not (dest / "ReleaseNotes.pdf").exists()
    assert MefStore(dest).years == (2023,)
    assert json.loads((dest / PROVENANCE_FILE).read_text())[0]["years"] == [2023]


def test_archives_without_a_mef_folder_are_accepted(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "flat.zip", {"Stylesheets/2024/IRS990.xsl": XSL})
    assert import_irs_zip(archive, tmp_path / "mef").years == [2024]


def test_import_merges_instead_of_replacing(tmp_path: Path) -> None:
    dest = tmp_path / "mef"
    import_irs_zip(_zip(tmp_path / "a.zip", {"mef/Stylesheets/2023/A.xsl": XSL}), dest)
    import_irs_zip(_zip(tmp_path / "b.zip", {"mef/Stylesheets/2023/B.xsl": XSL}), dest)
    assert sorted(p.name for p in (dest / "Stylesheets/2023").iterdir()) == ["A.xsl", "B.xsl"]


@pytest.mark.parametrize(
    "name",
    ["mef/Stylesheets/../../../evil.xsl", "../mef/Stylesheets/2023/x.xsl", "/abs/mef/Stylesheets/2023/x.xsl", "C:/mef/Stylesheets/x.xsl"],
)
def test_archive_paths_cannot_escape(tmp_path: Path, name: str) -> None:
    archive = _zip(tmp_path / "evil.zip", {name: XSL})
    with pytest.raises(SourceError, match="unsafe path"):
        import_irs_zip(archive, tmp_path / "mef")
    assert not (tmp_path / "evil.xsl").exists()


def test_rejects_archives_that_are_not_stylesheets(tmp_path: Path) -> None:
    with pytest.raises(SourceError, match="not an IRS MeF stylesheet ZIP"):
        import_irs_zip(_zip(tmp_path / "x.zip", {"readme.txt": b"hi"}), tmp_path / "mef")
    (tmp_path / "junk.zip").write_bytes(b"not a zip")
    with pytest.raises(SourceError, match="not a readable ZIP"):
        import_irs_zip(tmp_path / "junk.zip", tmp_path / "mef")


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_fetch_installs_only_the_requested_years_at_the_pinned_commit(tmp_path: Path) -> None:
    upstream = tmp_path / "upstream"
    for rel in ["mef/Stylesheets/2014/IRS990.xsl", "mef/Stylesheets/2021/IRS990.xsl",
                "mef/rrprd/common/images/attach.gif", "mef/rrprd/sdi/versioned/2014/styles/body.css",
                "mef/rrprd/sdi/versioned/2021/styles/body.css", "index.html"]:
        (upstream / rel).parent.mkdir(parents=True, exist_ok=True)
        (upstream / rel).write_bytes(XSL)

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(upstream), "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
            check=True, capture_output=True, text=True,
        ).stdout.strip()

    git("init", "-q")
    git("config", "uploadpack.allowFilter", "true")
    git("config", "uploadpack.allowAnySHA1InWant", "true")
    git("add", ".")
    git("commit", "-q", "-m", "tree")
    pinned = git("rev-parse", "HEAD")
    (upstream / "mef/Stylesheets/2014/IRS990.xsl").write_bytes(b"changed after the pin")
    git("commit", "-q", "-am", "later")

    dest = tmp_path / "mef"
    summary = fetch_betson(dest, [2014], repository=upstream.as_uri(), commit=pinned)
    assert summary.years == [2014]
    assert (dest / "Stylesheets/2014/IRS990.xsl").read_bytes() == XSL  # the pinned content
    assert (dest / "rrprd/common/images/attach.gif").is_file()
    assert (dest / "rrprd/sdi/versioned/2014/styles/body.css").is_file()
    assert not (dest / "Stylesheets/2021").exists()
    assert not (dest / "rrprd/sdi/versioned/2021").exists()
    log = json.loads((dest / PROVENANCE_FILE).read_text())
    assert log[0]["commit"] == pinned and log[0]["years"] == [2014]


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_fetch_reports_git_failures(tmp_path: Path) -> None:
    with pytest.raises(SourceError, match="git fetch failed"):
        fetch_betson(tmp_path / "mef", [2014], repository=(tmp_path / "nowhere").as_uri(), commit="0" * 40)
