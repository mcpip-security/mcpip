"""The command line, in-process and as an installed entry point."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from irs_efile_helpers import build_tree, efile_xml

from irs_efile_viewer.cli import main

SRC = Path(__file__).resolve().parents[1] / "src"


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def test_render_one_return(tree: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    xml = _write(tmp_path / "201541349349307794_public.xml", efile_xml())
    out = tmp_path / "out"
    assert main(["render", str(xml), "-o", str(out), "--mef", str(tree)]) == 0
    assert sorted(p.name for p in out.iterdir()) == ["IRSTEST.data.html", "IRSTEST.html", "index.html"]
    printed = capsys.readouterr().out
    assert "EXAMPLE ORG — Form 990, tax year 2014" in printed
    assert "1 with their own year's IRS stylesheet, 0 approximated, 0 failed" in printed


def test_render_several_returns_into_subdirectories(tree: Path, tmp_path: Path) -> None:
    a = _write(tmp_path / "a_public.xml", efile_xml())
    b = _write(tmp_path / "b.xml", efile_xml())
    assert main(["render", str(a), str(b), "-o", str(tmp_path / "out"), "--mef", str(tree)]) == 0
    assert (tmp_path / "out" / "a_public" / "index.html").is_file()
    assert (tmp_path / "out" / "b" / "index.html").is_file()


def test_strict_fails_on_approximation(tmp_path: Path) -> None:
    tree = build_tree(tmp_path, years=(2014,))
    xml = _write(tmp_path / "r.xml", efile_xml(version="2016v3.0"))
    args = ["render", str(xml), "-o", str(tmp_path / "out"), "--mef", str(tree)]
    assert main(args) == 0
    assert main([*args, "--strict"]) == 1


def test_data_only(tmp_path: Path) -> None:
    xml = _write(tmp_path / "r.xml", efile_xml())
    assert main(["render", str(xml), "-o", str(tmp_path / "out"), "--data-only"]) == 0
    assert "There is no IRS stylesheet" in (tmp_path / "out" / "IRSTEST.html").read_text(encoding="utf-8")


def test_missing_stylesheets_degrade_to_data_views(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("IRS_EFILE_MEF_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "empty"))
    xml = _write(tmp_path / "r.xml", efile_xml())
    assert main(["render", str(xml), "-o", str(tmp_path / "out")]) == 0
    assert "writing data views only" in capsys.readouterr().err
    assert main(["render", str(xml), "-o", str(tmp_path / "out"), "--strict"]) == 1


def test_bad_inputs_exit_2(tree: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = _write(tmp_path / "bad.xml", b"<html/>")
    assert main(["render", str(bad), str(tmp_path / "missing.xml"), "-o", str(tmp_path / "o"), "--mef", str(tree)]) == 2
    err = capsys.readouterr().err
    assert "expected an IRS e-file <Return>" in err and "missing.xml" in err
    assert main(["render", str(bad), "--mef", str(tmp_path / "nope")]) == 2


def test_size_limit(tree: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    xml = _write(tmp_path / "r.xml", efile_xml().replace(b"hello", b"x" * (2 * 1024 * 1024)))
    assert main(["render", str(xml), "-o", str(tmp_path / "o"), "--mef", str(tree), "--max-mb", "1"]) == 2
    assert "raise --max-mb" in capsys.readouterr().err


def test_years(tree: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["years", "--mef", str(tree)]) == 0
    assert capsys.readouterr().out.strip().endswith(": 2014")


def test_import_irs_zip_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import zipfile

    archive = tmp_path / "ty2023.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("mef/Stylesheets/2023/IRS990.xsl", "<x/>")
    assert main(["import-irs-zip", str(archive), "--dest", str(tmp_path / "mef")]) == 0
    assert "1 files, TY2023" in capsys.readouterr().out


def test_module_entry_point_reads_stdin(tree: Path, tmp_path: Path) -> None:
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    proc = subprocess.run(
        [sys.executable, "-m", "irs_efile_viewer", "render", "-", "-o", str(tmp_path / "out"), "--mef", str(tree)],
        input=efile_xml(), capture_output=True, env=env,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    assert (tmp_path / "out" / "IRSTEST.html").is_file()
