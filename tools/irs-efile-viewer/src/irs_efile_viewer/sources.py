"""Getting the IRS stylesheets onto disk.

Two sources, because the stylesheets are published in two places:

* :func:`fetch_betson` — TY2008–2021 (plus a partial TY2022 update) from the public
  betson/irs-efile-viewer repository, pinned to one commit so every install renders the
  same way. Git is used sparse and blob-filtered, so asking for two years downloads two
  years, not the whole 640 MB tree.
* :func:`import_irs_zip` — a stylesheet ZIP downloaded from irs.gov, where TY2022 onward
  lives. Merged file by file, as the IRS intends: each archive carries only what was
  added or changed for that release, so replacing directories would drop files. Import
  tax years in order.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

BETSON_REPOSITORY = "https://github.com/betson/irs-efile-viewer.git"
#: 2023-09-27 — the repository's latest commit. Bump deliberately: output can change.
BETSON_COMMIT = "ef48107563bc49d64f92b476dd21786353b4b049"
PROVENANCE_FILE = "irs-efile-viewer-sources.json"

#: Archive limits: the full TY2021 tree is ~50 MB across ~3,000 files.
_MAX_MEMBER_BYTES = 64 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
_TREE_ROOTS = {"stylesheets": "Stylesheets", "rrprd": "rrprd", "rrdprd": "rrprd"}


class SourceError(RuntimeError):
    """A stylesheet source could not be fetched or imported."""


@dataclass
class InstallSummary:
    destination: Path
    files: int = 0
    years: list[int] = field(default_factory=list)


def fetch_betson(
    destination: str | os.PathLike[str],
    years: Sequence[int] | None = None,
    *,
    repository: str = BETSON_REPOSITORY,
    commit: str = BETSON_COMMIT,
    git: str = "git",
) -> InstallSummary:
    """Install the pinned betson/irs-efile-viewer stylesheets (all years, or ``years``)."""
    dest = Path(destination).expanduser()
    if years:
        patterns = ["/mef/rrprd/common/"]
        for year in sorted(set(years)):
            patterns += [f"/mef/Stylesheets/{year}/", f"/mef/rrprd/sdi/versioned/{year}/"]
    else:
        patterns = ["/mef/"]

    with tempfile.TemporaryDirectory(prefix="irs-mef-") as tmp:
        checkout = Path(tmp)

        def run(*args: str) -> None:
            env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
            proc = subprocess.run(
                [git, "-C", str(checkout), *args], capture_output=True, text=True, env=env
            )
            if proc.returncode != 0:
                raise SourceError(f"git {args[0]} failed: {proc.stderr.strip() or proc.stdout.strip()}")

        run("init", "-q")
        run("remote", "add", "origin", repository)
        run("config", "core.sparseCheckout", "true")
        (checkout / ".git" / "info").mkdir(parents=True, exist_ok=True)
        (checkout / ".git" / "info" / "sparse-checkout").write_text("\n".join(patterns) + "\n")
        run("fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", commit)
        run("-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD")

        source = checkout / "mef"
        if not (source / "Stylesheets").is_dir():
            raise SourceError(f"{repository}@{commit[:7]} has no mef/Stylesheets for {patterns}")
        summary = InstallSummary(destination=dest)
        for path in source.rglob("*"):
            if path.is_file():
                target = dest / path.relative_to(source)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
                summary.files += 1
        summary.years = sorted(
            int(p.name) for p in (source / "Stylesheets").iterdir() if p.is_dir() and p.name.isdigit()
        )

    _record(dest, {"source": repository, "commit": commit, "years": summary.years or "all"})
    return summary


def import_irs_zip(archive: str | os.PathLike[str], destination: str | os.PathLike[str]) -> InstallSummary:
    """Merge an irs.gov MeF stylesheet ZIP into the tree at ``destination``."""
    dest = Path(destination).expanduser()
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    summary = InstallSummary(destination=dest)
    years: set[int] = set()
    total = 0
    try:
        zf = zipfile.ZipFile(archive)
    except (OSError, zipfile.BadZipFile) as exc:
        raise SourceError(f"{archive}: not a readable ZIP archive ({exc})") from exc
    with zf:
        for member in zf.infolist():
            if member.is_dir():
                continue
            parts = _tree_parts(member.filename)
            if parts is None:
                continue
            if member.file_size > _MAX_MEMBER_BYTES:
                raise SourceError(f"{member.filename}: {member.file_size} bytes is over the per-file limit")
            target = (root / PurePosixPath(*parts)).resolve()
            if not target.is_relative_to(root):
                raise SourceError(f"{member.filename}: escapes the stylesheet tree")
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with zf.open(member) as src, open(target, "wb") as out:
                while chunk := src.read(1 << 16):
                    written += len(chunk)
                    total += len(chunk)
                    if written > _MAX_MEMBER_BYTES or total > _MAX_ARCHIVE_BYTES:
                        raise SourceError(f"{member.filename}: archive expands past the size limit")
                    out.write(chunk)
            summary.files += 1
            if parts[0] == "Stylesheets" and len(parts) > 2 and parts[1].isdigit():
                years.add(int(parts[1]))
    if summary.files == 0:
        raise SourceError(f"{archive}: no mef/Stylesheets or mef/rrprd entries — not an IRS MeF stylesheet ZIP?")
    summary.years = sorted(years)
    _record(dest, {"source": Path(archive).name, "years": summary.years})
    return summary


def _tree_parts(name: str) -> tuple[str, ...] | None:
    """Path inside the tree for an archive member, or ``None`` if it is not part of one.

    Accepts ``mef/...`` at any depth (``PY2023R01/mef/Stylesheets/...``) and archives that
    start at ``Stylesheets/`` or ``rrprd/``. Refuses anything that could climb out.
    """
    clean = name.replace("\\", "/")
    parts = PurePosixPath(clean).parts
    if clean.startswith("/") or ".." in parts or any(":" in p for p in parts):
        raise SourceError(f"{name}: unsafe path in archive")
    lowered = [p.lower() for p in parts]
    start = lowered.index("mef") + 1 if "mef" in lowered else 0
    rest = parts[start:]
    if len(rest) < 2 or rest[0].lower() not in _TREE_ROOTS:
        return None
    return (_TREE_ROOTS[rest[0].lower()], *rest[1:])


def _record(dest: Path, entry: dict[str, object]) -> None:
    """Append to the provenance log, so an install says where its files came from."""
    log = dest / PROVENANCE_FILE
    try:
        entries = json.loads(log.read_text(encoding="utf-8"))
        if not isinstance(entries, list):
            entries = []
    except (OSError, ValueError):
        entries = []
    entries.append({**entry, "installed_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")})
    log.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
