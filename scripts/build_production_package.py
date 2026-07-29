#!/usr/bin/env python3
"""Build the MCPIP public production distribution.

MCPIP's working repository carries two kinds of material: the **product** —
source, tests, SDKs, console, deployment manifests, operator/security/compliance
documentation — and the maintainers' **internal business material** (strategy,
roadmap, pricing, narrative deck, competitive review, unbuilt managed-cloud
design) plus agent/dev scaffolding. Only the first belongs in the public
distribution.

This script assembles that distribution from the working tree into a
deterministic, verified ZIP. It **never mutates the working tree** — it stages a
copy, rewrites the handful of documentation references that would otherwise
dangle, and verifies the result before it writes the archive.

    python scripts/build_production_package.py                  # -> dist/mcpip-<version>-production.zip
    python scripts/build_production_package.py --keep-tree      # also leave the staged tree for inspection
    python scripts/build_production_package.py --check          # verify only; write nothing

What the build guarantees, and fails loudly rather than silently degrades:

* **Allowlist, not denylist.** A new top-level file or directory is *excluded*
  until it is listed here. Nothing leaks into a public release because someone
  forgot to update an ignore rule.
* **No dangling internal reference.** After the rewrites, the packaged tree
  contains zero mentions of any excluded document, and every relative Markdown
  link between packaged documents resolves. Both are enforced (§ verify).
* **Rot detection.** Every declared line edit must match exactly one line in its
  file. If upstream prose changes underneath a rewrite, the build fails instead
  of shipping a half-edited sentence.
* **Determinism.** Sorted traversal and fixed archive timestamps: the same tree
  produces a byte-identical ZIP, so the package hash is reviewable.

The manifest written into the archive (``PACKAGE_MANIFEST.json``) records the
SHA-256 of every packaged file, the source commit, and the exclusion list — the
package states plainly what was left out of it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------
# 1. What ships.  Allowlist — anything not named here is excluded by default.
# --------------------------------------------------------------------------

INCLUDE_ROOT_FILES: tuple[str, ...] = (
    # Product entrypoints + shared primitives.
    "main.py",
    "interfaces.py",
    # Packaging / build / runtime.
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "VERSION",
    "Dockerfile",
    ".dockerignore",
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "redis.conf",
    "install.sh",
    ".env.production.example",
    ".gitignore",
    ".mcp.json",
    # Product, security & operator documentation.
    "README.md",
    "CHANGELOG.md",
    "RELEASE.md",
    "SECURITY.md",
    "SECURITY_THREAT_MODEL.md",
    "SUPPORT.md",
    "NOTICES.md",
    # Licensing + the published policy set.
    "LICENSE",
    "LICENSING.md",
    "TERMS.md",
    "PRIVACY.md",
    "TRADEMARK.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
)

INCLUDE_DIRS: tuple[str, ...] = (
    ".github",       # CI is part of the verifiability story — it must be readable.
    "app",
    "audit",
    "auth",
    "bridge",
    "chart",
    "core",
    "dashboard",
    "docs",
    "k8s",
    "mcpip_verify",
    "models",
    "obfuscator",
    "packaging",
    "release",       # signed manifests + public verification keys; `mcpip verify` needs them.
    "rust",
    "scripts",
    "sdk",
    "services",
    "tests",         # you should not have to trust an authorizer whose tests you cannot run.
    "training",
)

# Internal-only paths, named explicitly so the manifest can state what was held
# back rather than leaving the reader to infer it from an absence.
EXCLUDE_PATHS: tuple[str, ...] = (
    ".claude/",   # agent context lake — maintainer tooling, not product
    "CLAUDE.md",  # agent instructions
)

# --------------------------------------------------------------------------
# 2. Internal documents, and the phrase that replaces a reference to each.
#
# These are business/planning artifacts. Product documentation legitimately
# cites them; in the public package each citation becomes a plain-prose mention
# of an internal document rather than a link to a file that is not there.
# --------------------------------------------------------------------------

EXCLUDED_DOCS: dict[str, str] = {
    "the internal strategy notes": "the internal strategy notes",
    "the internal roadmap": "the internal roadmap",
    "the project's commercial terms": "the project's commercial terms",
    "the project's narrative deck": "the project's narrative deck",
    "the internal developer-experience review": "the internal developer-experience review",
    "the internal managed-cloud design note": "the internal managed-cloud design note",
    "SOC2_READINESS.md": "the internal SOC 2 self-assessment",
}

EXCLUDED_DOC_PATHS: frozenset[str] = frozenset(f"docs/{name}" for name in EXCLUDED_DOCS)

# The public home of the project. The working repo predates the move and still
# carries the personal-namespace URL in a few places.
REPO_SLUG_REWRITES: tuple[tuple[str, str], ...] = (
    ("mcpip-security/mcpip", "mcpip-security/mcpip"),
)

# --------------------------------------------------------------------------
# 3. Build hygiene — never-ship artifacts.
# --------------------------------------------------------------------------

PRUNE_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git", ".venv", "venv", "node_modules", "dist", "build", "target", "gen",
        "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".keys",
        ".idea", ".vscode",
    }
)
PRUNE_DIR_SUFFIXES: tuple[str, ...] = (".egg-info",)
PRUNE_FILE_SUFFIXES: tuple[str, ...] = (
    ".pyc", ".pyo", ".pyd", ".so", ".tsbuildinfo", ".anchor", ".log", ".rdb",
    ".pem", ".key",  # private key material must never enter a distribution
)
PRUNE_FILE_NAMES: frozenset[str] = frozenset(
    {".DS_Store", "Thumbs.db", "dump.rdb", "mcpip_worm.jsonl", "mcpip-workspace-plan.json"}
)
# Public verification keys are the deliberate exception to the *.pem prune:
# `mcpip verify` and the license gate need them, and they are public by design.
PRUNE_EXCEPTIONS: tuple[str, ...] = ("release/keys/",)

TEXT_SUFFIXES: frozenset[str] = frozenset(
    {
        ".md", ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".json", ".yml", ".yaml",
        ".toml", ".cfg", ".ini", ".txt", ".sh", ".rs", ".html", ".css", ".conf", ".rb",
    }
)

# --------------------------------------------------------------------------
# 4. Declared documentation rewrites.
#
# Every entry must match EXACTLY ONE line in its file, or the build fails. That
# is deliberate: when upstream prose moves, this file is the thing that should
# break, loudly, at build time.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LineEdit:
    """One declared edit against one line of one packaged document."""

    anchor: str
    #: ``None`` drops the line; a string replaces the whole line; a
    #: ``(old, new)`` pair replaces a fragment within the line.
    action: object

    def apply(self, line: str) -> Optional[str]:
        if self.action is None:
            return None
        if isinstance(self.action, tuple):
            old, new = self.action
            if old not in line:
                raise BuildError(f"fragment {old!r} not present in matched line: {line!r}")
            return line.replace(old, new)
        return str(self.action)


LINE_EDITS: dict[str, tuple[LineEdit, ...]] = {
    "README.md": (
        # Repository-layout tree: drop the internal deck entry.
        LineEdit("│   ├── the project's narrative deck", None),
        # Two of the five hub bullets below are pointers to internal planning docs.
        LineEdit(
            "**The enterprise doc set** — five hubs are the front door;",
            "**The enterprise doc set** — the hubs below are the front door;",
        ),
        # Documentation index: two bullets are pure pointers to the roadmap.
        LineEdit("- the internal roadmap", None),
        LineEdit("- the internal roadmap", None),
        LineEdit(
            "- [**Compliance pack**](docs/operate/COMPLIANCE.md)",
            (
                " — see the the internal roadmap for the honest external gap",
                "",
            ),
        ),
        LineEdit(
            "structure in [`SUPPORT.md`](SUPPORT.md) and the project's commercial terms.",
            "  structure in [`SUPPORT.md`](SUPPORT.md).",
        ),
        LineEdit(
            "[`LICENSING.md`](LICENSING.md) · the internal strategy notes.",
            "[`LICENSING.md`](LICENSING.md) · [`TERMS.md`](TERMS.md).",
        ),
    ),
    "SUPPORT.md": (
        LineEdit(
            "support. Structure and pricing are published openly in",
            "support. Structure and commercial terms are shared directly on request.",
        ),
        LineEdit("the project's commercial terms.", None),
    ),
    "LICENSING.md": (
        LineEdit(
            "MCPIP uses an **open-core, source-available** model. The rationale (why source-available and not",
            "MCPIP uses an **open-core, source-available** model. What that model means for your",
        ),
        LineEdit(
            "pure Apache or fully proprietary) is in the internal strategy notes.",
            "deployment in practice is set out in [`TERMS.md`](TERMS.md).",
        ),
        LineEdit(
            "| **Product tiers / entitlements** |",
            (
                " See the internal strategy notes for the open-core boundary.",
                "",
            ),
        ),
    ),
    "SECURITY.md": (
        LineEdit(
            "  off/opt-in and say so honestly — see the internal roadmap).",
            "  off/opt-in and say so honestly).",
        ),
    ),
    "docs/README.md": (
        LineEdit(
            "This set was consolidated from ~38 scattered files into the hubs below. Start with",
            "The documentation is organized into the hubs below. Start with",
        ),
        LineEdit(
            "**Getting Started**; operators go to **Operations**; the strategy/roadmap docs are the",
            "**Getting Started**; operators go to **Operations**.",
        ),
        LineEdit("business view.", None),
        LineEdit("## Strategy & business", "## Background"),
        LineEdit("| the internal strategy notes |", None),
        LineEdit("| the internal developer-experience review |", None),
        LineEdit("| the internal roadmap |", None),
        LineEdit("| the project's narrative deck |", None),
    ),
    ".github/pull_request_template.md": (
        LineEdit(
            "for anything checked, state how the invariant is preserved (see CLAUDE.md /",
            "for anything checked, state how the invariant is preserved (see CONTRIBUTING.md §3).",
        ),
        LineEdit(".claude/skills/semantic-context-lake/references/invariants.md).", None),
        LineEdit("## Docs & context-lake", "## Docs"),
        LineEdit("- [ ] Updated `.claude/skills/semantic-context-lake/references/`", None),
    ),
    "docs/build/IMPLEMENTATION_WEB.md": (
        LineEdit(
            "## 13. Quickstart (identical across `README.md`, `IMPLEMENTATION_WEB.md`, the project's narrative deck)",
            "## 13. Quickstart (identical across `README.md` and `IMPLEMENTATION_WEB.md`)",
        ),
    ),
}

#: ``(file, heading)`` sections dropped from the package: maintainer action
#: items that are not policy and would only confuse a reader of the release.
SECTION_DROPS: tuple[tuple[str, str], ...] = (
    ("LICENSING.md", "## ⚖️ Legal note (please read before public release)"),
)


class BuildError(RuntimeError):
    """A packaging invariant failed. The build stops; nothing is written."""


# --------------------------------------------------------------------------
# 5. Selection
# --------------------------------------------------------------------------


def _is_pruned(rel: str, name: str, *, is_dir: bool) -> bool:
    if any(rel.startswith(keep) for keep in PRUNE_EXCEPTIONS):
        return False
    if is_dir:
        return name in PRUNE_DIR_NAMES or name.endswith(PRUNE_DIR_SUFFIXES)
    return name in PRUNE_FILE_NAMES or name.endswith(PRUNE_FILE_SUFFIXES)


def _walk(root: Path, base: Path) -> Iterable[Path]:
    """Yield packageable files under ``root``, deterministically ordered."""
    for entry in sorted(root.iterdir(), key=lambda p: p.name):
        rel = entry.relative_to(base).as_posix()
        if _is_pruned(rel, entry.name, is_dir=entry.is_dir()):
            continue
        if entry.is_symlink():          # never follow a link out of the tree
            continue
        if entry.is_dir():
            yield from _walk(entry, base)
        elif entry.is_file():
            yield entry


def select_files(repo: Path) -> list[str]:
    selected: list[str] = []
    for name in INCLUDE_ROOT_FILES:
        path = repo / name
        if not path.is_file():
            raise BuildError(f"allowlisted root file is missing: {name}")
        selected.append(name)
    for name in INCLUDE_DIRS:
        directory = repo / name
        if not directory.is_dir():
            raise BuildError(f"allowlisted directory is missing: {name}")
        for path in _walk(directory, repo):
            rel = path.relative_to(repo).as_posix()
            if rel in EXCLUDED_DOC_PATHS:
                continue
            if any(rel == p or rel.startswith(p) for p in EXCLUDE_PATHS):
                continue
            selected.append(rel)
    return sorted(set(selected))


def report_unreviewed(repo: Path, selected: Iterable[str]) -> list[str]:
    """Top-level entries that are neither allowlisted nor deliberately excluded.

    Not an error — a new file appearing here means someone added something the
    allowlist has not yet considered, which is exactly the state this build is
    designed to surface rather than resolve on its own.
    """
    known = set(INCLUDE_ROOT_FILES) | set(INCLUDE_DIRS)
    known |= {p.rstrip("/") for p in EXCLUDE_PATHS}
    unreviewed = []
    for entry in sorted(repo.iterdir(), key=lambda p: p.name):
        if entry.name in known or entry.name == ".git":
            continue
        if _is_pruned(entry.name, entry.name, is_dir=entry.is_dir()):
            continue
        unreviewed.append(entry.name + ("/" if entry.is_dir() else ""))
    return unreviewed


# --------------------------------------------------------------------------
# 6. Rewrites
# --------------------------------------------------------------------------


def _drop_section(text: str, heading: str) -> str:
    lines = text.splitlines(keepends=True)
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == heading)
    except StopIteration:
        raise BuildError(f"section to drop not found: {heading!r}") from None
    level = len(heading) - len(heading.lstrip("#"))
    end = len(lines)
    for i in range(start + 1, len(lines)):
        stripped = lines[i].lstrip()
        if stripped.startswith("#"):
            depth = len(stripped) - len(stripped.lstrip("#"))
            if 0 < depth <= level:
                end = i
                break
    return "".join(lines[:start] + lines[end:])


def _apply_line_edits(rel: str, text: str) -> str:
    edits = LINE_EDITS.get(rel)
    if not edits:
        return text
    lines = text.splitlines(keepends=True)
    for edit in edits:
        matches = [i for i, line in enumerate(lines) if edit.anchor in line]
        if len(matches) != 1:
            raise BuildError(
                f"{rel}: anchor {edit.anchor!r} matched {len(matches)} lines, expected exactly 1 "
                "— upstream prose changed; update LINE_EDITS in this script"
            )
        index = matches[0]
        original = lines[index]
        newline = "\n" if original.endswith("\n") else ""
        result = edit.apply(original.rstrip("\n"))
        if result is None:
            lines[index] = ""
        else:
            lines[index] = result + newline
    return "".join(line for line in lines if line != "")


def _excluded_doc_pattern(doc: str) -> re.Pattern[str]:
    """Match a reference to an excluded document in any form it appears.

    Covers the Markdown link ``[text](docs/X.md#anchor)``, the inline-code
    citation ``` `docs/X.md §3.4` ```, and the bare prose mention ``X.md §2`` —
    together with an optional ``docs/`` prefix and an optional section suffix.
    """
    stem = re.escape(doc)
    return re.compile(
        r"\[[^\]\n]*\]\(\.?/?(?:docs/)?" + stem + r"(?:#[^)\n]*)?\)"    # markdown link
        r"|`(?:\.\./)?(?:docs/)?" + stem + r"(?:\s*(?:§|#)[^`\n]*)?`"   # inline code
        r"|(?:docs/)?" + stem + r"(?:\s*§\s*[0-9A-Za-z.–-]+)?"     # bare prose
    )


_EXCLUDED_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (_excluded_doc_pattern(doc), phrase) for doc, phrase in EXCLUDED_DOCS.items()
)


def _tidy_phrase(text: str, phrase: str) -> str:
    """Make a substituted phrase read like prose rather than like a substitution.

    A source sentence citing the same internal document twice ("(the internal roadmap)") collapses to one mention, and a citation that opened a
    sentence keeps its capital letter.
    """
    quoted = re.escape(phrase)
    text = re.sub(rf"{quoted}(?:\s*(?:,|;|·|and)\s*{quoted})+", phrase, text)
    capitalized = phrase[0].upper() + phrase[1:]
    text = re.sub(rf"(?<=[.!?:]\s){quoted}", capitalized, text)
    text = re.sub(rf"(?<=\*\*\s){quoted}", capitalized, text)
    # At a line start, capitalize only when the previous line actually ended a
    # sentence — these documents wrap mid-sentence constantly, and a wrapped
    # continuation must stay lowercase.
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if not line.startswith(phrase):
            continue
        previous = lines[i - 1].rstrip() if i else ""
        if not previous or previous.endswith((".", "!", "?", ":")):
            lines[i] = capitalized + line[len(phrase):]
    return "\n".join(lines)


def rewrite_text(rel: str, text: str) -> str:
    for name, heading in SECTION_DROPS:
        if rel == name:
            text = _drop_section(text, heading)
    text = _apply_line_edits(rel, text)
    for pattern, phrase in _EXCLUDED_PATTERNS:
        text = pattern.sub(phrase, text)
    for phrase in dict.fromkeys(EXCLUDED_DOCS.values()):
        text = _tidy_phrase(text, phrase)
    for old, new in REPO_SLUG_REWRITES:
        text = text.replace(old, new)
    return text


# --------------------------------------------------------------------------
# 7. Verification
# --------------------------------------------------------------------------

_MD_LINK = re.compile(r"\[[^\]\n]*\]\(([^)\s]+)")


def verify(stage: Path, files: list[str]) -> list[str]:
    """Assert the package is internally consistent. Returns non-fatal warnings."""
    warnings: list[str] = []
    packaged = set(files)
    forbidden = tuple(EXCLUDED_DOCS) + tuple(p.rstrip("/") for p in EXCLUDE_PATHS)

    for rel in files:
        path = stage / rel
        if path.suffix not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        # The manifest and this builder legitimately *name* what they hold back.
        if rel not in ("PACKAGE_MANIFEST.json", "scripts/build_production_package.py"):
            for token in forbidden:
                if token in text:
                    line = next(
                        (n for n, l in enumerate(text.splitlines(), 1) if token in l), 0
                    )
                    raise BuildError(
                        f"{rel}:{line} references excluded material {token!r} — "
                        "add a LINE_EDITS entry or widen the rewrite patterns"
                    )
            for old, _ in REPO_SLUG_REWRITES:
                if old in text:
                    raise BuildError(f"{rel}: stale repository slug {old!r} survived the rewrite")

        if path.suffix != ".md":
            continue
        for target in _MD_LINK.findall(text):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            clean = target.split("#", 1)[0]
            if not clean or not clean.endswith(".md"):
                continue
            # Lexical normalization only — never touches the filesystem, so the
            # result cannot depend on the caller's working directory.
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(rel), clean))
            if resolved not in packaged:
                warnings.append(f"{rel}: relative link does not resolve in-package -> {target}")
    return warnings


# --------------------------------------------------------------------------
# 8. Build
# --------------------------------------------------------------------------


@dataclass
class BuildResult:
    version: str
    files: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    unreviewed: list[str] = field(default_factory=list)
    archive: Optional[Path] = None
    stage: Optional[Path] = None


def _git(repo: Path, *args: str) -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", *args], cwd=repo, capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None if out.returncode == 0 else None


def build(repo: Path, out_dir: Path, *, check_only: bool, keep_tree: bool) -> BuildResult:
    version = (repo / "VERSION").read_text(encoding="utf-8").strip()
    files = select_files(repo)
    result = BuildResult(version=version, unreviewed=report_unreviewed(repo, files))

    stage_root = out_dir / f"mcpip-{version}"
    if stage_root.exists():
        shutil.rmtree(stage_root)
    stage_root.mkdir(parents=True)

    for rel in files:
        src, dst = repo / rel, stage_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.suffix in TEXT_SUFFIXES:
            try:
                dst.write_text(
                    rewrite_text(rel, src.read_text(encoding="utf-8")), encoding="utf-8"
                )
                shutil.copymode(src, dst)
                continue
            except UnicodeDecodeError:
                pass
        shutil.copy2(src, dst)

    manifest = {
        "package": "mcpip",
        "version": version,
        "distribution": "public production distribution",
        "license": {
            "core": "BSL-1.1 (see LICENSE; converts to Apache-2.0 on 2030-07-16)",
            "sdk/python, sdk/typescript": "Apache-2.0",
        },
        "source": {
            "repository": "https://github.com/mcpip-security/mcpip",
            "commit": _git(repo, "rev-parse", "HEAD"),
            "branch": _git(repo, "rev-parse", "--abbrev-ref", "HEAD"),
        },
        "excluded": {
            "reason": "maintainers' internal business and agent-tooling material; not part of the product",
            "documents": sorted(EXCLUDED_DOC_PATHS),
            "paths": sorted(EXCLUDE_PATHS),
        },
        "file_count": len(files),
        "files": {},
    }

    digests: dict[str, str] = {}
    for rel in files:
        digests[rel] = hashlib.sha256((stage_root / rel).read_bytes()).hexdigest()
    manifest["files"] = digests
    (stage_root / "PACKAGE_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    files.append("PACKAGE_MANIFEST.json")

    result.files = files
    result.warnings = verify(stage_root, files)
    result.stage = stage_root

    if check_only:
        shutil.rmtree(stage_root)
        result.stage = None
        return result

    archive = out_dir / f"mcpip-{version}-production.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for rel in sorted(files):
            info = zipfile.ZipInfo(f"mcpip-{version}/{rel}", date_time=(1980, 1, 1, 0, 0, 0))
            source = stage_root / rel
            info.external_attr = (0o755 if source.stat().st_mode & 0o100 else 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, source.read_bytes())
    result.archive = archive

    if not keep_tree:
        shutil.rmtree(stage_root)
        result.stage = None
    return result


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out-dir", type=Path, default=REPO_ROOT / "dist")
    parser.add_argument("--check", action="store_true", help="verify only; write no archive")
    parser.add_argument("--keep-tree", action="store_true", help="leave the staged tree in place")
    args = parser.parse_args(argv)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = build(REPO_ROOT, args.out_dir, check_only=args.check, keep_tree=args.keep_tree)
    except BuildError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1

    print(f"mcpip {result.version} — {len(result.files)} files")
    print(f"  excluded documents : {', '.join(sorted(EXCLUDED_DOC_PATHS))}")
    print(f"  excluded paths     : {', '.join(sorted(EXCLUDE_PATHS))}")
    for entry in result.unreviewed:
        print(f"  NOT ALLOWLISTED (held back): {entry}")
    for warning in result.warnings:
        print(f"  warning: {warning}")
    if result.stage:
        print(f"  staged tree        : {result.stage}")
    if result.archive:
        digest = hashlib.sha256(result.archive.read_bytes()).hexdigest()
        size = result.archive.stat().st_size
        print(f"  archive            : {result.archive} ({size:,} bytes)")
        print(f"  sha256             : {digest}")
    else:
        print("  check only — no archive written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
