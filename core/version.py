"""
MCPIP V2 — Core: the single source of truth for the release version.

    ◐ "Authorize every AI action before execution."

The release version lives in exactly ONE place — the ``VERSION`` file at the repo
root — and every runtime surface (FastAPI ``version=``, the MCP ``serverInfo``
card, ``/healthz``) reads it through :func:`get_version`. There is deliberately NO
fallback constant: a missing or malformed ``VERSION`` file is a fail-closed boot
error, because a gateway that cannot prove which release it is must not claim to
be any release at all (the signed release/integrity manifests are keyed by this
version).
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

# Strict SemVer core grammar (MAJOR.MINOR.PATCH, no pre-release/build metadata) —
# matches the release manifest / image tag scheme exactly.
_VERSION_PATTERN = r"\d+\.\d+\.\d+"


@lru_cache(maxsize=1)
def get_version() -> str:
    """
    Read, validate, and cache the release version from the repo-root ``VERSION`` file.

    Fail-closed: an unreadable file or a value that is not exactly
    ``MAJOR.MINOR.PATCH`` (after stripping surrounding whitespace) raises
    ``RuntimeError`` — no default is ever substituted.
    """
    version_file = Path(__file__).resolve().parent.parent / "VERSION"
    try:
        raw = version_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError("VERSION file missing or malformed") from exc
    if re.fullmatch(_VERSION_PATTERN, raw) is None:
        raise RuntimeError("VERSION file missing or malformed")
    return raw


def parse_version(raw: str) -> tuple[int, int, int]:
    """
    Parse a strict ``MAJOR.MINOR.PATCH`` string into a comparable integer tuple.

    Fail-closed: anything that is not exactly the strict SemVer core grammar raises
    ``ValueError`` (never a best-effort partial parse) — an update decision must
    never rest on a version string the gateway could not fully understand.
    """
    text = raw.strip()
    if re.fullmatch(_VERSION_PATTERN, text) is None:
        raise ValueError(f"not a strict MAJOR.MINOR.PATCH version: {raw!r}")
    major, minor, patch = (int(part) for part in text.split("."))
    return major, minor, patch


def is_newer(candidate: str, baseline: str) -> bool:
    """
    True iff ``candidate`` is a strictly higher release than ``baseline``.

    Both operands must be strict SemVer cores; a malformed operand raises
    ``ValueError`` (the caller decides how to fail — an unparseable "latest" is
    treated as *no* update, never as an update).
    """
    return parse_version(candidate) > parse_version(baseline)
