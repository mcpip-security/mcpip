"""
MCPIP V2 — unit tests for the release-version / update-decision core.

    ◐  "Authorize every AI action before execution."

These are pure functions (no Redis, no app boot): the strict SemVer parse and the
``is_newer`` comparison that decides whether ``/v1/version`` reports an available
update. The update surface is a NOTIFIER — the only thing that must be exactly right
here is the ordering (never claim an update that is not strictly newer) and the
fail-closed parse (never guess at a version string we could not fully understand).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from core.version import is_newer, parse_version


def test_parse_version_strict_tuple() -> None:
    assert parse_version("2.0.0") == (2, 0, 0)
    assert parse_version("10.4.13") == (10, 4, 13)
    # Surrounding whitespace is tolerated (mirrors the VERSION-file reader).
    assert parse_version("  1.2.3\n") == (1, 2, 3)


@pytest.mark.parametrize(
    "bad",
    ["2.0", "2.0.0.0", "v2.0.0", "2.0.0-rc1", "2.0.0+build", "", "latest", "2.0.x"],
)
def test_parse_version_fail_closed(bad: str) -> None:
    """Anything but a strict MAJOR.MINOR.PATCH is a hard ValueError — never a guess."""
    with pytest.raises(ValueError):
        parse_version(bad)


def test_is_newer_ordering() -> None:
    assert is_newer("2.1.0", "2.0.0") is True
    assert is_newer("2.0.1", "2.0.0") is True
    assert is_newer("3.0.0", "2.9.9") is True
    # Equal is NOT newer — an equal manifest must never surface "update available".
    assert is_newer("2.0.0", "2.0.0") is False
    # Older is never newer (no downgrade nudges).
    assert is_newer("2.0.0", "2.1.0") is False
    assert is_newer("1.9.9", "2.0.0") is False


def test_is_newer_numeric_not_lexical() -> None:
    """10 > 9 numerically — a lexical compare would wrongly rank '2.9.0' over '2.10.0'."""
    assert is_newer("2.10.0", "2.9.0") is True
    assert is_newer("2.9.0", "2.10.0") is False


def test_is_newer_propagates_parse_failure() -> None:
    """A malformed operand raises — the endpoint catches it and reports NO update."""
    with pytest.raises(ValueError):
        is_newer("garbage", "2.0.0")
    with pytest.raises(ValueError):
        is_newer("2.0.0", "garbage")
