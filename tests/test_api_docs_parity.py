"""
MCPIP — docs/start/API.md must list the vendor registry as it actually ships.

"82 named vendor ids" was a headline claim in the README, the API reference and
the website, but the 82 strings appeared nowhere: a developer who wanted to send
`vendor` instead of choosing a `source_format` had to read
`bridge/connectors/registry.py` to find a legal value, and a wrong guess is an
opaque 403 that tells them nothing.

The list is now in the doc, which means it can drift. Adding a vendor is already
a deliberate registry re-pin; this makes it a documentation change too.
"""

from __future__ import annotations

import os
import re

from bridge.connectors.registry import VENDOR_FORMAT

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_API_DOC = os.path.join(_REPO_ROOT, "docs", "start", "API.md")

#: The registry keys are `Vendor` enum members; the doc names their wire values.
_VENDOR_IDS = {str(getattr(v, "value", v)) for v in VENDOR_FORMAT}


def _vendor_table() -> str:
    """Just the vendor-id table, so unrelated backticks elsewhere are not read as ids."""
    with open(_API_DOC, encoding="utf-8") as handle:
        doc = handle.read()
    body = doc.split("#### The vendor ids", 1)[1]
    return body.split("\nA vendor id is a routing convenience", 1)[0]


def test_every_shipped_vendor_id_is_documented() -> None:
    table = _vendor_table()
    missing = sorted(v for v in _VENDOR_IDS if f"`{v}`" not in table)
    assert not missing, f"API.md does not list shipped vendor ids: {missing}"


def test_no_documented_vendor_id_is_invented() -> None:
    """The table may not name a vendor the registry would refuse with an opaque 403."""
    table = _vendor_table()
    listed = set(re.findall(r"`([a-z0-9_]+)`", table))
    # The left column names formats, not vendors.
    listed -= {str(getattr(f, "value", f)) for f in VENDOR_FORMAT.values()}
    listed -= {"raw_mcp", "vendor"}  # column header words, not ids
    bogus = sorted(listed - _VENDOR_IDS)
    assert not bogus, f"API.md lists vendor ids the registry does not know: {bogus}"


def test_the_documented_count_matches_the_registry() -> None:
    """The headline number must be the real one wherever it is claimed."""
    count = len(_VENDOR_IDS)
    for name in ("docs/start/API.md", "README.md", "docs/integrate/REPOSITORY.md"):
        with open(os.path.join(_REPO_ROOT, name), encoding="utf-8") as handle:
            text = handle.read()
        for stated in re.findall(r"(\d+)\s+(?:named\s+)?vendor ids", text):
            assert int(stated) == count, (
                f"{name} claims {stated} vendor ids; the registry ships {count}"
            )
