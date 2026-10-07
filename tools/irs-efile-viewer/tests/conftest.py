"""Shared fixtures for the irs-efile-viewer tests.

Most tests are hermetic: they build a small synthetic stylesheet tree in a temp dir.
The end-to-end tests render real filings with the real IRS stylesheets; they run when a
tree is installed (``irs-efile-viewer fetch``, ``$IRS_EFILE_MEF_DIR``) and are skipped
otherwise — unless ``IRS_EFILE_REQUIRE_MEF=1``, as in CI, where a missing tree fails.

The repository-wide ``pytest`` run (the gateway's backend CI job) collects these too. Its
environment has lxml (a transitive development dependency) but neither python-multipart
nor a stylesheet tree, so there the hermetic tests run and the web and end-to-end ones
skip. Without lxml, nothing here is collected.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
FILINGS = Path(__file__).resolve().parent / "fixtures" / "filings"

try:
    import lxml  # noqa: F401
except ImportError:  # the gateway's own test environment
    collect_ignore_glob = ["test_*.py"]
else:
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))
    from irs_efile_helpers import build_tree


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    return build_tree(tmp_path)


@pytest.fixture(scope="session")
def real_store():
    """The real IRS stylesheet tree, or skip (fail under IRS_EFILE_REQUIRE_MEF=1)."""
    from irs_efile_viewer.mef import MefError, MefStore

    try:
        return MefStore.locate()
    except MefError as exc:
        if os.environ.get("IRS_EFILE_REQUIRE_MEF") == "1":
            pytest.fail(f"IRS_EFILE_REQUIRE_MEF=1 but no stylesheet tree: {exc}")
        pytest.skip(f"real IRS stylesheets not installed ({exc})")
