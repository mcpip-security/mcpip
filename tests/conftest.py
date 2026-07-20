"""
Session/module-scoped test harness fixtures.

WORM anchor isolation
---------------------
The signed WORM epoch chain lives in Redis, but its out-of-tamper-domain rollback
witness — the ``AnchorStore`` low-watermark — is an on-disk append-only file
(``audit/anchor.py``). Per-module test setup flushes the Redis test DB, but a
``flushdb`` does NOT touch the disk anchor. So an anchor written while module A
sealed epochs survives into module B, whose fresh (flushed) chain then reads a
witnessed head that no longer exists → ``verify_chain`` reports a false rollback,
spuriously failing WORM-verify assertions when the whole suite runs in one
``pytest tests/`` invocation (every module passes in isolation).

Fix it at the harness level, NOT by weakening any tamper-evidence assertion: remove
BOTH on-disk anchor files BETWEEN WORM-touching modules (module scope), so each
module starts with a clean anchor consistent with its freshly-flushed Redis chain.
Within a module the anchor still accumulates normally, so the intra-module
rollback-detection tests (which deliberately exercise the anchor low-watermark) are
untouched.

Two anchor files exist and both must be cleared — note the LEADING-DOT test file a
naive ``*.anchor`` glob would miss:
  * ``<repo>/mcpip_worm.jsonl.anchor``            (default ``MCPIP_WORM_PATH`` + ".anchor")
  * ``<repo>/tests/.mcpip_test_worm.jsonl.anchor`` (the suite's namespaced worm path)

The WORM emit/verify PRODUCT code is untouched — this is purely test lifecycle hygiene.
"""

from __future__ import annotations

import os
from typing import Iterator

import pytest

_TESTS_DIR = os.path.dirname(__file__)
_REPO_ROOT = os.path.dirname(_TESTS_DIR)

# Both on-disk anchor files a WORM-touching module may have written, PLUS the atomic
# rewrite temp file ``AnchorStore._compact_file`` uses. Absolute paths so cwd is
# irrelevant. The leading-dot test file is enumerated explicitly (a "*.anchor" glob
# would silently skip a dotfile on the default glob flags).
_ANCHOR_FILES: tuple[str, ...] = (
    os.path.join(_REPO_ROOT, "mcpip_worm.jsonl.anchor"),
    os.path.join(_REPO_ROOT, "mcpip_worm.jsonl.anchor.tmp"),
    os.path.join(_TESTS_DIR, ".mcpip_test_worm.jsonl.anchor"),
    os.path.join(_TESTS_DIR, ".mcpip_test_worm.jsonl.anchor.tmp"),
)


def _remove_stale_anchor_files() -> None:
    """Best-effort removal of every on-disk WORM anchor artifact."""
    for path in _ANCHOR_FILES:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


@pytest.fixture(autouse=True, scope="module")
def _clear_worm_anchor_between_modules() -> Iterator[None]:
    """
    Remove the on-disk WORM anchor files at the boundary of every test module.

    Module-scoped + autouse: runs before the first test of each module (so a fresh,
    flushed Redis chain never inherits a prior module's disk witness) and again after
    the last (so nothing leaks forward). It runs BEFORE the module's own ``client``
    fixture flushes Redis, keeping the anchor and the chain consistent. Never
    per-function — that would erase an anchor mid-module and defeat the tests that
    intentionally exercise anchor rollback-detection.
    """
    _remove_stale_anchor_files()
    yield
    _remove_stale_anchor_files()
