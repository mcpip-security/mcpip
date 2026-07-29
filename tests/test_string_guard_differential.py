"""
MCPIP — the ingress string guard's fast path must be a speed change and nothing else.

    ◐ "An optimization in a canonicalization input is a correctness change until proven
       otherwise."

``reject_unsafe_string`` sits upstream of everything that must stay byte-identical: the
canonical JSON, the payload-bound PIN hash, the WORM record. Its return value is what
callers store and hash. So making it faster is not a local decision — if the fast path
ever accepted one string the slow path rejects, or returned a different NFC form, the
register/consume hashes would diverge and a lock would silently stop matching its payload.

The fast path skips the per-character scan when the NFC form is printable ASCII, on the
argument that U+0020..U+007E is disjoint from every forbidden set. That argument is
checkable by exhaustion rather than by reading, so this file checks it by exhaustion: the
reference implementation is kept here verbatim and compared against the shipped one over
EVERY codepoint in Unicode, then over adversarial strings built from the codepoints that
sit on each boundary.

The reference below is the pre-optimization body. It is deliberately duplicated rather
than imported — a differential test that shares an implementation with its subject proves
nothing.
"""

from __future__ import annotations

import os
import sys
import unicodedata
from typing import Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from interfaces import (
    MAX_STRING_LEN,
    _FORBIDDEN_CATEGORIES,
    _FORBIDDEN_RANGES,
    _ZERO_WIDTH,
    reject_unsafe_string,
)

# Surrogates cannot appear in a well-formed str and ``unicodedata.normalize`` rejects them;
# every other codepoint is in scope.
_SURROGATES = range(0xD800, 0xE000)


def _reference_is_forbidden(cp: int) -> bool:
    """The original predicate, verbatim."""
    if cp in _ZERO_WIDTH:
        return True
    for lo, hi in _FORBIDDEN_RANGES:
        if lo <= cp <= hi:
            return True
    if unicodedata.category(chr(cp)) in _FORBIDDEN_CATEGORIES:
        return True
    return False


def _reference(s: str, field: str) -> str:
    """The original ``reject_unsafe_string`` body, verbatim — no fast path."""
    nfc = unicodedata.normalize("NFC", s)
    for ch in nfc:
        if _reference_is_forbidden(ord(ch)):
            raise ValueError(f"illegal character U+{ord(ch):04X} in field '{field}'")
    if len(nfc) > MAX_STRING_LEN:
        raise ValueError(
            f"field '{field}' exceeds MAX_STRING_LEN ({len(nfc)} > {MAX_STRING_LEN})"
        )
    return nfc


def _outcome(fn: Callable[[str, str], str], s: str) -> tuple[str, str]:
    """('ok', returned) or ('err', message) — compares the message too, because upstream
    maps it and an operator reads it."""
    try:
        return ("ok", fn(s, "probe"))
    except ValueError as exc:
        return ("err", str(exc))


# ---------------------------------------------------------------------------
# The load-bearing claim, checked by exhaustion.
# ---------------------------------------------------------------------------


def test_printable_ascii_is_disjoint_from_every_forbidden_set() -> None:
    """The whole justification for the fast path, stated as an assertion over the band it
    skips. If a future edit added a forbidden codepoint inside printable ASCII — a
    plausible thing to want, e.g. banning a quote character — the fast path would silently
    stop enforcing it, and this fires before that ships."""
    for cp in range(0x20, 0x7F):
        assert not _reference_is_forbidden(cp), (
            f"U+{cp:04X} is forbidden but lives in the band the fast path skips — the "
            f"skip must be narrowed or removed before this codepoint can be banned"
        )


def test_str_isprintable_means_exactly_the_band_we_claim() -> None:
    """The fast path's gate is ``isascii() and isprintable()``; its soundness argument is
    that this pair means 'every codepoint is U+0020..U+007E'. CPython's definition is
    checked directly rather than trusted from the docs."""
    for cp in range(0x00, 0x80):
        ch = chr(cp)
        assert ch.isascii()
        assert ch.isprintable() is (0x20 <= cp <= 0x7E), f"U+{cp:04X}"


def test_every_codepoint_decides_identically() -> None:
    """The exhaustive sweep: all ~1.1M codepoints, one-character strings, shipped vs
    reference. Sampling would leave exactly the rare bands — bidi marks, format
    characters, unusual separators — untested, and those are the ones the guard exists
    for."""
    divergences: list[str] = []
    for cp in range(0x110000):
        if cp in _SURROGATES:
            continue
        s = chr(cp)
        got, want = _outcome(reject_unsafe_string, s), _outcome(_reference, s)
        if got != want:
            divergences.append(f"U+{cp:04X}: shipped={got!r} reference={want!r}")
            if len(divergences) >= 20:
                break
    assert not divergences, "fast path changed a decision:\n" + "\n".join(divergences)


def test_boundary_codepoints_survive_in_context() -> None:
    """Single characters exercise the predicate; real payloads are mixtures. These are the
    codepoints that sit exactly on a boundary, each embedded in ASCII so the string as a
    whole is non-ASCII and must take the slow path — the case where a fast path that
    checked the WRONG property (say, ``isascii()`` alone) would wrongly skip."""
    boundaries = [
        0x001F,  # last C0
        0x0020,  # first printable ASCII
        0x007E,  # last printable ASCII
        0x007F,  # DEL
        0x0080,  # first C1
        0x009F,  # last C1
        0x00AD,  # SOFT HYPHEN
        0x061C,  # ARABIC LETTER MARK (Cf, outside every explicit range)
        0x200B,  # ZERO WIDTH SPACE
        0x200E,  # LEFT-TO-RIGHT MARK (Cf — the category-only reject)
        0x2028,  # LINE SEPARATOR (Zl)
        0x2029,  # PARAGRAPH SEPARATOR (Zp)
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2066,  # first bidi isolate
        0x2069,  # last bidi isolate
        0x3000,  # IDEOGRAPHIC SPACE (Zs — allowed, and must stay allowed)
        0xFEFF,  # BOM
    ]
    for cp in boundaries:
        for template in ("{c}", "prefix{c}", "{c}suffix", "pre{c}post"):
            s = template.format(c=chr(cp))
            assert _outcome(reject_unsafe_string, s) == _outcome(_reference, s), (
                f"U+{cp:04X} in {template!r}"
            )


@pytest.mark.parametrize(
    "sample",
    [
        "",
        " ",
        "skill_spend_summary",
        "quarterly revenue reconciliation for EMEA, ledger 2026-Q2",
        "~!@#$%^&*()_+-={}[]|\\:;\"'<>,.?/",
        "tab\there",
        "newline\nhere",
        "null\x00here",
        "réconciliation trimestrielle",
        "é",  # precomposed e-acute
        "é",  # decomposed — NFC must fold it to the above
        "\U0001F600",  # astral plane
        "a" * MAX_STRING_LEN,
        "a" * (MAX_STRING_LEN + 1),
        "é" * (MAX_STRING_LEN + 1),
    ],
)
def test_representative_payloads_agree(sample: str) -> None:
    """Named cases that a reader can check by eye, including the two that make the guard's
    ORDER load-bearing: NFC before the length check (a decomposed string that fits only
    after folding), and over-length in both ASCII and non-ASCII form."""
    assert _outcome(reject_unsafe_string, sample) == _outcome(_reference, sample)


def test_nfc_folding_is_unchanged_by_the_fast_path() -> None:
    """The return value is what callers hash. A decomposed input whose NFC form is pure
    ASCII must still come back FOLDED — if the fast path ever short-circuited before
    normalization, register and consume would hash different bytes for the same payload
    and the PIN lock would stop matching."""
    assert reject_unsafe_string("é", "f") == "é"
    assert reject_unsafe_string("Å", "f") == "Å"


def test_length_ceiling_still_applies_on_the_fast_path() -> None:
    """The fast path skips the CHARACTER scan only. An over-length printable-ASCII string
    is the exact shape that would slip through if the skip were placed one line too far
    down."""
    with pytest.raises(ValueError, match="MAX_STRING_LEN"):
        reject_unsafe_string("a" * (MAX_STRING_LEN + 1), "f")


def test_the_rust_mirror_still_defers_exactly_what_python_fast_paths() -> None:
    """The cross-language half of the same argument.

    ``rust/mcpip_fastwalk`` decides pure ASCII in-process and DEFERS everything else to
    Python, because the Cc/Cf/Zl/Zp category reject is Unicode-version dependent. Python's
    new fast path relies on the SAME fact from the other side — that printable ASCII needs
    no category lookup. The two are only safe together while Rust keeps deferring
    non-ASCII; a Rust edit that started deciding non-ASCII locally would put a
    version-sensitive judgement back in the accelerator.

    This is asserted against the Rust SOURCE rather than by running it: the crate pins
    Unicode 15.0.0 and the shim refuses to activate unless CPython's ``unidata_version``
    matches, so on any interpreter with a different UCD the accelerator is off and a
    behavioural parity test would silently skip — passing while proving nothing.
    """
    from pathlib import Path

    rust = Path(__file__).resolve().parents[1] / "rust" / "mcpip_fastwalk" / "src" / "lib.rs"
    if not rust.exists():  # pragma: no cover — accelerator source not vendored here.
        pytest.skip("rust/mcpip_fastwalk/src/lib.rs is not present in this checkout")
    source = rust.read_text(encoding="utf-8")
    body = source[source.index("fn reject_unsafe_string") :]
    body = body[: body.index("\n}\n")]
    assert "if !nfc.is_ascii()" in body and "defer_err()" in body, (
        "the Rust mirror no longer defers non-ASCII — it would be deciding "
        "version-sensitive Cc/Cf/Zl/Zp territory locally, which is the exact judgement "
        "both fast paths are built to avoid"
    )


def test_randomized_mixtures_agree() -> None:
    """Deterministic pseudo-random mixtures of allowed and forbidden codepoints. The
    exhaustive sweep covers single characters; this covers ORDERING — specifically that
    the shipped guard still reports the FIRST offending codepoint, not merely some
    offending one, since the message names the character an operator will go looking for.
    """
    import random

    rng = random.Random(20260725)
    alphabet = [chr(c) for c in range(0x20, 0x7F)] + [
        "é", "​", "‎", " ", "‮", "﻿", "　", "\x01",
    ]
    for _ in range(3000):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 24)))
        assert _outcome(reject_unsafe_string, s) == _outcome(_reference, s), repr(s)
