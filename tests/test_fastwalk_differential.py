"""
MCPIP V2 — Differential fuzz: Rust fast-walker vs pure-Python (the enabling gate).

The Rust accelerator (``mcpip_fastwalk``) is opt-in via ``MCPIP_FAST_WALKER=1`` and may
ONLY be recommended-on after this differential fuzz is green with **zero divergences**,
because the payload-lock hash binds register-time to consume-time: any byte or decision
drift between the two canonicalizers is a CRITICAL, must-fix bug.

Before any input is drawn the gate asserts an input-INDEPENDENT precondition: the crate's
bundled Unicode version (``mcpip_fastwalk.UNICODE_VERSION``) exactly equals this CPython's
``unicodedata.unidata_version``. A skew silently reorders combining marks (canonically the
U+1AB0..U+1AFF extended block) and is an immediate RED — see ``_assert_unicode_parity``.

For every generated input we then assert all three:
  1. ``canonical_json`` byte-identity whenever both accept (incl. via the float/big-int/
     surrogate/non-ASCII-NFKC-key DEFERRAL path, which falls back to pure-Python for that
     whole payload).
  2. ``enforce_argument_safety`` agrees on accept-vs-reject.
  3. On reject, ``map_engine_exception(rust_exc).reason == map_engine_exception(py_exc)
     .reason`` — identical ``DenyReason``.

Coverage that the audit found missing and this gate now includes: the full
U+1AB0..U+1AFF Combining Diacritical Marks Extended block paired adjacent to classic
below-marks (the exact NFC canonical-reordering skew), plus non-ASCII-NFKC identity keys
that force the casefold DEFER path.

Run standalone for the full gate (defaults to 1_000_000 iterations plus the enumerated
adversarial corpus):

    MCPIP_FAST_WALKER=1 .venv/bin/python tests/test_fastwalk_differential.py 1000000

A small deterministic slice also runs under pytest as ``test_differential_smoke``.
"""

from __future__ import annotations

import os
import random
import sys
import unicodedata
from typing import Any, Callable

# Pure-Python source-of-truth implementations (never the dispatchers, to avoid recursion
# and to test the real Rust path head-to-head).
from interfaces import _canonical_json_py
from bridge.intent_parser import _enforce_argument_safety_py
from core.security import map_engine_exception

_rust: Any
try:
    import mcpip_fastwalk as _rust_mod  # type: ignore  # compiled ext: no stubs.

    _rust = _rust_mod
    _IMPORT_ERR: Exception | None = None
except Exception as exc:  # pragma: no cover - the gate cannot run without the ext.
    _rust = None
    _IMPORT_ERR = exc


def _assert_unicode_parity() -> None:
    """Fail the gate RED unless the crate's Unicode data matches CPython's.

    The byte-identity contract only holds when the Rust NFC/NFKC tables are the SAME
    Unicode version as this interpreter's ``unicodedata.unidata_version``. A skew silently
    reorders combining marks (the U+1AB0..U+1AFF extended block is the canonical example)
    and breaks the payload-lock hash. This is a DIRECT, input-independent detector: it goes
    RED the instant a build ships a mismatched crate, even before any fuzz input is drawn,
    so the accelerator can never be green-lit on a divergent canonicalizer.
    """
    if _rust is None:  # pragma: no cover - the gate cannot run without the ext.
        raise RuntimeError(f"mcpip_fastwalk not importable: {_IMPORT_ERR!r}")
    rust_version = getattr(_rust, "UNICODE_VERSION", None)
    if rust_version != unicodedata.unidata_version:
        raise Divergence(
            "Unicode-data skew: mcpip_fastwalk.UNICODE_VERSION="
            f"{rust_version!r} != unicodedata.unidata_version="
            f"{unicodedata.unidata_version!r}. The fast walker MUST NOT be enabled until "
            "the crate's bundled Unicode version exactly matches the deployed CPython's."
        )


# ---------------------------------------------------------------------------
# Rust-side wrappers that model the shim's DEFERRAL semantics exactly.
# ---------------------------------------------------------------------------
def _rust_canonical(obj: object) -> bytes:
    assert _rust is not None
    try:
        return bytes(_rust.canonical_json(obj))
    except _rust.Defer:
        return _canonical_json_py(obj)


def _rust_enforce(args: dict[str, Any]) -> dict[str, Any]:
    assert _rust is not None
    try:
        result: dict[str, Any] = _rust.enforce_argument_safety(args)
    except _rust.Defer:
        return _enforce_argument_safety_py(args)
    return result


# ---------------------------------------------------------------------------
# Generators.
# ---------------------------------------------------------------------------

# Zero-width + bidi + control adversarial characters (the exact bands the engine bans).
_ZERO_WIDTH = ["​", "‌", "‍", "⁠", "﻿", "­"]
_BIDI = ["‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩"]
_C0 = ["\x00", "\x01", "\x07", "\x08", "\x09", "\x0a", "\x0d", "\x1f"]
_C1 = ["\x7f", "\x80", "\x85", "\x9f"]
# Format / bidi / separator marks that live OUTSIDE the enumerated ZERO_WIDTH set and the
# FORBIDDEN_RANGES bands, so they are decided ONLY by the Cc/Cf/Zl/Zp general-category
# reject (interfaces.py:219). A fast-walker that omits that category check would ACCEPT
# these while pure-Python rejects them — the exact bidi/format-mark ingress-smuggling
# divergence this corpus now guards. Includes the left/right/arabic-letter marks (Cf), the
# Mongolian vowel separator (Cf), and the line/paragraph separators (Zl/Zp).
_FORMAT_MARKS = [
    "‎",  # LEFT-TO-RIGHT MARK (Cf) — not in ZERO_WIDTH, not in a forbidden range.
    "‏",  # RIGHT-TO-LEFT MARK (Cf).
    "؜",  # ARABIC LETTER MARK (Cf).
    "᠎",  # MONGOLIAN VOWEL SEPARATOR (Cf).
    " ",  # LINE SEPARATOR (Zl).
    " ",  # PARAGRAPH SEPARATOR (Zp).
    "⁡",  # FUNCTION APPLICATION (Cf).
    "⁢",  # INVISIBLE TIMES (Cf).
    "⁣",  # INVISIBLE SEPARATOR (Cf).
    "⁤",  # INVISIBLE PLUS (Cf).
    "￹",  # INTERLINEAR ANNOTATION ANCHOR (Cf).
    "￻",  # INTERLINEAR ANNOTATION TERMINATOR (Cf).
]
_COMBINING = ["́", "̀", "̣", "̧"]  # classic combining marks (NFC-relevant).
_SURROGATES = [chr(0xD800), chr(0xDBFF), chr(0xDC00), chr(0xDFFF)]

# Combining Diacritical Marks Extended (U+1AB0..U+1AFF) — THE coverage this gate
# previously lacked. Several codepoints in this block were assigned a non-zero canonical
# combining class only in a LATER Unicode version than others, so two canonicalizers built
# against different Unicode data reorder them differently under NFC. Pairing one of these
# adjacent to a classic below-mark (CCC=220, e.g. U+0323) forces the canonical reordering
# that diverges on a version-skewed build. U+1AE7 next to U+0323 is the minimal repro
# ({"note": "᫧̣"}) from the audit. We enumerate the whole block so no single
# code point's version-dependent CCC can slip through the gate again.
_COMBINING_EXTENDED = [chr(cp) for cp in range(0x1AB0, 0x1B00)]
# Classic below/attached marks with differing CCC used to force a reorder against the
# extended block above.
_BELOW_MARKS = ["̣", "̤", "̥", "̧", "̮", "̖"]

# Identity-shaped keys: plain, uppercase, and NFKC-fullwidth homoglyph variants.
_IDENTITY_KEYS_PLAIN = [
    "tenant_id", "agent_id", "role", "tenant", "actor", "principal",
    "identity", "sub", "capabilities", "capability", "entitlement",
    "entitlements", "grants",
]


def _fullwidth(s: str) -> str:
    """Map ASCII to fullwidth homoglyphs (NFKC folds them back — must be caught)."""
    out = []
    for ch in s:
        o = ord(ch)
        if 0x21 <= o <= 0x7E:
            out.append(chr(o - 0x21 + 0xFF01))
        else:
            out.append(ch)
    return "".join(out)


_IDENTITY_KEYS_ADVERSARIAL = (
    _IDENTITY_KEYS_PLAIN
    + [k.upper() for k in _IDENTITY_KEYS_PLAIN]
    + [k.title() for k in _IDENTITY_KEYS_PLAIN]
    + [_fullwidth(k) for k in _IDENTITY_KEYS_PLAIN]
)

_SAFE_KEYS = ["a", "b", "key", "name", "value", "nested", "list", "x", "compartment", "amount"]

# Keys whose NFKC form is NON-ASCII — the exact class the Rust walk now DEFERS to
# pure-Python for the identity-injection decision (full casefold is Unicode-version
# dependent, so Rust must not decide it). Some casefold to a forbidden identity string
# (LATIN SMALL LETTER LONG S 'ſ' casefolds to 's', so "ſub" -> "sub" IS identity injection
# Python must catch); others are innocuous non-ASCII keys that must round-trip byte-
# identically. Both paths verify the defer keeps decision- and byte-identity intact.
_CASEFOLD_IDENTITY_KEYS = [
    "ſub",      # 'ſ'+ub : NFKC keeps 'ſ' (non-ASCII) -> casefold 'sub' -> IDENTITY.
    "ſUB",      # mixed-case variant of the above.
    "roﬂe",     # 'ﬂ' ligature: NFKC -> 'fl' but non-ASCII pre-fold path exercised.
    "Rοle",     # Greek omicron 'ο' (non-ASCII) -> not identity, must round-trip.
    "tenᴀnt",   # small-capital A (non-ASCII) -> defer, not identity.
    "grантs",   # Cyrillic homoglyphs -> defer, not identity.
]

# NFC/NFD-equivalent pairs (composed vs decomposed) — canonicalization must collapse them.
_NFD_PAIRS = [
    ("é", "é"),        # é
    ("Å", "Å"),        # Å
    ("ẛ", "ẛ"),   # ẛ
    ("ﬁ", "ﬁ"),         # ﬁ (NFKC-only; stays under NFC).
]


def _rand_string(rng: random.Random) -> str:
    kind = rng.random()
    if kind < 0.45:
        n = rng.randint(0, 12)
        return "".join(rng.choice("abcXYZ0_ é😀日本語ß") for _ in range(n))
    if kind < 0.55:
        # Over-length probe (4096 boundary): sometimes 4095/4096/4097.
        n = rng.choice([4095, 4096, 4097, rng.randint(4090, 4100)])
        return "a" * n
    if kind < 0.70:
        return rng.choice(_ZERO_WIDTH + _BIDI + _C0 + _C1 + _FORMAT_MARKS) + "tail"
    if kind < 0.80:
        base, decomposed = rng.choice(_NFD_PAIRS)
        return rng.choice([base, decomposed]) + rng.choice(["", "x"])
    if kind < 0.84:
        return "".join(rng.choice(_COMBINING) for _ in range(rng.randint(1, 6))) + "e"
    if kind < 0.90:
        # Extended combining block (U+1AB0..U+1AFF) adjacent to a classic below-mark:
        # exercises the exact version-dependent NFC canonical reordering the old gate
        # missed. Build a base + interleaved extended/below marks in random order so the
        # canonical sort order (not the input order) is what's compared.
        base = rng.choice(["a", "e", "o", "é", "日", "x"])
        marks = [
            rng.choice(_COMBINING_EXTENDED + _BELOW_MARKS)
            for _ in range(rng.randint(1, 5))
        ]
        rng.shuffle(marks)
        return base + "".join(marks)
    if kind < 0.93:
        return rng.choice(_SURROGATES) + rng.choice(["", "z"])
    # Random codepoints across the BMP + astral (may include surrogates).
    n = rng.randint(0, 6)
    chars = []
    for _ in range(n):
        cp = rng.randint(0, 0x10FFFF)
        try:
            chars.append(chr(cp))
        except ValueError:
            chars.append("?")
    return "".join(chars)


def _rand_number(rng: random.Random) -> Any:
    pick = rng.random()
    if pick < 0.35:
        return rng.randint(-1000, 1000)
    if pick < 0.55:
        # Big-int boundary probes (i64/u64 edges -> Rust defers).
        return rng.choice([
            2 ** 63 - 1, 2 ** 63, 2 ** 64 - 1, 2 ** 64, -(2 ** 63),
            -(2 ** 63) - 1, 2 ** 200, -(2 ** 200),
        ])
    if pick < 0.85:
        return rng.choice([
            0.0, -0.0, 1.5, -3.25, 1e-300, 1e308, 5e-324, 0.1, 2.0,
            float("1e16"), 123456.789,
        ])
    # Non-finite (pure-Python rejects; Rust defers to it).
    return rng.choice([float("inf"), float("-inf"), float("nan")])


def _rand_scalar(rng: random.Random) -> Any:
    pick = rng.random()
    if pick < 0.30:
        return _rand_string(rng)
    if pick < 0.60:
        return _rand_number(rng)
    if pick < 0.75:
        return rng.choice([True, False])
    if pick < 0.85:
        return None
    return _rand_string(rng)


def _rand_key(rng: random.Random) -> Any:
    pick = rng.random()
    if pick < 0.55:
        return rng.choice(_SAFE_KEYS)
    if pick < 0.68:
        return rng.choice(_IDENTITY_KEYS_ADVERSARIAL)
    if pick < 0.80:
        return _rand_string(rng)
    if pick < 0.84:
        # NFC-colliding keys (composed vs decomposed).
        base, decomposed = rng.choice(_NFD_PAIRS)
        return rng.choice([base, decomposed])
    if pick < 0.90:
        # Non-ASCII-NFKC identity keys — exercise the Rust defer path (casefold).
        return rng.choice(_CASEFOLD_IDENTITY_KEYS)
    if pick < 0.94:
        return rng.randint(0, 5)  # non-string key -> pure raises; Rust matches.
    return rng.choice(_ZERO_WIDTH + _BIDI) + "k"


def _rand_node(rng: random.Random, depth: int, budget: list[int]) -> Any:
    budget[0] -= 1
    if depth >= rng.randint(1, 10) or budget[0] <= 0:
        return _rand_scalar(rng)
    pick = rng.random()
    if pick < 0.55:
        n = rng.choice([0, 1, 2, 3, rng.randint(0, 6), rng.choice([64, 65])])
        d: dict[Any, Any] = {}
        for _ in range(n):
            d[_rand_key(rng)] = _rand_node(rng, depth + 1, budget)
            if budget[0] <= 0:
                break
        return d
    if pick < 0.85:
        n = rng.choice([0, 1, 2, 3, rng.randint(0, 6), rng.choice([256, 257])])
        lst = []
        for _ in range(n):
            lst.append(_rand_node(rng, depth + 1, budget))
            if budget[0] <= 0:
                break
        return lst
    return _rand_scalar(rng)


def _deep_chain(depth: int) -> dict[str, Any]:
    """A right-leaning nesting exactly `depth` deep (root object == depth 1)."""
    node: dict[str, Any] = {"leaf": 1}
    for _ in range(max(0, depth - 1)):
        node = {"n": node}
    return node


def _enumerated_corpus() -> list[Any]:
    """Deterministic adversarial corpus exercising every boundary/oracle."""
    corpus: list[Any] = []
    # Depth boundaries (8 accept / 9 reject).
    corpus.append(_deep_chain(8))
    corpus.append(_deep_chain(9))
    corpus.append(_deep_chain(20))
    # Key-count boundaries.
    corpus.append({f"k{i}": i for i in range(64)})
    corpus.append({f"k{i}": i for i in range(65)})
    # Array boundaries.
    corpus.append({"a": list(range(256))})
    corpus.append({"a": list(range(257))})
    # String-length boundaries.
    corpus.append({"s": "a" * 4096})
    corpus.append({"s": "a" * 4097})
    # Node-count near the aggregate ceiling.
    corpus.append({"a": list(range(16000))})
    corpus.append({"a": list(range(17000))})
    # Identity injection at every nesting level + folded variants.
    for k in _IDENTITY_KEYS_ADVERSARIAL:
        corpus.append({k: 1})
        corpus.append({"outer": {"mid": {k: "x"}}})
        corpus.append({"list": [{k: True}]})
    # Every zero-width / bidi / control / format-mark char as a value and as a (non-
    # identity) key. The _FORMAT_MARKS entries (LRM/RLM/ALM, Zl/Zp separators, invisible
    # operators) are the exact codepoints decided only by the Cc/Cf/Zl/Zp category reject —
    # the divergence a category-blind fast walker re-opens.
    for ch in _ZERO_WIDTH + _BIDI + _C0 + _C1 + _FORMAT_MARKS:
        corpus.append({"v": "pre" + ch + "post"})
        corpus.append({"pre" + ch: 1})
        corpus.append({"v": ch})
        corpus.append({"nested": {"list": ["ok", "x" + ch + "y"]}})
    # NFC/NFD colliding keys and values.
    for base, decomposed in _NFD_PAIRS:
        corpus.append({base: 1, decomposed: 2})
        corpus.append({"v": decomposed})
    # Extended-combining-block NFC reordering (the audit's minimal repro + full sweep).
    # {"note": "᫧̣"} == U+1AE7 then U+0323: canonical order depends on the extended mark's
    # combining class, which differs across Unicode versions. This deterministically
    # detects any crate-vs-CPython Unicode-data skew.
    corpus.append({"note": "᫧̣"})
    corpus.append({"note": "̣᫧"})  # reversed input -> same canonical target.
    for cp in range(0x1AB0, 0x1B00):
        mark = chr(cp)
        for below in _BELOW_MARKS:
            corpus.append({"v": "a" + mark + below})
            corpus.append({"v": "a" + below + mark})
    # Non-ASCII-NFKC identity keys — exercise the Rust identity-fold DEFER path at several
    # nesting levels (some ARE identity injection via casefold, e.g. "ſub" -> "sub").
    for k in _CASEFOLD_IDENTITY_KEYS:
        corpus.append({k: 1})
        corpus.append({"outer": {k: "x"}})
        corpus.append({"list": [{k: True}]})
    # Numeric edges.
    for n in [0.0, -0.0, 5e-324, 1e308, float("inf"), float("nan"),
              2 ** 63, 2 ** 64, 2 ** 200, -(2 ** 63) - 1]:
        corpus.append({"n": n})
    # Surrogate-adjacent scalars.
    for s in _SURROGATES:
        corpus.append({"s": s})
    # Provider-shaped payloads (the adversarial /v1/authorize suite shapes).
    corpus.append({"account": "ACME-1", "amount": 1234, "memo": "wire"})
    corpus.append({"compartment": "3e7d1a95-6c4b-42f0-8a9e-1b2c3d4e5f60", "ttl": 3600})
    corpus.append({"query": "SELECT 1", "params": [1, 2, {"x": None}]})
    corpus.append({"deep": {"a": {"b": {"c": {"d": {"e": {"f": {"g": 1}}}}}}}})
    # Non-dict top-levels (canonical_json accepts; enforce rejects).
    corpus.extend([[1, 2, 3], "scalar", 42, True, None, 3.14, {"": ""}])
    return corpus


# ---------------------------------------------------------------------------
# Comparators.
# ---------------------------------------------------------------------------
def _run(fn: Callable[[Any], Any], obj: Any) -> tuple[str, Any]:
    try:
        return ("ok", fn(obj))
    except BaseException as exc:  # noqa: BLE001 - we compare failure modes too.
        return ("err", exc)


class Divergence(Exception):
    """Raised on ANY Rust-vs-Python mismatch — a CRITICAL, ship-blocking bug."""


def _check_canonical(obj: Any) -> None:
    p_kind, p_val = _run(_canonical_json_py, obj)
    r_kind, r_val = _run(_rust_canonical, obj)
    if p_kind != r_kind:
        raise Divergence(
            f"canonical accept/reject differs: py={p_kind}({p_val!r}) rust={r_kind}({r_val!r}) "
            f"input={obj!r}"
        )
    if p_kind == "ok":
        if bytes(p_val) != bytes(r_val):
            raise Divergence(
                f"canonical BYTES differ:\n py={p_val!r}\n rs={r_val!r}\n input={obj!r}"
            )
    else:
        if type(p_val) is not type(r_val):
            raise Divergence(
                f"canonical error TYPE differs: py={type(p_val).__name__} "
                f"rust={type(r_val).__name__} input={obj!r}"
            )


def _check_enforce(obj: Any) -> None:
    p_kind, p_val = _run(_enforce_argument_safety_py, obj)
    r_kind, r_val = _run(_rust_enforce, obj)
    if p_kind != r_kind:
        p_reason = map_engine_exception(p_val).reason if p_kind == "err" else "ACCEPT"
        r_reason = map_engine_exception(r_val).reason if r_kind == "err" else "ACCEPT"
        raise Divergence(
            f"enforce accept/reject differs: py={p_kind}/{p_reason} rust={r_kind}/{r_reason} "
            f"input={obj!r}"
        )
    if p_kind == "ok":
        # Sanitized dicts must canonicalize to identical bytes.
        pb = _canonical_json_py(p_val)
        rb = _canonical_json_py(r_val)
        if pb != rb:
            raise Divergence(
                f"enforce sanitized output differs:\n py={pb!r}\n rs={rb!r}\n input={obj!r}"
            )
    else:
        p_reason = map_engine_exception(p_val).reason
        r_reason = map_engine_exception(r_val).reason
        if p_reason != r_reason:
            raise Divergence(
                f"enforce DenyReason differs: py={p_reason} rust={r_reason} "
                f"input={obj!r} (py_exc={p_val!r} rust_exc={r_val!r})"
            )


def run_fuzz(iterations: int, seed: int = 1234567) -> int:
    """Run the enumerated corpus + `iterations` random inputs. Returns total checks."""
    if _rust is None:  # pragma: no cover
        raise RuntimeError(f"mcpip_fastwalk not importable: {_IMPORT_ERR!r}")
    # Input-independent skew detector FIRST: a mismatched Unicode-data crate is a RED gate
    # before any fuzz input is drawn (it would silently reorder combining marks).
    _assert_unicode_parity()
    checks = 0
    # 1) Enumerated deterministic corpus (both canonical_json and enforce).
    for obj in _enumerated_corpus():
        _check_canonical(obj)
        if isinstance(obj, dict):
            _check_enforce(obj)
        else:
            _check_enforce(obj)  # non-dict -> both raise "arguments must be an object".
        checks += 1
    # 2) Randomized corpus.
    rng = random.Random(seed)
    for _ in range(iterations):
        obj = _rand_node(rng, depth=1, budget=[rng.randint(1, 400)])
        _check_canonical(obj)
        _check_enforce(obj)
        checks += 1
    return checks


def test_differential_smoke() -> None:
    """Pytest entry: a fast deterministic slice (full gate runs standalone).

    The Rust accelerator is OPT-IN and build-time-optional: it is a ``cp3xx-abi3`` wheel
    that (a) may not be compiled in a given environment and (b) only activates when its
    bundled Unicode version EXACTLY matches this CPython's ``unicodedata.unidata_version``
    (the parity guard in ``bridge/fastwalk.py``). When the extension is absent or its UCD
    version does not match, the accelerator is — correctly — DISABLED (pure-Python is the
    source of truth), so there is nothing to differentially compare and this smoke SKIPS
    rather than erroring. This never weakens the gate: wherever the extension IS active
    (the environment that could actually ship it), the full corpus below runs and MUST be
    divergence-free — the standalone ``__main__`` gate still hard-fails on absence.
    """
    if _rust is None:
        import pytest

        pytest.skip(f"mcpip_fastwalk extension not built in this environment: {_IMPORT_ERR!r}")
    rust_version = getattr(_rust, "UNICODE_VERSION", None)
    if rust_version != unicodedata.unidata_version:
        import pytest

        pytest.skip(
            "mcpip_fastwalk Unicode-data version "
            f"{rust_version!r} != CPython {unicodedata.unidata_version!r} — accelerator "
            "disabled by the parity guard, nothing to differentially compare"
        )
    total = run_fuzz(iterations=20000)
    assert total > 0


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1_000_000
    print(f"MCPIP_FAST_WALKER={os.environ.get('MCPIP_FAST_WALKER')!r} rust={_rust is not None}")
    total_checks = run_fuzz(iterations=n)
    print(f"OK: {total_checks} differential checks, 0 divergences (iterations={n}).")
