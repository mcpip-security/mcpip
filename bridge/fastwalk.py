"""
MCPIP V2 — Bridge: opt-in Rust fast-walker dispatch shim.

    ◐ "Same canonicalizer at register AND consume — or don't use it at all."

This module is the SINGLE seam between the pure-Python engine and the optional
Rust/PyO3 accelerator (`mcpip_fastwalk`, built via maturin). It is consulted at the
two hot entry points that the payload lock binds:

  * ``interfaces.canonical_json``            (register- AND consume-time lock hash)
  * ``bridge.intent_parser.enforce_argument_safety``  (ingress safety walk)

Contract (all load-bearing):

  * **Pure-Python is the DEFAULT.** The Rust path is used IFF the environment variable
    ``MCPIP_FAST_WALKER == "1"`` (read ONCE at import, so a single process can never mix
    canonicalizers mid-flight) AND the compiled extension actually imported. If the flag
    is set but the extension is missing/broken, we transparently run pure-Python — the
    accelerator is never allowed to fail a request open or closed by its mere absence.

  * **Unicode-version parity or it doesn't activate.** The Rust NFC/NFKC tables must be
    the SAME Unicode version as this CPython's ``unicodedata.unidata_version``; the
    extension advertises its bundled version as ``UNICODE_VERSION`` and this module refuses
    to route to it (treats it as absent → pure-Python) on any mismatch. See the parity
    guard below.

  * **Byte-identical or it doesn't ship.** The Rust encoder handles
    None/bool/int(i64|u64)/str/list/dict. On a ``float`` leaf, an ``int`` outside the
    i64/u64 range, or a lone-surrogate string it raises ``mcpip_fastwalk.Defer``; we
    catch that and fall back to the pure-Python implementation for that entire payload,
    which trivially guarantees byte-identity for those cases (CPython's shortest-round-
    trip float ``repr`` is never re-implemented in Rust).

  * **Decision-identical.** For a rejected payload the Rust walk raises the REAL bridge
    exception types (``IdentityInjection`` / ``DepthExceeded`` / ``SizeExceeded``) or
    ``ValueError`` / ``TypeError``, so the unchanged ``core.security.map_engine_exception``
    yields the identical ``DenyReason``.

The fallback targets the PURE implementations (``_canonical_json_py`` /
``_enforce_argument_safety_py``) directly, never the public dispatchers, so a defer can
never recurse back into this shim.

Performance note (why this is opt-in and pure-Python stays the default): the net win on
the real hot path (safety-walk + canonical-encode + sha256) comes almost entirely from the
Rust **safety walk** replacing the pure-Python recursive ``_walk`` — NOT from the JSON
encoder. Measured in isolation, ``canonical_json`` alone is actually SLOWER in Rust on a
large (multi-KiB, deeply-keyed) payload — CPython's ``json.dumps`` is C and the PyO3
marshalling adds overhead — while it wins on small payloads. So enabling the walker is a
net win on realistic traffic (the walk dominates), but do not assume the canonical-encode
sub-step is universally faster; it is not for large objects. Correctness is unaffected
either way (byte-identity is verified by ``tests/test_fastwalk_differential.py``).
"""

from __future__ import annotations

import os
import unicodedata
from typing import Any

# Read the flag exactly once, at import — a process is homogeneous for its lifetime.
FAST_ENABLED: bool = os.environ.get("MCPIP_FAST_WALKER") == "1"

# The compiled Rust extension is a build-time artifact (maturin), untracked by
# requirements.txt. Its absence is not an error: we simply stay on pure-Python.
_rust: Any
try:  # pragma: no cover - availability depends on whether maturin built the ext.
    import mcpip_fastwalk as _rust_mod  # type: ignore  # compiled ext: no stubs / may be absent.

    _rust = _rust_mod
except Exception:  # noqa: BLE001 - availability-only; never fail import on this.
    _rust = None

# --- UNICODE-VERSION PARITY GUARD (fail-closed) -----------------------------------
# The Rust NFC/NFKC canonicalizer is only BYTE-IDENTICAL to CPython when the crate's
# bundled Unicode Character Database is the SAME version as this interpreter's
# ``unicodedata.unidata_version``. A skew (e.g. a crate shipping Unicode 16.0/17.0 while
# CPython 3.12 is 15.0.0) reorders combining marks in the U+1AB0..U+1AFF block differently,
# emitting different canonical bytes and thus a different payload-lock hash — silently
# breaking the register/consume TOCTOU binding on a mixed fleet. So if the compiled
# extension does not advertise a ``UNICODE_VERSION`` that EXACTLY matches CPython's, we
# refuse to route to it at all (treat it as absent) and stay on the pure-Python source of
# truth. This makes activation fail-closed: a CPython upgrade that bumps the Unicode data
# version, or a wheel built against a different crate pin, deactivates the accelerator
# rather than shipping a divergent canonicalizer.
_RUST_UNICODE_VERSION: Any = getattr(_rust, "UNICODE_VERSION", None) if _rust is not None else None
UNICODE_PARITY_OK: bool = _RUST_UNICODE_VERSION == unicodedata.unidata_version
if _rust is not None and not UNICODE_PARITY_OK:  # pragma: no cover - build-dependent.
    _rust = None

# The sentinel the Rust layer raises to request a pure-Python fallback for a payload.
# Resolved to a concrete exception type so ``except`` clauses stay statically typed.
if _rust is not None:
    _DeferError: type[BaseException] = _rust.Defer
else:  # pragma: no cover - only when the extension is absent.

    class _DeferError(Exception):  # type: ignore[no-redef]
        """Placeholder so the fallback path is well-typed when Rust is absent."""


def rust_active() -> bool:
    """True iff the flag is set AND the compiled extension is importable."""
    return FAST_ENABLED and _rust is not None


def canonical_json(obj: object) -> bytes:
    """Dispatch ``interfaces.canonical_json``: Rust when active, else pure-Python.

    Only ever called by ``interfaces.canonical_json`` when ``FAST_ENABLED`` is true.
    On a Rust ``Defer`` (float / big-int / surrogate) it runs the pure implementation
    for the whole payload, guaranteeing byte-identity.
    """
    from interfaces import _canonical_json_py

    if _rust is None:
        return _canonical_json_py(obj)
    try:
        result: bytes = _rust.canonical_json(obj)
    except _DeferError:
        return _canonical_json_py(obj)
    return result


def enforce_argument_safety(arguments: dict[str, Any]) -> dict[str, Any]:
    """Dispatch ``bridge.intent_parser.enforce_argument_safety``: Rust when active.

    On a Rust ``Defer`` it runs the pure implementation for the whole payload. Rust
    rejections raise the same bridge exception types as pure-Python, so the deny reason
    is identical either way.
    """
    from bridge.intent_parser import _enforce_argument_safety_py

    if _rust is None:
        return _enforce_argument_safety_py(arguments)
    try:
        result: dict[str, Any] = _rust.enforce_argument_safety(arguments)
    except _DeferError:
        return _enforce_argument_safety_py(arguments)
    return result


__all__ = [
    "FAST_ENABLED",
    "rust_active",
    "canonical_json",
    "enforce_argument_safety",
]
