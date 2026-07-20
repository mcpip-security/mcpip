//! MCPIP opt-in fast walker (Rust/PyO3).
//!
//! Byte-for-byte and decision-for-decision mirror of the pure-Python engine, so the
//! payload-lock hash (which binds register-time to consume-time) is identical whether
//! the Rust path or the Python path produced it. This crate is **opt-in** (the shim
//! `bridge/fastwalk.py` only routes to it when `MCPIP_FAST_WALKER=1`); pure-Python is
//! the default and the source of truth.
//!
//! Mirrored Python surface (quoted signatures — any drift is a CRITICAL bug):
//!   * `interfaces.py:167  canonical_json(obj) -> bytes`
//!       - NFC every str key+value; reject NaN/Inf; sort_keys=True (Unicode code
//!         point == UTF-8 byte order); separators=(",",":"); ensure_ascii=False; UTF-8.
//!   * `interfaces.py:190  sha256_hex(data) -> str`.
//!   * `interfaces.py:102  reject_unsafe_string(s, field) -> str`
//!       - NFC -> scan forbidden codepoints -> enforce MAX_STRING_LEN; returns NFC form.
//!   * `bridge/intent_parser.py:228  enforce_argument_safety(arguments) -> dict`
//!       - `_walk` node-count / depth / keys / array / scalar-typing / NaN-Inf /
//!         per-string reject / identity-injection (NFKC-casefold), then the post-walk
//!         `len(canonical_json(sanitized)) <= MAX_CANONICAL_BYTES` check.
//!
//! DEFERRAL CONTRACT (the mandated safe default): the Rust encoder/walker handles
//! None/bool/int(i64|u64)/str/list/dict. On ANY of
//!   * a `float` leaf (CPython emits floats via shortest-round-trip `repr` — do NOT
//!     hand-roll it),
//!   * an `int` outside the i64/u64 range (Python ints are unbounded),
//!   * a `str` CPython cannot render as UTF-8 (lone surrogate),
//!   * a dict key whose NFKC form is non-ASCII (full Unicode casefold is version-
//!     dependent and not pinned, so the identity-injection decision is handed to
//!     pure-Python rather than guessed),
//!   * a safety-walk key or value string whose NFC form is non-ASCII (the Cc/Cf/Zl/Zp
//!     general-category reject in `reject_unsafe_string` is version-dependent and not
//!     pinned, so the bidi/format-mark decision is handed to pure-Python — see
//!     `reject_unsafe_string`),
//! it raises the `Defer` exception; the Python shim then runs the pure-Python path for
//! that entire payload. This trivially guarantees byte- and decision-identity for those
//! cases.
//!
//! UNICODE-VERSION PARITY (the other half of the byte-identity contract): NFC/NFKC are
//! only byte-identical to CPython when the crate's bundled UCD is the SAME Unicode version
//! as `unicodedata.unidata_version`. `unicode-normalization` is therefore PINNED (Cargo
//! `=0.1.22` -> Unicode 15.0.0 == CPython 3.12.7) and the version is re-exported as
//! `UNICODE_VERSION`; the shim asserts it equals CPython's and refuses to activate on a
//! mismatch. A CPython upgrade that bumps `unidata_version` MUST be matched by a crate
//! re-pin, or the accelerator stays off (fail-closed).

use std::collections::BTreeMap;

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::UNICODE_VERSION;

// --- Ground-truth constants (quoted verbatim from interfaces.py / intent_parser.py). --
const MAX_ARG_DEPTH: usize = 8; // interfaces.py:49
const MAX_ARG_KEYS: usize = 64; // interfaces.py:50
const MAX_ARG_ARRAY: usize = 256; // interfaces.py:51
const MAX_STRING_LEN: usize = 4096; // interfaces.py:52
const MAX_CANONICAL_BYTES: usize = 16384; // interfaces.py:53
const MAX_ARG_NODES: usize = MAX_CANONICAL_BYTES; // bridge/intent_parser.py:90

// Zero-width / invisible codepoints (interfaces.py:72).
const ZERO_WIDTH: [u32; 6] = [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD];

// Inclusive forbidden ranges (interfaces.py:84).
const FORBIDDEN_RANGES: [(u32, u32); 4] = [
    (0x0000, 0x001F), // C0 controls (TAB/LF/CR included).
    (0x007F, 0x009F), // DEL + C1 controls.
    (0x202A, 0x202E), // Bidi embeddings / overrides.
    (0x2066, 0x2069), // Bidi isolates.
];

// Identity-injection forbidden key set (bridge/intent_parser.py:113), compared after
// NFKC-casefold. All entries are ASCII lowercase.
const FORBIDDEN_IDENTITY_KEYS: [&str; 13] = [
    "tenant_id",
    "agent_id",
    "role",
    "tenant",
    "actor",
    "principal",
    "identity",
    "sub",
    "capabilities",
    "capability",
    "entitlement",
    "entitlements",
    "grants",
];

// The one sentinel the Python shim catches to fall back to the pure implementation.
create_exception!(
    mcpip_fastwalk,
    Defer,
    PyException,
    "Rust encountered a value it must not decide itself — a float / out-of-range int / \
     surrogate string, or a dict key whose NFKC form is non-ASCII (version-sensitive \
     casefold) — and defers the entire payload to the pure-Python implementation for \
     guaranteed byte- and decision-identity."
);

#[inline]
fn defer_err() -> PyErr {
    Defer::new_err("defer to pure-Python (float / big-int / surrogate / non-ASCII NFKC key)")
}

// ---------------------------------------------------------------------------
// Bridge-exception construction — raise the REAL Python bridge exception types so
// the unchanged `core.security.map_engine_exception` classifies Rust-raised rejects
// identically to Python-raised ones. Imported lazily at raise-time (rare, error path),
// after `bridge.intent_parser` is fully loaded (the shim is only used at call time).
// ---------------------------------------------------------------------------
fn bridge_exc(py: Python<'_>, class_name: &str, msg: String) -> PyErr {
    let module = match PyModule::import(py, "bridge.intent_parser") {
        Ok(m) => m,
        Err(e) => return e,
    };
    match module.getattr(class_name) {
        Ok(cls) => match cls.call1((msg,)) {
            Ok(inst) => PyErr::from_value(inst),
            Err(e) => e,
        },
        Err(e) => e,
    }
}

#[inline]
fn identity_injection(py: Python<'_>, msg: String) -> PyErr {
    bridge_exc(py, "IdentityInjection", msg)
}
#[inline]
fn depth_exceeded(py: Python<'_>, msg: String) -> PyErr {
    bridge_exc(py, "DepthExceeded", msg)
}
#[inline]
fn size_exceeded(py: Python<'_>, msg: String) -> PyErr {
    bridge_exc(py, "SizeExceeded", msg)
}

// ---------------------------------------------------------------------------
// String safety — mirrors interfaces.reject_unsafe_string.
// ---------------------------------------------------------------------------
#[inline]
fn is_forbidden_codepoint(cp: u32) -> bool {
    if ZERO_WIDTH.contains(&cp) {
        return true;
    }
    for (lo, hi) in FORBIDDEN_RANGES.iter() {
        if cp >= *lo && cp <= *hi {
            return true;
        }
    }
    false
}

/// NFC-normalize, scan for forbidden codepoints, enforce MAX_STRING_LEN. Returns the
/// NFC form. Mirrors interfaces.reject_unsafe_string byte-for-byte, including messages.
///
/// Category parity (the other half of the ingress guard): Python's reject_unsafe_string
/// ALSO rejects any codepoint whose Unicode general category is Cc/Cf/Zl/Zp — the bidi
/// marks (LRM U+200E / RLM U+200F / ALM U+061C), every other invisible format char (Cf),
/// and the line/paragraph separators (Zl/Zp: U+2028/U+2029) — via `unicodedata.category`
/// (interfaces.py:219). A hand-rolled `ZERO_WIDTH`+`FORBIDDEN_RANGES` list here can only
/// enumerate a FIXED subset, so a format/bidi mark outside those bands (e.g. U+200E) would
/// pass Rust while Python rejects it — a decision divergence that re-opens bidi/format-mark
/// ingress smuggling whenever `MCPIP_FAST_WALKER=1`. A full general-category lookup is
/// Unicode-VERSION dependent (a codepoint's category can change across UCD releases) and no
/// general-category crate is pinned to the crate's exact `unicode-normalization` UCD, so —
/// EXACTLY like the version-sensitive NFKC casefold in `is_identity_key` — we do NOT guess:
/// any string that is not pure ASCII is DEFERRED to the pure-Python source of truth for the
/// whole payload. Pure ASCII contains no Cf/Zl/Zp codepoints and its Cc controls are already
/// covered byte-identically by `FORBIDDEN_RANGES` (0x00–0x1F, 0x7F), so the ASCII fast path
/// stays fully and identically decided in Rust; only version-sensitive non-ASCII defers. The
/// DEFER is taken on the NFC form (what Python scans), so an NFC that stays non-ASCII defers
/// and one that is ASCII takes the fast path — matching Python's decision either way.
fn reject_unsafe_string(s: &str, field: &str) -> PyResult<String> {
    let nfc: String = s.nfc().collect();
    if !nfc.is_ascii() {
        // Version-sensitive Cc/Cf/Zl/Zp category territory -> defer the whole payload.
        return Err(defer_err());
    }
    for ch in nfc.chars() {
        let cp = ch as u32;
        if is_forbidden_codepoint(cp) {
            return Err(PyValueError::new_err(format!(
                "illegal character U+{:04X} in field '{}'",
                cp, field
            )));
        }
    }
    // Python len(str) counts Unicode code points, not bytes.
    let count = nfc.chars().count();
    if count > MAX_STRING_LEN {
        return Err(PyValueError::new_err(format!(
            "field '{}' exceeds MAX_STRING_LEN ({} > {})",
            field, count, MAX_STRING_LEN
        )));
    }
    Ok(nfc)
}

/// Decide the identity-injection test for a key, mirroring Python
/// `unicodedata.normalize("NFKC", key).casefold() in FORBIDDEN_IDENTITY_KEYS`.
///
/// NFKC is byte-matched to CPython (unicode-normalization is pinned to the deployed
/// CPython's Unicode version). Full Unicode `casefold`, however, is version-dependent and
/// there is no pinned crate for it, so we NEVER hand-roll it: we only DECIDE here when the
/// NFKC form is pure ASCII, where casefold is exactly ASCII-lowercasing — identical in
/// every Unicode version and byte-for-byte equal to CPython's. Every forbidden identity
/// key is ASCII, so any key that could match must NFKC to ASCII; a non-ASCII NFKC form can
/// only match via a version-sensitive casefold (e.g. a codepoint assigned after the pinned
/// version that folds to ASCII), which we refuse to guess: we raise `Defer` so the pure-
/// Python source of truth decides the whole payload. This makes the fold decision-identical
/// by construction, closing the casefold half of the canonicalizer-skew hole.
fn is_identity_key(key: &str) -> PyResult<bool> {
    let nfkc: String = key.nfkc().collect();
    if !nfkc.is_ascii() {
        // Version-sensitive casefold territory -> defer the whole payload to pure-Python.
        return Err(defer_err());
    }
    let folded = nfkc.to_ascii_lowercase();
    Ok(FORBIDDEN_IDENTITY_KEYS.contains(&folded.as_str()))
}

/// Extract a Python str as `&str`, deferring on a lone-surrogate string CPython cannot
/// render as UTF-8 (Python would accept it in reject_unsafe_string but then fail at the
/// `.encode("utf-8")` in canonical_json — deferring reproduces that exact behavior).
fn py_str_to_utf8<'a>(s: &'a Bound<'a, PyString>) -> PyResult<&'a str> {
    match s.to_str() {
        Ok(v) => Ok(v),
        Err(_) => Err(defer_err()),
    }
}

// ---------------------------------------------------------------------------
// Canonical JSON encoder — mirrors interfaces._nfc + json.dumps(sort_keys=True,
// separators=(",",":"), ensure_ascii=False, allow_nan=False).
// ---------------------------------------------------------------------------

/// Escape one already-NFC string into a JSON string literal, matching CPython's
/// `json.encoder` with ensure_ascii=False (short escapes for \b\t\n\f\r\"\\, lowercase
/// \u00xx for the remaining C0 controls, everything else emitted literally as UTF-8).
fn encode_str_raw(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{0008}' => out.extend_from_slice(b"\\b"),
            '\u{000C}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn encode(py: Python<'_>, obj: &Bound<'_, PyAny>, out: &mut Vec<u8>) -> PyResult<()> {
    if obj.is_none() {
        out.extend_from_slice(b"null");
        return Ok(());
    }
    // bool BEFORE int (bool is a subclass of int).
    if let Ok(b) = obj.downcast::<PyBool>() {
        out.extend_from_slice(if b.is_true() { b"true" } else { b"false" });
        return Ok(());
    }
    if let Ok(i) = obj.downcast::<PyInt>() {
        if let Ok(v) = i.extract::<i64>() {
            out.extend_from_slice(v.to_string().as_bytes());
            return Ok(());
        }
        if let Ok(v) = i.extract::<u64>() {
            out.extend_from_slice(v.to_string().as_bytes());
            return Ok(());
        }
        return Err(defer_err()); // int outside i64/u64 -> defer.
    }
    if obj.downcast::<PyFloat>().is_ok() {
        return Err(defer_err()); // float -> defer (never hand-roll repr(float)).
    }
    if let Ok(s) = obj.downcast::<PyString>() {
        let raw = py_str_to_utf8(s)?;
        let nfc: String = raw.nfc().collect();
        encode_str_raw(&nfc, out);
        return Ok(());
    }
    if let Ok(l) = obj.downcast::<PyList>() {
        out.push(b'[');
        for (idx, el) in l.iter().enumerate() {
            if idx > 0 {
                out.push(b',');
            }
            encode(py, &el, out)?;
        }
        out.push(b']');
        return Ok(());
    }
    if let Ok(d) = obj.downcast::<PyDict>() {
        // Mirror interfaces._nfc EXACTLY, including its eager depth-first recursion:
        // it validates/encodes EVERY value in insertion order (so a value whose
        // NFC-colliding key is later overwritten is still fully recursed, and raises
        // if it is malformed), then json.dumps(sort_keys=True) emits the last-wins,
        // code-point-sorted result. We therefore recurse-encode each value NOW (in
        // insertion order, raising on the first bad one) and store its bytes keyed by
        // the NFC key; a later duplicate NFC key overwrites those bytes (last wins).
        // BTreeMap<String,_> orders by UTF-8 byte order == Python's code-point sort.
        let mut map: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for (k, v) in d.iter() {
            let ks = match k.downcast::<PyString>() {
                Ok(s) => s,
                Err(_) => {
                    return Err(PyTypeError::new_err(format!(
                        "canonical_json: object key must be str, got {}",
                        k.get_type().name()?
                    )))
                }
            };
            let raw = py_str_to_utf8(ks)?;
            let nfc: String = raw.nfc().collect();
            let mut child: Vec<u8> = Vec::new();
            encode(py, &v, &mut child)?;
            map.insert(nfc, child);
        }
        out.push(b'{');
        for (idx, (k, child)) in map.iter().enumerate() {
            if idx > 0 {
                out.push(b',');
            }
            encode_str_raw(k, out); // key already NFC.
            out.push(b':');
            out.extend_from_slice(child);
        }
        out.push(b'}');
        return Ok(());
    }
    Err(PyTypeError::new_err(format!(
        "canonical_json: unsupported type {}",
        obj.get_type().name()?
    )))
}

// ---------------------------------------------------------------------------
// Safety walk — mirrors bridge/intent_parser._walk (validate AND rebuild NFC form).
// ---------------------------------------------------------------------------
fn walk_build<'py>(
    py: Python<'py>,
    node: &Bound<'py, PyAny>,
    depth: usize,
    counter: &mut usize,
) -> PyResult<Bound<'py, PyAny>> {
    // Aggregate work bound (counter.bump()), then depth — order matches Python.
    *counter += 1;
    if *counter > MAX_ARG_NODES {
        return Err(size_exceeded(
            py,
            format!("argument node count exceeds MAX_ARG_NODES={}", MAX_ARG_NODES),
        ));
    }
    if depth > MAX_ARG_DEPTH {
        return Err(depth_exceeded(
            py,
            format!("argument depth exceeds MAX_ARG_DEPTH={}", MAX_ARG_DEPTH),
        ));
    }

    if let Ok(d) = node.downcast::<PyDict>() {
        if d.len() > MAX_ARG_KEYS {
            return Err(size_exceeded(
                py,
                format!("object has {} keys > MAX_ARG_KEYS={}", d.len(), MAX_ARG_KEYS),
            ));
        }
        let out = PyDict::new(py);
        for (key, value) in d.iter() {
            // Non-string key -> ValueError (JSON objects only have string keys).
            let key_str = match key.downcast::<PyString>() {
                Ok(s) => s,
                Err(_) => return Err(PyValueError::new_err("object key must be a string")),
            };
            let key_utf8 = py_str_to_utf8(key_str)?;
            // Identity-injection guard BEFORE the char scan (matches Python order),
            // on the NFKC-casefolded key. `is_identity_key` raises `Defer` for a key whose
            // NFKC form is non-ASCII (version-sensitive casefold), handing the whole
            // payload to pure-Python for a guaranteed-identical decision.
            if is_identity_key(key_utf8)? {
                return Err(identity_injection(
                    py,
                    format!("identity-shaped key '{}' is forbidden in arguments", key_utf8),
                ));
            }
            let safe_key = reject_unsafe_string(key_utf8, "argument-key")?;
            let child = walk_build(py, &value, depth + 1, counter)?;
            out.set_item(safe_key, child)?;
        }
        return Ok(out.into_any());
    }

    if let Ok(l) = node.downcast::<PyList>() {
        if l.len() > MAX_ARG_ARRAY {
            return Err(size_exceeded(
                py,
                format!("array has {} elements > MAX_ARG_ARRAY={}", l.len(), MAX_ARG_ARRAY),
            ));
        }
        let out = PyList::empty(py);
        for element in l.iter() {
            let child = walk_build(py, &element, depth + 1, counter)?;
            out.append(child)?;
        }
        return Ok(out.into_any());
    }

    // Scalar leaves. bool BEFORE int.
    if node.is_none() {
        return Ok(node.clone());
    }
    if let Ok(b) = node.downcast::<PyBool>() {
        return Ok(b.to_owned().into_any());
    }
    if let Ok(i) = node.downcast::<PyInt>() {
        if i.extract::<i64>().is_ok() || i.extract::<u64>().is_ok() {
            return Ok(node.clone()); // in-range int kept as-is.
        }
        return Err(defer_err()); // big int -> defer.
    }
    if node.downcast::<PyFloat>().is_ok() {
        return Err(defer_err()); // float (incl. NaN/Inf) -> defer to pure-Python.
    }
    if let Ok(s) = node.downcast::<PyString>() {
        let raw = py_str_to_utf8(s)?;
        let safe = reject_unsafe_string(raw, "argument-value")?;
        return Ok(PyString::new(py, &safe).into_any());
    }

    Err(PyValueError::new_err(format!(
        "unsupported argument leaf type {}",
        node.get_type().name()?
    )))
}

// ---------------------------------------------------------------------------
// Public PyO3 surface.
// ---------------------------------------------------------------------------

/// Byte-identical mirror of `interfaces.canonical_json`. Raises `Defer` on
/// float / out-of-range int / surrogate so the shim falls back to pure-Python.
#[pyfunction]
fn canonical_json<'py>(py: Python<'py>, obj: Bound<'py, PyAny>) -> PyResult<Bound<'py, PyBytes>> {
    let mut out: Vec<u8> = Vec::with_capacity(256);
    encode(py, &obj, &mut out)?;
    Ok(PyBytes::new(py, &out))
}

/// Byte-identical mirror of `interfaces.sha256_hex` (lowercase hex).
#[pyfunction]
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest.iter() {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

/// Mirror of `interfaces.reject_unsafe_string` (exposed for the differential fuzz).
/// Defers on a surrogate string (Python accepts it; parity is preserved because the
/// deferred pure-Python path produces the identical result/exception).
#[pyfunction]
fn reject_unsafe_string_py(s: Bound<'_, PyString>, field: &str) -> PyResult<String> {
    let raw = py_str_to_utf8(&s)?;
    reject_unsafe_string(raw, field)
}

/// Byte-identical / decision-identical mirror of
/// `bridge.intent_parser.enforce_argument_safety`. Returns the sanitized (NFC) dict;
/// raises the real bridge exceptions (IdentityInjection/DepthExceeded/SizeExceeded) or
/// ValueError, or `Defer` for a float / big-int / surrogate payload.
#[pyfunction]
fn enforce_argument_safety<'py>(
    py: Python<'py>,
    arguments: Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    if arguments.downcast::<PyDict>().is_err() {
        return Err(PyValueError::new_err("arguments must be an object"));
    }
    let mut counter: usize = 0;
    let sanitized = walk_build(py, &arguments, 1, &mut counter)?;

    // Post-walk canonical byte ceiling — the exact bytes the payload lock will hash.
    // `sanitized` has no floats/surrogates (those would have deferred in the walk), so
    // encode cannot itself defer here.
    let mut encoded: Vec<u8> = Vec::with_capacity(256);
    encode(py, &sanitized, &mut encoded)?;
    if encoded.len() > MAX_CANONICAL_BYTES {
        return Err(size_exceeded(
            py,
            format!(
                "canonical arguments {} bytes > MAX_CANONICAL_BYTES={}",
                encoded.len(),
                MAX_CANONICAL_BYTES
            ),
        ));
    }
    Ok(sanitized)
}

#[pymodule]
fn mcpip_fastwalk(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("Defer", m.py().get_type::<Defer>())?;
    // The bundled UCD version of the normalization tables, formatted exactly like
    // CPython's `unicodedata.unidata_version` (e.g. "15.0.0"). The Python shim asserts
    // this equals `unicodedata.unidata_version` at import and REFUSES to activate the
    // accelerator on any mismatch — the fail-closed guard against a canonicalizer skew
    // (mismatched NFC/NFKC tables) breaking the payload-lock register/consume binding.
    m.add(
        "UNICODE_VERSION",
        format!("{}.{}.{}", UNICODE_VERSION.0, UNICODE_VERSION.1, UNICODE_VERSION.2),
    )?;
    m.add_function(wrap_pyfunction!(canonical_json, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_hex, m)?)?;
    m.add_function(wrap_pyfunction!(reject_unsafe_string_py, m)?)?;
    m.add_function(wrap_pyfunction!(enforce_argument_safety, m)?)?;
    Ok(())
}
