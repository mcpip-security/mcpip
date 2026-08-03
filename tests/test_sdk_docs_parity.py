"""
MCPIP — docs/start/SDK.md must name only identifiers that actually ship.

This suite exists because the page had drifted into fiction on the TypeScript
side: every class name was wrong (`MCPIPClient` for the real `McpipClient`), the
error classes carried an `…Error` suffix nothing exports, and 15 of the admin
method names did not exist in any form (`registerSkill` for `skillsRegister`).
A TypeScript developer following the page failed on the import line.

Prose drifts silently; a test does not. These checks parse the shipped sources
and the document, and fail on any identifier the document claims but the code
does not provide.

The direction is deliberately one-way: the document may describe a SUBSET of the
surface (it is a guide, not generated API reference), but it may never name
something that does not exist.
"""

from __future__ import annotations

import os
import re

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SDK_DOC = os.path.join(_REPO_ROOT, "docs", "start", "SDK.md")
_TS_SRC = os.path.join(_REPO_ROOT, "sdk", "typescript", "src")
_PY_SRC = os.path.join(_REPO_ROOT, "sdk", "python", "src", "mcpip_sdk")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _ts_class_members(filename: str) -> set[str]:
    """Method names on the classes in one TypeScript module.

    Members are at two-space indent; the optional generic parameter list is why a
    naive `name(` match misses `mcpCall<TResult = unknown>(`.
    """
    src = _read(os.path.join(_TS_SRC, filename))
    found = re.findall(r"^  (?:async\s+)?([A-Za-z_][\w]*)\s*(?:<[^>]*>)?\s*\(", src, re.M)
    return set(found) - {"constructor"}


def _ts_exported_classes() -> set[str]:
    names: set[str] = set()
    for filename in os.listdir(_TS_SRC):
        if filename.endswith(".ts"):
            src = _read(os.path.join(_TS_SRC, filename))
            names.update(re.findall(r"^export (?:abstract )?class ([A-Za-z_][\w]*)", src, re.M))
    return names


def _doc_section(title: str) -> str:
    """The body of one `## ` section of SDK.md."""
    doc = _read(_SDK_DOC)
    body = doc.split(title, 1)[1]
    nxt = re.search(r"^## ", body, re.M)
    return body[: nxt.start()] if nxt else body


def _backticked(text: str) -> set[str]:
    return set(re.findall(r"`([A-Za-z_][\w]*)`", text))


def test_typescript_method_names_all_exist() -> None:
    """Every camelCase method SDK.md's TypeScript section names must be real."""
    real = (
        _ts_class_members("client.ts")
        | _ts_class_members("admin.ts")
        | _ts_class_members("sandbox.ts")
    )
    section = _doc_section("## 10. TypeScript mirror")
    # camelCase identifiers only: lowercase first letter, at least one capital.
    claimed = {n for n in _backticked(section) if re.fullmatch(r"[a-z]+[A-Z]\w*", n)}
    assert claimed, "the TypeScript section names no methods — did it move?"
    missing = sorted(claimed - real)
    assert not missing, f"SDK.md names TypeScript methods that do not exist: {missing}"


def test_typescript_class_names_all_exist() -> None:
    """`McpipClient`, not `MCPIPClient`. The two languages spell the acronym differently."""
    real = _ts_exported_classes()
    doc = _read(_SDK_DOC)
    # Require a real suffix: bare `Mcpip` appears only in prose about the prefix itself.
    claimed = {n for n in _backticked(doc) if re.fullmatch(r"Mcpip[A-Z]\w*", n)}
    assert claimed, "SDK.md names no TypeScript classes — did the parity table move?"
    missing = sorted(claimed - real)
    assert not missing, f"SDK.md names TypeScript classes that do not exist: {missing}"


def test_no_suffixed_error_class_names() -> None:
    """The TypeScript errors have no `…Error` suffix; the doc claimed they did."""
    doc = _read(_SDK_DOC)
    # `MCPIPError` and `McpipError` are the REAL base classes; the bogus names are the
    # suffixed variants (`MCPIPDeniedError`), so require something before "Error".
    bogus = sorted(set(re.findall(r"`((?:MCPIP|Mcpip)\w+Error)`", doc)))
    assert not bogus, f"SDK.md names non-existent error classes: {bogus}"


def test_python_names_all_exist() -> None:
    """The Python column has to hold up too."""
    import mcpip_sdk

    doc = _read(_SDK_DOC)
    claimed = {n for n in _backticked(doc) if re.fullmatch(r"MCPIP[A-Z]\w*", n)}
    missing = sorted(n for n in claimed if not hasattr(mcpip_sdk, n))
    assert not missing, f"SDK.md names Python symbols mcpip_sdk does not export: {missing}"


def test_documented_source_formats_match_the_protocol() -> None:
    """All seven dialects, not the six that predate a2a_task."""
    doc = _read(_SDK_DOC)
    formats = {
        "openai_tool_call",
        "anthropic_tool_use",
        "gemini_function_call",
        "bedrock_tool_use",
        "mcp_jsonrpc",
        "raw_mcp",
        "a2a_task",
    }
    missing = sorted(f for f in formats if f"`{f}`" not in doc)
    assert not missing, f"SDK.md omits shipped source formats: {missing}"


def test_admin_surfaces_are_parallel_except_where_documented() -> None:
    """Python and TypeScript admin methods must match name-for-name, bar three.

    SDK.md tells readers the two surfaces are the same name in snake_case and
    camelCase. That promise is only safe if it is enforced: a new method added to
    one client under a different name in the other would silently make the page
    wrong again. The three real exceptions are pinned here — if you resolve one,
    delete it from this set AND from §10.
    """
    known_exceptions = {
        # python name -> typescript name (or None where TS has no equivalent)
        "extension_submit": "submitExtension",
        "verified_publishers_get": "verifiedPublishers",
        "decisions_iter": None,
    }

    def camel(name: str) -> str:
        head, *rest = name.split("_")
        return head + "".join(word.capitalize() for word in rest)

    py_src = _read(os.path.join(_PY_SRC, "admin.py"))
    py = {m for m in re.findall(r"^    def ([a-z_]+)", py_src, re.M) if not m.startswith("_")}
    ts = _ts_class_members("admin.ts")

    unmatched_py = {m for m in py if camel(m) not in ts} - set(known_exceptions)
    assert not unmatched_py, (
        f"Python admin methods with no camelCase TypeScript twin: {sorted(unmatched_py)}. "
        "Either add the TypeScript method or document it in SDK.md §10 and here."
    )
    expected_ts = {camel(m) for m in py - set(known_exceptions)}
    expected_ts |= {v for v in known_exceptions.values() if v}
    unmatched_ts = ts - expected_ts
    assert not unmatched_ts, (
        f"TypeScript admin methods with no Python twin: {sorted(unmatched_ts)}."
    )
    # And the documented exceptions must still BE exceptions, not silently fixed.
    for py_name, ts_name in known_exceptions.items():
        assert py_name in py, f"{py_name} no longer exists; drop it from the exception set"
        if ts_name is not None:
            assert ts_name in ts, f"{ts_name} no longer exists; update the exception set"
