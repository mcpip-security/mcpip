#!/usr/bin/env python3
"""Stamp the root component onto a generated CycloneDX SBOM, and refuse to leak.

``cyclonedx-py environment`` inventories a virtualenv. It produces a components
list and no ``metadata.component`` — so the document says what is *installed*
without saying what it is installed *for*. An SBOM with no root component fails
the NTIA minimum elements, gives ``grype``/``trivy``/Dependency-Track nothing to
attribute findings to, and cannot be matched to a release by any consumer that
was not told out of band which release it belongs to.

The second job is refusal. The 2.0.0 SBOM shipped with

    "bom-ref": "...file:///Users/yuvalkatz/mcpip-genesis/rust/mcpip_fastwalk"

embedded in it — a maintainer's home directory and the project's pre-publication
name, published in a signed release artifact. That came from inventorying a
development virtualenv containing an editable local install; building from the
runtime closure removes the cause, and this refuses the symptom, because a
generator that merely *usually* avoids leaking a build path is not a control.

Both checks fail the build rather than sanitizing silently: an unexpected local
path means the SBOM described something other than the runtime closure, and that
is a fact about the release worth stopping for.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator

#: Absolute-path shapes that identify a machine rather than a package: a POSIX
#: home or build directory, a Windows drive path, a file:// URL. Package URLs
#: (``pkg:pypi/...``) and https references are unaffected.
_LEAK = re.compile(
    r"file://[^\s\"']*"
    r"|(?<![\w.])/(?:home|Users|root|build|workspace|tmp|private)/[^\s\"':,]+"
    r"|[A-Za-z]:\\\\[^\s\"']+"
)


def _strings(node: Any, path: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from _strings(value, f"{path}.{key}" if path else key)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _strings(value, f"{path}[{index}]")


def find_leaks(document: dict[str, Any]) -> list[str]:
    """Every local filesystem path reachable in the document, with its location."""
    found: list[str] = []
    for where, text in _strings(document):
        for match in _LEAK.findall(text):
            found.append(f"{where}: {match}")
    return found


def root_component(version: str) -> dict[str, Any]:
    """The thing this SBOM is *about* — the gateway, not the virtualenv."""
    return {
        "type": "application",
        "bom-ref": f"pkg:pypi/mcpip@{version}",
        "name": "mcpip",
        "version": version,
        "purl": f"pkg:pypi/mcpip@{version}",
        "description": (
            "MCPIP authorization gateway — runtime dependency closure "
            "(requirements.txt, as resolved by the Dockerfile builder stage)"
        ),
        "licenses": [{"license": {"id": "BUSL-1.1"}}],
        "externalReferences": [
            {"type": "vcs", "url": "https://github.com/mcpip-security/mcpip"},
        ],
    }


def finalize(document: dict[str, Any], version: str) -> dict[str, Any]:
    metadata = document.setdefault("metadata", {})
    metadata["component"] = root_component(version)
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)

    document = json.loads(args.input.read_text(encoding="utf-8"))
    document = finalize(document, args.version)

    leaks = find_leaks(document)
    if leaks:
        print(
            "SBOM contains local filesystem paths — it did not describe the runtime\n"
            "closure, or an editable local install was picked up. Refusing to write:",
            file=sys.stderr,
        )
        for leak in leaks:
            print(f"  {leak}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    count = len(document.get("components") or [])
    print(f"  root component: mcpip {args.version}; {count} runtime components")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
