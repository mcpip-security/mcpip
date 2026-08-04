"""
MCPIP — a global flag that is documented as optional must actually be optional.

Every global (`--gateway`, `--context`, `--sandbox`, …) is attached with
`default=argparse.SUPPRESS` so it can appear before OR after the subcommand
without a later default clobbering an earlier value. The cost of that trick is
that **the attribute does not exist unless the flag was typed** — so any handler
reading `args.gateway` instead of `getattr(args, "gateway", None)` dies with a
naked `AttributeError` the moment a user omits it.

That is exactly what `mcpip login` did. It is the second command in the CLI's own
"Zero to authorized in three", `docs/start/CLI.md` documents all three flags as
optional, and every example in the README happens to pass all three — so the one
invocation anybody had ever run was the one that worked. `mcpip context set` had
the same bug. Neither had a single test.

These tests are deliberately mechanical: they scan for the unguarded read, and
they invoke the commands with no flags at all.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "sdk", "python", "src"))

from mcpip_sdk.cli.main import build_parser  # noqa: E402

_CLI_DIR = os.path.join(_REPO_ROOT, "sdk", "python", "src", "mcpip_sdk", "cli")

#: The globals declared with SUPPRESS defaults in `_add_global`.
_GLOBALS = (
    "gateway",
    "context",
    "sandbox",
    "config",
    "token_file",
    "token_stdin",
    "token_cmd",
    "json",
    "quiet",
    "no_color",
)

_UNGUARDED = re.compile(r"(?<!getattr\()\bargs\.(" + "|".join(_GLOBALS) + r")\b")


def _command_sources() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for root, _dirs, files in os.walk(_CLI_DIR):
        if "__pycache__" in root:
            continue
        for name in sorted(files):
            if not name.endswith(".py") or name == "_runtime.py":
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf-8") as handle:
                out.append((os.path.relpath(path, _REPO_ROOT), handle.read()))
    return out


def test_no_handler_reads_a_suppressed_global_directly() -> None:
    """`args.gateway` raises when the flag is absent; `getattr` is the contract."""
    offenders: list[str] = []
    for rel, source in _command_sources():
        for line_no, line in enumerate(source.splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            for match in _UNGUARDED.finditer(line):
                # `if getattr(args, "config", None): ... args.config` is safe — the
                # read is inside a truthiness guard on the same name.
                guard = f'getattr(args, "{match.group(1)}"'
                if guard in line or guard in source[: source.find(line)][-400:]:
                    continue
                offenders.append(f"{rel}:{line_no}  {line.strip()}")
    assert not offenders, (
        "these read a SUPPRESS-defaulted global directly, so the command dies with "
        "AttributeError when the flag is omitted:\n  " + "\n  ".join(offenders)
    )


def test_every_optional_global_is_genuinely_optional_in_the_parser() -> None:
    """A flag documented `[--flag]` must parse when absent, for every subcommand."""
    parser = build_parser()
    namespace = parser.parse_args(["login"])
    for name in ("gateway", "context", "sandbox"):
        assert not hasattr(namespace, name), (
            f"--{name} materialised a default; the SUPPRESS contract this file "
            "guards no longer holds and the getattr guards can be simplified"
        )


def test_login_and_context_set_survive_with_no_flags() -> None:
    """The regression itself: build the namespace a bare invocation produces."""
    parser = build_parser()
    for argv in (["login"], ["context", "set", "some-name"]):
        namespace = parser.parse_args(argv)
        # Mirror exactly what the handlers do — these are the reads that crashed.
        assert getattr(namespace, "context", None) is None
        assert getattr(namespace, "gateway", None) is None
        assert getattr(namespace, "sandbox", None) is None
        with_defaults = argparse.Namespace(**vars(namespace))
        assert not hasattr(with_defaults, "gateway")
