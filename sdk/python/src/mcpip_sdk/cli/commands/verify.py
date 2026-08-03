"""
mcpip_sdk.cli.commands.verify — `mcpip verify` / `mcpip export-audit`.

These two live in the `mcpip_verify` package, which ships with the GATEWAY
distribution rather than the SDK. That split is deliberate: release verification
must work for an auditor who has a signed tarball, an interpreter, and no
network — no gateway, no SDK, no credentials. Coupling it to this client would
defeat that.

But both are documented as `mcpip verify …` and `mcpip export-audit …` across
Operations, Release and Compliance — where release verification is an auditable
control — and the documented install (`pipx install ./sdk/python`) puts THIS CLI
on the PATH. So the commands have to exist here, delegating to the real
implementation when it is importable.

When it is not importable, this says exactly that and names both ways to get it,
rather than reporting a verification verdict nothing performed. A verifier that
guesses is worse than one that is absent.
"""

from __future__ import annotations

import argparse
import importlib
import sys
from typing import Callable, Sequence

from mcpip_sdk.cli._runtime import Runtime
from mcpip_sdk.cli.errors import ExitCode

_MISSING = """\
`mcpip {sub}` needs the mcpip_verify package, which ships with the gateway
distribution rather than the SDK — release verification is deliberately
standalone so an auditor can run it with no gateway, no SDK and no network.

Install it, or run it directly from a checkout:

  pip install mcpip            # the gateway distribution
  mcpip-verify {sub} ...       # its own console script, no SDK needed
  python -m mcpip_verify {sub} ...
                               # from a source checkout, nothing installed
"""


def delegate(sub: str, argv: Sequence[str]) -> int:
    """Hand `sub` plus its raw arguments to mcpip_verify's own parser."""
    try:
        # Resolved at runtime rather than imported statically. mcpip_verify lives in
        # the GATEWAY distribution, which the SDK does not depend on and does not
        # typecheck under --strict; a module-level import would drag it into this
        # package's type graph and fail the SDK's own gate for code it does not own.
        module = importlib.import_module("mcpip_verify.cli")
    except ImportError:
        # Honest absence. Never a verdict we did not compute.
        print(_MISSING.format(sub=sub), file=sys.stderr)
        return ExitCode.UNAVAILABLE
    verify_main: Callable[[Sequence[str]], int] = module.main
    return int(verify_main([sub, *argv]))


def cmd_verify(rt: Runtime, args: argparse.Namespace) -> int:
    return delegate("verify", getattr(args, "passthrough", []))


def cmd_export_audit(rt: Runtime, args: argparse.Namespace) -> int:
    return delegate("export-audit", getattr(args, "passthrough", []))
