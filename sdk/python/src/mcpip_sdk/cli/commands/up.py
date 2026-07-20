"""
mcpip_sdk.cli.commands.up — the one blessed front door for a local sandbox.

``mcpip up`` boots the complete local stack — prerequisite checks, Redis
(:63790), a SANDBOX gateway (:8080), and the live company walkthrough — by
running the repo's canonical ``scripts/quickstart_demo.sh``. One source of
truth: the CLI never re-implements the boot steps, so the script and the verb
can never drift. Idempotent (anything already running is reused), sandbox-only
(the script exports ``MCPIP_SANDBOX_MODE=true``; production stays fail-closed
and untouched by this command).

The gateway itself ships in the source checkout, not on PyPI, so ``up`` needs
an MCPIP repo to run from: it auto-detects one by walking upward from the
current directory, or takes ``--repo PATH`` explicitly. Outside a checkout it
fails with the exact `git clone` line to run — never a stack trace.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from mcpip_sdk.cli._runtime import Runtime
from mcpip_sdk.cli.errors import CLIConfigError

# Both must exist for a directory to count as an MCPIP checkout — the script
# alone could be a stray copy; interfaces.py anchors the actual gateway source.
_MARKERS = ("scripts/quickstart_demo.sh", "interfaces.py")

_CLONE_HINT = (
    "mcpip up boots the sandbox gateway from an MCPIP source checkout, and none was "
    "found here.\n"
    "  Get one:   git clone https://github.com/katzyuval/mcpip && cd mcpip && mcpip up\n"
    "  Or point at an existing checkout:   mcpip up --repo /path/to/mcpip"
)


def _is_checkout(candidate: Path) -> bool:
    return all((candidate / marker).is_file() for marker in _MARKERS)


def find_repo_root(explicit: str | None) -> Path | None:
    """The MCPIP checkout to boot from: ``--repo`` verbatim, else cwd upward."""
    if explicit is not None:
        root = Path(explicit).expanduser().resolve()
        return root if _is_checkout(root) else None
    cwd = Path.cwd().resolve()
    for candidate in (cwd, *cwd.parents):
        if _is_checkout(candidate):
            return candidate
    return None


def cmd_up(rt: Runtime, args: argparse.Namespace) -> int:
    root = find_repo_root(args.repo)
    if root is None:
        raise CLIConfigError(_CLONE_HINT)
    script = root / "scripts" / "quickstart_demo.sh"
    if args.print_only:
        # Plan only — nothing starts. Used by tests and the cautious.
        print(f"mcpip up · checkout: {root}")
        print(f"would run: bash {script}")
        print("(prereq checks -> Redis :63790 -> sandbox gateway :8080 -> live walkthrough)")
        return 0
    # Hand the terminal to the script — its own say/note output IS the UX.
    return subprocess.call(["bash", str(script)], cwd=str(root))
