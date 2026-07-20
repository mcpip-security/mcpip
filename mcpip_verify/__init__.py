"""
MCPIP release verification tooling (READ-ONLY, fail-closed, offline).

Public surface: :func:`mcpip_verify.cli.main` (the ``mcpip`` console script,
re-exported lazily so ``python -m mcpip_verify.cli`` never double-imports)
and the pure verifier library in :mod:`mcpip_verify.verifier`.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcpip_verify.cli import main as main

__all__ = ["main"]


def __getattr__(name: str) -> object:
    if name == "main":
        from mcpip_verify.cli import main as _main

        return _main
    raise AttributeError(name)
