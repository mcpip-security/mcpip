"""
Allow ``python -m mcpip_verify`` alongside the ``mcpip-verify`` console script.

An auditor verifying a signed release often has the source tree and an
interpreter but no installed distribution — a checked-out tarball in an
air-gapped enclave being the case this exists for. Without this module that
invocation failed with "package cannot be directly executed", leaving the
console script as the only way in.
"""

from __future__ import annotations

import sys

from mcpip_verify.cli import main

if __name__ == "__main__":
    sys.exit(main())
