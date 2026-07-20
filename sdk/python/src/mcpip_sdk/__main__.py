"""Enable ``python -m mcpip_sdk`` — runs the ``mcpip`` CLI."""

from __future__ import annotations

import sys

from mcpip_sdk.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
