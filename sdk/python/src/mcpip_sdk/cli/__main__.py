"""Enable ``python -m mcpip_sdk.cli`` — delegates to :func:`mcpip_sdk.cli.main`."""

from __future__ import annotations

import sys

from mcpip_sdk.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
