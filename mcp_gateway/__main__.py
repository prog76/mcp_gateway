#!/usr/bin/env python3
"""Allow ``python -m mcp_gateway`` as an alternative to the console script."""

import sys

from mcp_gateway.start import main

if __name__ == "__main__":
    sys.exit(main())