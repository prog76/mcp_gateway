#!/usr/bin/env python3
"""Allow ``python -m mcp_policy_proxy`` as an alternative to the console script."""

import sys

from mcp_policy_proxy.start import main

if __name__ == "__main__":
    sys.exit(main())