#!/usr/bin/env python3
"""Allow ``python -m gateway`` as an alternative to the console script."""

import sys

from gateway.start import main

if __name__ == "__main__":
    sys.exit(main())