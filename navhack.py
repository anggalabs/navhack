#!/usr/bin/env python3
"""Zero-install launcher for navhack.

Three supported invocations::

    python navhack.py <command>      # directly
    python -m navhack <command>      # from the repo root
    navhack <command>                # after `pip install .`

The ``__path__`` assignment turns this module into a package shim, so
``import navhack.cli`` works even though ``navhack.py`` shadows the real
package on ``sys.path``.
"""

from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "src")
PACKAGE = os.path.join(SRC, "navhack")

if os.path.isdir(PACKAGE):
    if SRC not in sys.path:
        sys.path.insert(0, SRC)
    __path__ = [PACKAGE]  # type: ignore[assignment]
    __package__ = "navhack"
    try:
        with open(os.path.join(PACKAGE, "__init__.py"), encoding="utf-8") as handle:
            __version__ = re.search(r'__version__ = "([^"]+)"', handle.read()).group(1)  # type: ignore[union-attr]
    except Exception:
        __version__ = "0.0.0"

if __name__ == "__main__":
    from navhack.cli import main

    sys.exit(main())
