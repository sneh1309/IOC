#!/usr/bin/env python3
"""Zero-install launcher: `python3 run_aletheia.py <command> ...` (used by the Claude plugin)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aletheia.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
