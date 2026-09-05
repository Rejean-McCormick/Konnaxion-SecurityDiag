#!/usr/bin/env python3
from __future__ import annotations
import sys
from pathlib import Path

TOOL_ROOT = Path(__file__).resolve().parent
if str(TOOL_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOL_ROOT))

from securitydiag_core.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
