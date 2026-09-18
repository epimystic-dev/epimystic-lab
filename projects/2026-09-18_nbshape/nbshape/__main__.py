"""Entry point for `python -m nbshape`."""

from __future__ import annotations

import sys

from .cli import main

sys.exit(main())
