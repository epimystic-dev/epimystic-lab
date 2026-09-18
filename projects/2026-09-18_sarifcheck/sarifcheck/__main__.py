"""Entry point for `python -m sarifcheck`."""

from __future__ import annotations

import sys

from .cli import main

sys.exit(main())
