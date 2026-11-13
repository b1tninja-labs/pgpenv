"""Allow python -m pgpenv without installing the console script."""

from __future__ import annotations

from .cli import main

raise SystemExit(main())
