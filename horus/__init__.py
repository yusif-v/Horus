"""Horus — Daily PoC Research Scanner.

Plugin-based architecture. Adding a new source means creating a single
file in sources/ with a run() function. No other files change.

Usage:
    python3 -m horos [--sources github,nvd] [--skip-kev] [--format md]
"""

__version__ = "0.8.0"
