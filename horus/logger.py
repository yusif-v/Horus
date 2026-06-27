"""Structured logging for Horus.

Configures Python's logging module with a consistent format.
Usage:
    from horus.logger import setup_logging, getLogger
    setup_logging()
    logger = get_logger(__name__)
    logger.info("message")
"""

from __future__ import annotations

import logging
import os
import sys


def setup_logging() -> None:
    """Configure root logger for Horus.

    - Log level from HORUS_LOG_LEVEL env (default: INFO)
    - Format: %(asctime)s [%(levelname)s] %(name)s: %(message)s
    - Output to stderr
    """
    level_name = os.environ.get("HORUS_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root = logging.getLogger("horus")
    root.setLevel(level)

    # Avoid duplicate handlers on re-init
    if not root.handlers:
        root.addHandler(handler)
    else:
        # Replace existing handler to pick up new level/format
        for h in root.handlers[:]:
            root.removeHandler(h)
        root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Get a logger under the horus namespace."""
    if not logging.getLogger("horus").handlers:
        setup_logging()
    return logging.getLogger(name)
