"""Structured logging with [Drako] prefix."""

from __future__ import annotations

import logging
import sys


def get_logger(name: str = "drako") -> logging.Logger:
    """Return a logger with the [Drako] prefix format."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter("[Drako] %(levelname)s %(message)s")
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


log = get_logger()
