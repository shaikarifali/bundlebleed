from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(scan_run_id: str) -> None:
    """Configure structlog for JSON output, with scan_run_id bound to every
    log line so events from one scan can be correlated end to end."""
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )
    structlog.contextvars.bind_contextvars(scan_run_id=scan_run_id)
