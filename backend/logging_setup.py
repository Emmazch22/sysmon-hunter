"""Logging configuration.

Two output shapes for the same log records: human-readable text (the
default -- what every session working on this project from a terminal has
looked at so far), and single-line JSON when `HUNTER_LOG_JSON` is set. Log
aggregators built for production (CloudWatch, Loki, the ELK stack) all
expect one JSON object per line, not a format string they have to regex
back apart -- switching formatters is the entire difference between "runs
on my laptop" and "runs somewhere with a log pipeline behind it".
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

TEXT_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
TEXT_DATEFMT = "%H:%M:%S"


class JsonFormatter(logging.Formatter):
    """Renders one JSON object per log record.

    Only the fields that are always meaningful, plus the exception traceback
    when there is one -- an aggregator's schema should not accumulate a wide,
    mostly-null table because every possible LogRecord attribute got dumped
    in "just in case".
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(*, json_format: bool, level: int = logging.INFO) -> None:
    """Set up the root logger for the whole app. Called once, from main.py,
    before anything logs -- swapping formatters after handlers are already
    attached would leave early boot messages in the old shape.
    """
    handler = logging.StreamHandler()
    if json_format:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(fmt=TEXT_FORMAT, datefmt=TEXT_DATEFMT))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
