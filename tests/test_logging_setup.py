"""backend/logging_setup.py -- text vs. JSON log formatting.

Confirms both output shapes are actually correct (JSON parses, includes the
exception traceback when there is one) and that `configure_logging` wires the
right formatter class onto the root handler for each flag -- the part that
would silently keep shipping text logs even with HUNTER_LOG_JSON=true if the
branch were ever inverted by mistake.
"""

from __future__ import annotations

import json
import logging

from backend.logging_setup import JsonFormatter, configure_logging


def _make_record(
    message: str = "hello", exc_info: bool = False
) -> logging.LogRecord:
    exc = None
    if exc_info:
        try:
            raise ValueError("boom")
        except ValueError:
            import sys

            exc = sys.exc_info()
    return logging.LogRecord(
        name="hunter.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=exc,
    )


class TestJsonFormatter:
    def test_produces_valid_json_with_expected_fields(self) -> None:
        record = _make_record("engine ready")
        payload = json.loads(JsonFormatter().format(record))
        assert payload["level"] == "INFO"
        assert payload["logger"] == "hunter.test"
        assert payload["message"] == "engine ready"
        assert "timestamp" in payload
        assert "exception" not in payload

    def test_includes_exception_traceback_when_present(self) -> None:
        record = _make_record("failed", exc_info=True)
        payload = json.loads(JsonFormatter().format(record))
        assert "ValueError: boom" in payload["exception"]

    def test_message_supports_percent_style_args(self) -> None:
        record = logging.LogRecord(
            name="hunter.test",
            level=logging.WARNING,
            pathname=__file__,
            lineno=1,
            msg="%d rule(s) rejected",
            args=(3,),
            exc_info=None,
        )
        payload = json.loads(JsonFormatter().format(record))
        assert payload["message"] == "3 rule(s) rejected"


class TestConfigureLogging:
    def _restore(self, root: logging.Logger, handlers, level) -> None:
        root.handlers.clear()
        for h in handlers:
            root.addHandler(h)
        root.setLevel(level)

    def test_json_format_attaches_json_formatter(self) -> None:
        root = logging.getLogger()
        saved_handlers, saved_level = list(root.handlers), root.level
        try:
            configure_logging(json_format=True)
            assert len(root.handlers) == 1
            assert isinstance(root.handlers[0].formatter, JsonFormatter)
        finally:
            self._restore(root, saved_handlers, saved_level)

    def test_text_format_attaches_plain_formatter(self) -> None:
        root = logging.getLogger()
        saved_handlers, saved_level = list(root.handlers), root.level
        try:
            configure_logging(json_format=False)
            assert len(root.handlers) == 1
            assert not isinstance(root.handlers[0].formatter, JsonFormatter)
            assert root.handlers[0].formatter is not None
        finally:
            self._restore(root, saved_handlers, saved_level)

    def test_replaces_rather_than_accumulates_handlers(self) -> None:
        root = logging.getLogger()
        saved_handlers, saved_level = list(root.handlers), root.level
        try:
            configure_logging(json_format=False)
            configure_logging(json_format=True)
            configure_logging(json_format=True)
            assert len(root.handlers) == 1
        finally:
            self._restore(root, saved_handlers, saved_level)
