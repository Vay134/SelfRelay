"""Structured logging with conservative redaction for sensitive values."""

from __future__ import annotations

import json
import logging as std_logging
import os
import re
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import TextIO, cast

REDACTED = "[REDACTED]"

_SENSITIVE_KEY_MARKERS = (
    "authorization",
    "cookie",
    "session",
    "csrf",
    "token",
    "password",
    "passphrase",
    "secret",
    "apikey",
    "privatekey",
    "signingkey",
    "otp",
)
_SENSITIVE_FIELD_PATTERN = (
    r"(?:authorization|proxy[-_ ]?authorization|cookie|set[-_ ]?cookie|"
    r"session|csrf|token|password|passphrase|secret|api[-_ ]?key|"
    r"private[-_ ]?key|signing[-_ ]?key|otp)(?:[-_a-z0-9]*)"
)

_AUTH_HEADER_RE = re.compile(
    r"(?P<prefix>(?<![A-Za-z0-9])(?:authorization|proxy[-_ ]?authorization)"
    r"\s*[:=]\s*)(?P<value>[^\r\n,}]+)",
    re.IGNORECASE,
)
_COOKIE_HEADER_RE = re.compile(
    r"(?P<prefix>(?<![A-Za-z0-9])(?:cookie|set[-_ ]?cookie)\s*[:=]\s*)"
    r"(?P<value>[^\r\n,}]+)",
    re.IGNORECASE,
)
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?P<prefix>(?<![A-Za-z0-9])['\"]?" + _SENSITIVE_FIELD_PATTERN + r"['\"]?\s*[:=]\s*)"
    r"(?:(?P<quote>['\"])(?P<quoted>.*?)(?P=quote)|(?P<bare>[^\s,;}\]]+))",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(
    r"(?P<prefix>\b(?:bearer|basic|digest)\s+)(?P<value>[^\s,;]+)",
    re.IGNORECASE,
)

_STANDARD_RECORD_FIELDS = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
        "message",
    }
)
_HANDLER_MARKER = "_e2e_secure_file_transfer_handler"


def _normalise_key(key: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).casefold())


def _is_sensitive_key(key: object) -> bool:
    normalised = _normalise_key(key)
    return any(marker in normalised for marker in _SENSITIVE_KEY_MARKERS)


def _replace_header(match: re.Match[str]) -> str:
    return f"{match.group('prefix')}{REDACTED}"


def _replace_assignment(match: re.Match[str]) -> str:
    quote = match.group("quote") or ""
    return f"{match.group('prefix')}{quote}{REDACTED}{quote}"


def redact_text(value: str) -> str:
    """Redact common secret-bearing values embedded in text."""

    redacted = _SENSITIVE_ASSIGNMENT_RE.sub(_replace_assignment, value)
    redacted = _AUTH_HEADER_RE.sub(_replace_header, redacted)
    redacted = _COOKIE_HEADER_RE.sub(_replace_header, redacted)
    return _BEARER_RE.sub(_replace_header, redacted)


def redact_value(value: object, *, key: object | None = None) -> object:
    """Recursively redact sensitive mapping fields and textual values."""

    if key is not None and _is_sensitive_key(key):
        return REDACTED
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return REDACTED
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, object], value)
        return {
            str(item_key): redact_value(item_value, key=item_key)
            for item_key, item_value in mapping.items()
        }
    if isinstance(value, Sequence):
        sequence = cast(Sequence[object], value)
        return [redact_value(item) for item in sequence]
    if isinstance(value, set | frozenset):
        return [redact_value(item) for item in value]
    return redact_text(str(value))


class RedactingFilter(std_logging.Filter):
    """Remove sensitive values before a record reaches any configured handler."""

    def filter(self, record: std_logging.LogRecord) -> bool:
        record.msg = redact_text(record.getMessage())
        record.args = ()
        if record.exc_info:
            exception_text = std_logging.Formatter().formatException(record.exc_info)
            record.exc_info = None
            record.exc_text = redact_text(exception_text)
        if record.stack_info:
            record.stack_info = redact_text(record.stack_info)
        for key, value in tuple(record.__dict__.items()):
            if key not in {"msg", "args", "exc_info", "exc_text", "stack_info"}:
                record.__dict__[key] = redact_value(value, key=key)
        return True


class JsonFormatter(std_logging.Formatter):
    """Render log records as one redacted JSON object per line."""

    def format(self, record: std_logging.LogRecord) -> str:
        event: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_RECORD_FIELDS:
                event[key] = redact_value(value, key=key)
        if record.exc_text:
            event["exception"] = redact_text(record.exc_text)
        return json.dumps(event, ensure_ascii=False, separators=(",", ":"))


def _resolve_level(level: str | int | None) -> int:
    if level is None:
        return std_logging.INFO
    if isinstance(level, int):
        return level
    resolved = std_logging.getLevelNamesMapping().get(level.strip().upper())
    if resolved is None:
        raise ValueError(f"Unknown log level: {level}")
    return resolved


def _add_redaction_filter(handler: std_logging.Handler) -> None:
    if not any(isinstance(item, RedactingFilter) for item in handler.filters):
        handler.addFilter(RedactingFilter())


def configure_logging(level: str | int | None = None, *, stream: TextIO | None = None) -> None:
    """Configure the process logger with JSON output and redaction."""

    root_logger = std_logging.getLogger()
    root_logger.setLevel(_resolve_level(level if level is not None else os.getenv("LOG_LEVEL")))
    for handler in root_logger.handlers:
        _add_redaction_filter(handler)

    configured_handler = next(
        (handler for handler in root_logger.handlers if getattr(handler, _HANDLER_MARKER, False)),
        None,
    )
    if configured_handler is None:
        configured_handler = std_logging.StreamHandler(stream or sys.stderr)
        setattr(configured_handler, _HANDLER_MARKER, True)
        configured_handler.setFormatter(JsonFormatter())
        _add_redaction_filter(configured_handler)
        root_logger.addHandler(configured_handler)
