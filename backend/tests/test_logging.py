import json
import logging
from io import StringIO

from app.logging import JsonFormatter, RedactingFilter, redact_text


def _logger_for_stream(stream: StringIO) -> logging.Logger:
    logger = logging.getLogger("test.logging")
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    return logger


def test_structured_logs_redact_sensitive_fields_recursively() -> None:
    stream = StringIO()
    logger = _logger_for_stream(stream)

    logger.info(
        "request completed",
        extra={
            "request_id": "request-123",
            "authorization": "synthetic-authorization-value",
            "session_id": "synthetic-session-value",
            "headers": {
                "Cookie": "synthetic-cookie-value",
                "nested": {"token": "synthetic-token-value"},
            },
            "safe_status": "ok",
        },
    )

    event = json.loads(stream.getvalue())
    output = stream.getvalue()
    for secret in (
        "synthetic-authorization-value",
        "synthetic-session-value",
        "synthetic-cookie-value",
        "synthetic-token-value",
    ):
        assert secret not in output
    assert event["request_id"] == "request-123"
    assert event["safe_status"] == "ok"
    assert event["authorization"] == "[REDACTED]"
    assert event["headers"]["Cookie"] == "[REDACTED]"


def test_formatted_messages_and_exceptions_are_redacted() -> None:
    stream = StringIO()
    logger = _logger_for_stream(stream)

    logger.info(
        "authorization=%s session=%s cookie=%s token=%s password=%s",
        "synthetic-authorization-value",
        "synthetic-session-value",
        "synthetic-cookie-value",
        "synthetic-token-value",
        "synthetic-password-value",
    )
    try:
        raise ValueError("password=synthetic-exception-value")
    except ValueError:
        logger.exception("request failed")

    output = stream.getvalue()
    for secret in (
        "synthetic-authorization-value",
        "synthetic-session-value",
        "synthetic-cookie-value",
        "synthetic-token-value",
        "synthetic-password-value",
        "synthetic-exception-value",
    ):
        assert secret not in output
    assert "[REDACTED]" in output


def test_text_redaction_does_not_duplicate_placeholder_delimiters() -> None:
    assert redact_text("authorization=synthetic-value") == "authorization=[REDACTED]"
    assert redact_text("Authorization: Bearer synthetic-value") == "Authorization: [REDACTED]"
