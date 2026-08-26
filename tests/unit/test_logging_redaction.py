"""Secret-redaction tests for the logging layer.

Redaction is applied at the formatter rather than at each call site, because "remember not to log
the token" is a convention, not a control. These tests are the control.
"""

from __future__ import annotations

import json
import logging

import pytest

from app.core.logging import JsonFormatter, configure_logging, redact_text, redact_value

A_JWT = (
    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYyJ9."
    "eyJzdWIiOiIwMUhaIiwic2NvcGUiOiJvcGVuaWQifQ."
    "c2lnbmF0dXJlLWhlcmU"
)


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "client_secret",
        "refresh_token",
        "access_token",
        "code_verifier",
        "totp_code",
        "recovery_code",
        "authorization",
        "cookie",
        "session_id",
        "csrf_token",
        "private_key",
    ],
)
def test_sensitive_field_names_are_replaced(key: str) -> None:
    assert redact_value({key: "super-secret-value"}) == {key: "***"}


def test_redaction_recurses_through_nested_structures() -> None:
    payload = {
        "outer": {"inner": [{"password": "hunter2"}, {"safe": "value"}]},
        "list": ["fine", {"refresh_token": "rt-value"}],
    }
    redacted = redact_value(payload)
    assert redacted["outer"]["inner"][0] == {"password": "***"}
    assert redacted["outer"]["inner"][1] == {"safe": "value"}
    assert redacted["list"][1] == {"refresh_token": "***"}


def test_non_sensitive_fields_survive_intact() -> None:
    """Redaction that ate the useful fields would just move the problem to un-investigable logs."""
    payload = {"user_id": "01HZ", "client_id": "demo", "kid": "key-1", "jti": "01HZJTI"}
    assert redact_value(payload) == payload


def test_secrets_embedded_in_a_message_string_are_scrubbed() -> None:
    assert "hunter2" not in redact_text("login failed for password=hunter2")
    assert "abc123" not in redact_text('{"client_secret": "abc123"}')


def test_bearer_headers_are_scrubbed() -> None:
    redacted = redact_text(f"Authorization: Bearer {A_JWT}")
    assert A_JWT not in redacted
    assert "***" in redacted


def test_anything_shaped_like_a_jwt_is_scrubbed() -> None:
    """Catches tokens that arrive in an unexpected field name, which is exactly the case a
    field-name allowlist would miss."""
    assert A_JWT not in redact_text(f"issued token {A_JWT} for user")
    assert "<jwt-redacted>" in redact_text(f"issued token {A_JWT} for user")


def test_formatter_emits_one_line_of_json_with_the_expected_envelope() -> None:
    formatter = JsonFormatter(environment="test")
    record = logging.LogRecord(
        name="authforge.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="something happened",
        args=(),
        exc_info=None,
    )
    rendered = formatter.format(record)
    assert "\n" not in rendered
    payload = json.loads(rendered)
    assert payload["level"] == "INFO"
    assert payload["message"] == "something happened"
    assert payload["service"] == "authforge"
    assert payload["environment"] == "test"
    assert payload["timestamp"].endswith("+00:00")


def test_formatter_redacts_extra_fields() -> None:
    formatter = JsonFormatter(environment="test")
    record = logging.LogRecord(
        name="authforge.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="token issued",
        args=(),
        exc_info=None,
    )
    record.refresh_token = "rt-abc"  # type: ignore[attr-defined]
    record.jti = "01HZJTI"  # type: ignore[attr-defined]
    payload = json.loads(formatter.format(record))
    assert payload["refresh_token"] == "***"
    assert payload["jti"] == "01HZJTI"


def test_sqlalchemy_engine_logger_is_quiet_outside_local() -> None:
    """Bound SQL parameters must not ride along at INFO in staging/prod CloudWatch."""
    configure_logging(level="INFO", environment="staging")
    assert logging.getLogger("sqlalchemy.engine").level == logging.WARNING
    assert logging.getLogger("sqlalchemy.engine.Engine").level == logging.WARNING
    configure_logging(level="INFO", environment="local")
    assert logging.getLogger("sqlalchemy.engine").level == logging.INFO


def test_formatter_redacts_exception_text() -> None:
    """A traceback can contain a token in a local variable's repr or an exception message."""
    formatter = JsonFormatter(environment="test")
    try:
        raise ValueError("failed with client_secret=leaked-value")
    except ValueError:
        import sys

        record = logging.LogRecord(
            name="authforge.test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="boom",
            args=(),
            exc_info=sys.exc_info(),
        )
    payload = json.loads(formatter.format(record))
    assert "leaked-value" not in payload["exception"]
