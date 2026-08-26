"""Structured JSON logging with mandatory secret redaction.

CloudWatch Logs Insights can query JSON fields directly, so every record is one JSON
object on one line. The redaction filter is applied at the handler, not at each call site:
relying on developers to remember not to log a token is not a control.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

from app.core.context import current_request_id

# Field names whose values must never reach a log, however they were passed in.
_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "new_password",
        "current_password",
        "client_secret",
        "code",
        "code_verifier",
        "refresh_token",
        "access_token",
        "id_token",
        "token",
        "authorization",
        "cookie",
        "set-cookie",
        "totp_code",
        "otp",
        "recovery_code",
        "private_key",
        "secret",
        "totp_secret",
        "csrf_token",
        "session_id",
    }
)

# Catches secrets that arrive embedded in a formatted message string rather than as a field.
# Ordered most-specific first: a bearer credential or a JWT is recognised by its own shape before
# the generic `key=value` sweep gets to it.
_INLINE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]+"), "Bearer ***"),
    (re.compile(r"\beyJ[A-Za-z0-9._\-]{10,}"), "<jwt-redacted>"),
    (
        # The optional quote before the separator matters: a secret logged as part of a JSON
        # fragment appears as `"client_secret": "value"`, not `client_secret=value`.
        re.compile(
            r"(?i)\b("
            + "|".join(sorted(_SENSITIVE_KEYS))
            + r")\b[\"']?\s*[=:]\s*[\"']?([^\s\"',}&]+)"
        ),
        r"\1=***",
    ),
)

_RESERVED_RECORD_ATTRS = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
    }
)

REDACTED = "***"


def redact_value(value: Any) -> Any:
    """Recursively strip sensitive material from a structure bound for a log."""
    if isinstance(value, dict):
        return {
            key: (REDACTED if str(key).lower() in _SENSITIVE_KEYS else redact_value(item))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_text(text: str) -> str:
    for pattern, replacement in _INLINE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class JsonFormatter(logging.Formatter):
    """Renders a record as a single-line JSON object, redacting as it goes."""

    def __init__(self, *, environment: str, service: str = "authforge") -> None:
        super().__init__()
        self._environment = environment
        self._service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
            "service": self._service,
            "environment": self._environment,
        }
        request_id = current_request_id()
        if request_id:
            payload["request_id"] = request_id
        for key, value in record.__dict__.items():
            if key in _RESERVED_RECORD_ATTRS or key.startswith("_") or key in payload:
                continue
            # A sensitive *name* is enough to redact: `extra={"refresh_token": ...}` arrives here as
            # a bare string with no surrounding context for the inline patterns to recognise.
            payload[key] = REDACTED if key.lower() in _SENSITIVE_KEYS else redact_value(value)
        if record.exc_info:
            payload["exception"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, default=str, separators=(",", ":"))


def configure_logging(*, level: str = "INFO", environment: str = "local") -> None:
    """Install the JSON handler as the only root handler.

    Uvicorn's access log is silenced because the request middleware emits a richer,
    correlated, redacted equivalent — two access logs per request is noise, and uvicorn's
    includes full query strings (which can carry an authorization ``code``).
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(environment=environment))

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level.upper())

    for noisy in ("uvicorn.access",):
        logging.getLogger(noisy).handlers = []
        logging.getLogger(noisy).propagate = False
    logging.getLogger("uvicorn.error").setLevel(max(logging.INFO, root.level))
    # SQLAlchemy logs statements *and bound parameters* at INFO on sqlalchemy.engine.Engine.
    # That is useful locally and forbidden in staging/prod (secrets in CloudWatch, cost).
    engine_level = logging.INFO if environment == "local" else logging.WARNING
    logging.getLogger("sqlalchemy.engine").setLevel(engine_level)
    logging.getLogger("sqlalchemy.engine.Engine").setLevel(engine_level)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
