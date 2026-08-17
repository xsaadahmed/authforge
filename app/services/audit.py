"""Security audit event emission (§20).

Every event goes to three places with different guarantees:

* a **structured log line** (always, redacted, correlated by request ID) — the fast path an
  investigator greps;
* a **CloudWatch metric** via EMF for the events worth alarming on;
* a **Postgres row** for durable, queryable history.

The trade-off called out in §12/§21 is resolved explicitly here. ``record`` uses its own
short transaction and swallows database errors, so a failure of the audit table can never
deny a legitimate authentication. ``record_in_transaction`` joins the caller's transaction and
does *not* swallow, for the cases where the audit record and the state change must be
all-or-nothing — refresh-token reuse being the important one: "we revoked the family" and "we
recorded why" must not be separable.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.context import current_context
from app.core.database import Database
from app.core.logging import get_logger, redact_value
from app.core.metrics import get_metrics
from app.models.audit import AuditEventType
from app.repositories.audit_repository import AuditRepository

logger = get_logger("authforge.audit")

# Events that get a CloudWatch metric, because an alarm or a dashboard is built on them.
_METRIC_EVENTS = frozenset(
    {
        AuditEventType.LOGIN_SUCCESS,
        AuditEventType.LOGIN_FAILURE,
        AuditEventType.MFA_CHALLENGE_ISSUED,
        AuditEventType.MFA_FAILURE,
        AuditEventType.TOKEN_ISSUED,
        AuditEventType.TOKEN_REFRESHED,
        AuditEventType.TOKEN_REVOKED,
        AuditEventType.REFRESH_REUSE_DETECTED,
        AuditEventType.KEY_ROTATED,
        AuditEventType.AUTHZ_FAILURE,
        AuditEventType.ACCOUNT_LOCKED,
        AuditEventType.RATE_LIMIT_EXCEEDED,
    }
)


class AuditService:
    def __init__(self, *, settings: Settings, database: Database) -> None:
        self._settings = settings
        self._database = database

    async def record(
        self,
        event_type: AuditEventType,
        *,
        success: bool = True,
        user_id: str | None = None,
        client_id: str | None = None,
        subject_hint: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Emit an event on its own transaction; never raises."""
        context = self._log_and_measure(
            event_type,
            success=success,
            user_id=user_id,
            client_id=client_id,
            subject_hint=subject_hint,
            detail=detail,
        )
        try:
            async with self._database.session() as session:
                await AuditRepository(session).record(**context)
        except Exception:
            logger.error(
                "audit event could not be persisted",
                extra={"event_type": str(event_type), "degraded": True},
                exc_info=True,
            )
            if self._settings.audit_failures_are_fatal:
                raise

    async def record_in_transaction(
        self,
        session: AsyncSession,
        event_type: AuditEventType,
        *,
        success: bool = True,
        user_id: str | None = None,
        client_id: str | None = None,
        subject_hint: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Emit an event inside the caller's transaction; propagates database errors."""
        context = self._log_and_measure(
            event_type,
            success=success,
            user_id=user_id,
            client_id=client_id,
            subject_hint=subject_hint,
            detail=detail,
        )
        await AuditRepository(session).record(**context)

    def _log_and_measure(
        self,
        event_type: AuditEventType,
        *,
        success: bool,
        user_id: str | None,
        client_id: str | None,
        subject_hint: str | None,
        detail: dict[str, Any] | None,
    ) -> dict[str, Any]:
        request_context = current_context()
        safe_detail: dict[str, Any] = redact_value(dict(detail or {}))
        logger.info(
            "security event",
            extra={
                "event": str(event_type),
                "outcome": "success" if success else "failure",
                "user_id": user_id,
                "oauth_client_id": client_id,
                "detail": safe_detail,
            },
        )
        if event_type in _METRIC_EVENTS:
            get_metrics().count(
                _metric_name(event_type),
                dimensions={"Outcome": "success" if success else "failure"},
            )
        return {
            "event_type": event_type,
            "success": success,
            "user_id": user_id,
            "client_id": client_id,
            "subject_hint": subject_hint,
            "ip_address": request_context.client_ip,
            "user_agent": request_context.user_agent,
            "request_id": request_context.request_id,
            "detail": safe_detail,
        }


def _metric_name(event_type: AuditEventType) -> str:
    return "".join(part.capitalize() for part in str(event_type).split("_"))
