"""Security audit event emission (§20).

Every event goes to three places with different guarantees:

* a **structured log line** — always, redacted, correlated by request ID; the fast path an
  investigator greps and the one that cannot fail;
* a **CloudWatch metric** via EMF, for the events worth alarming on;
* a **Postgres row**, for durable, queryable history.

The §12/§21 trade-off — "audit writes should not block the primary operation, but should be atomic
with it where feasible" — is resolved by offering three explicitly different persistence modes
rather than one compromise:

``record``
    Writes inside the caller's transaction but wrapped in a SAVEPOINT, so a failure of the audit
    insert rolls back only itself and the authentication proceeds. Commits when the caller commits.
    This is the default and it borrows no extra database connection.

``record_in_transaction``
    Writes inside the caller's transaction with no savepoint, so the event and the state change are
    genuinely all-or-nothing. Used where "we did X" and "we recorded why we did X" must not be
    separable.

``record_durable``
    Writes and commits in its own transaction. Used on paths that are *about* to fail the request:
    a rejected authorization, a rate-limited login, a detected token replay. Those all end in a
    rolled-back request transaction, so an event recorded any other way would vanish exactly when it
    matters most.
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

# Events that also get a CloudWatch metric, because a dashboard or an alarm is built on them.
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
        session: AsyncSession,
        event_type: AuditEventType,
        *,
        success: bool = True,
        user_id: str | None = None,
        client_id: str | None = None,
        subject_hint: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Record inside the caller's transaction, protected by a SAVEPOINT. Never raises."""
        context = self._log_and_measure(
            event_type,
            success=success,
            user_id=user_id,
            client_id=client_id,
            subject_hint=subject_hint,
            detail=detail,
        )
        try:
            async with session.begin_nested():
                await AuditRepository(session).record(**context)
        except Exception:
            self._report_write_failure(event_type)
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
        """Record inside the caller's transaction with no savepoint; propagates failures."""
        context = self._log_and_measure(
            event_type,
            success=success,
            user_id=user_id,
            client_id=client_id,
            subject_hint=subject_hint,
            detail=detail,
        )
        await AuditRepository(session).record(**context)

    async def record_durable(
        self,
        event_type: AuditEventType,
        *,
        success: bool = False,
        user_id: str | None = None,
        client_id: str | None = None,
        subject_hint: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Record and commit in a dedicated transaction. Never raises.

        For events on a request that is about to fail: the caller's transaction will be rolled back,
        and a rejected authorization or a detected replay is precisely the event an investigator
        needs to still be there afterwards.
        """
        context = self._log_and_measure(
            event_type,
            success=success,
            user_id=user_id,
            client_id=client_id,
            subject_hint=subject_hint,
            detail=detail,
        )
        try:
            async with self._database.session() as own_session:
                await AuditRepository(own_session).record(**context)
        except Exception:
            self._report_write_failure(event_type)
            if self._settings.audit_failures_are_fatal:
                raise

    def _report_write_failure(self, event_type: AuditEventType) -> None:
        # The log line above already carries the event, so an investigator still sees it even when
        # the durable copy could not be written. `degraded` makes the gap queryable.
        logger.error(
            "audit event could not be persisted",
            extra={"event_type": str(event_type), "degraded": True},
            exc_info=True,
        )
        get_metrics().count("AuditWriteFailure")

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
                # Not `client_id`: LogRecord already has attributes we must not collide with, and a
                # distinct name keeps OAuth clients separable from other identifiers in queries.
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
