"""Audit-log persistence."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditEventType, AuditLog


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record(
        self,
        *,
        event_type: AuditEventType,
        success: bool = True,
        user_id: str | None = None,
        client_id: str | None = None,
        subject_hint: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> AuditLog:
        entry = AuditLog(
            event_type=str(event_type),
            success=success,
            user_id=user_id,
            client_id=client_id,
            subject_hint=subject_hint,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            detail=detail or {},
        )
        self._session.add(entry)
        # Flushed but not committed: the caller's transaction decides. See AuditService for
        # how a failure here is prevented from denying a legitimate authentication.
        await self._session.flush()
        return entry

    async def list_events(
        self,
        *,
        event_type: AuditEventType | None = None,
        user_id: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditLog]:
        statement = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
        if event_type is not None:
            statement = statement.where(AuditLog.event_type == str(event_type))
        if user_id is not None:
            statement = statement.where(AuditLog.user_id == user_id)
        if since is not None:
            statement = statement.where(AuditLog.created_at >= since)
        result = await self._session.execute(statement)
        return list(result.scalars())
