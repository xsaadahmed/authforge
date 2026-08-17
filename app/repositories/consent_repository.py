"""Consent persistence."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, cast

from sqlalchemy import CursorResult, Result, delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.consent import Consent


class ConsentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, *, user_id: str, client_id: str) -> Consent | None:
        result = await self._session.execute(
            select(Consent).where(Consent.user_id == user_id, Consent.client_id == client_id)
        )
        return result.scalars().one_or_none()

    async def grant(
        self,
        *,
        user_id: str,
        client_id: str,
        granted_scopes: Sequence[str],
        considered_scopes: Sequence[str],
        expires_at: datetime | None = None,
    ) -> Consent:
        """Upsert both sets for a (user, client) pair.

        Both are stored verbatim as computed by ``ConsentService``; the merge rules (this request's
        decision wins for the scopes in this request, earlier grants persist for scopes outside it)
        are policy and belong in the service, not in SQL.
        """
        granted = sorted(dict.fromkeys(granted_scopes))
        considered = sorted(dict.fromkeys(considered_scopes))
        statement = (
            insert(Consent)
            .values(
                user_id=user_id,
                client_id=client_id,
                granted_scopes=granted,
                considered_scopes=considered,
                expires_at=expires_at,
            )
            .on_conflict_do_update(
                index_elements=[Consent.user_id, Consent.client_id],
                set_={
                    "granted_scopes": granted,
                    "considered_scopes": considered,
                    "expires_at": expires_at,
                },
            )
            .returning(Consent)
        )
        result = await self._session.execute(statement)
        return result.scalars().one()

    async def revoke(self, *, user_id: str, client_id: str) -> int:
        result = await self._session.execute(
            delete(Consent).where(Consent.user_id == user_id, Consent.client_id == client_id)
        )
        return _affected_rows(result)

    async def list_for_user(self, user_id: str) -> list[Consent]:
        result = await self._session.execute(
            select(Consent).where(Consent.user_id == user_id).order_by(Consent.created_at)
        )
        return list(result.scalars())


def _affected_rows(result: Result[Any]) -> int:
    """Rows touched by a DML statement.

    ``Session.execute`` is typed as returning ``Result``, but every UPDATE/DELETE returns a
    ``CursorResult``, the only variant carrying ``rowcount``. The narrowing is explicit here rather
    than repeated as an ignore comment at each call site.
    """
    return cast("CursorResult[Any]", result).rowcount or 0
