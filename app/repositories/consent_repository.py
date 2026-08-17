"""Consent persistence."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import delete, select
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
        scopes: Sequence[str],
        expires_at: datetime | None = None,
    ) -> Consent:
        """Upsert the granted set.

        The stored set is *replaced*, not unioned, so a consent screen where the user
        unticks a previously granted scope actually narrows the grant. Union semantics would
        make consent monotonically expanding and impossible to reduce through the UI.
        """
        ordered = sorted(dict.fromkeys(scopes))
        statement = (
            insert(Consent)
            .values(
                user_id=user_id,
                client_id=client_id,
                granted_scopes=ordered,
                expires_at=expires_at,
            )
            .on_conflict_do_update(
                index_elements=[Consent.user_id, Consent.client_id],
                set_={"granted_scopes": ordered, "expires_at": expires_at},
            )
            .returning(Consent)
        )
        result = await self._session.execute(statement)
        return result.scalars().one()

    async def revoke(self, *, user_id: str, client_id: str) -> int:
        result = await self._session.execute(
            delete(Consent).where(Consent.user_id == user_id, Consent.client_id == client_id)
        )
        return result.rowcount or 0

    async def list_for_user(self, user_id: str) -> list[Consent]:
        result = await self._session.execute(
            select(Consent).where(Consent.user_id == user_id).order_by(Consent.created_at)
        )
        return list(result.scalars())
