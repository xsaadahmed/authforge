"""Scope catalogue persistence."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.client import Scope


class ScopeRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert(
        self, *, name: str, description: str, is_oidc: bool = False, is_default: bool = False
    ) -> None:
        """Idempotent so the seed script can run repeatedly without special-casing."""
        statement = (
            insert(Scope)
            .values(name=name, description=description, is_oidc=is_oidc, is_default=is_default)
            .on_conflict_do_update(
                index_elements=[Scope.name],
                set_={"description": description, "is_oidc": is_oidc, "is_default": is_default},
            )
        )
        await self._session.execute(statement)

    async def get_by_name(self, name: str) -> Scope | None:
        result = await self._session.execute(select(Scope).where(Scope.name == name))
        return result.scalars().one_or_none()

    async def list_all(self) -> list[Scope]:
        result = await self._session.execute(select(Scope).order_by(Scope.name))
        return list(result.scalars())

    async def list_names(self) -> set[str]:
        result = await self._session.execute(select(Scope.name))
        return set(result.scalars())

    async def find_unknown(self, names: Sequence[str]) -> set[str]:
        """Which of these scope names are not in the catalogue at all."""
        if not names:
            return set()
        result = await self._session.execute(select(Scope.name).where(Scope.name.in_(list(names))))
        return set(names) - set(result.scalars())
