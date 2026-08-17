"""Signing-key metadata persistence."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.signing_key import KeyStatus, SigningKey


class SigningKeyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        kid: str,
        public_jwk: dict[str, Any],
        public_pem: str,
        private_key_ref: str,
        status: KeyStatus,
        algorithm: str = "RS256",
    ) -> SigningKey:
        key = SigningKey(
            kid=kid,
            public_jwk=public_jwk,
            public_pem=public_pem,
            private_key_ref=private_key_ref,
            status=str(status),
            algorithm=algorithm,
            activated_at=func.now() if status is KeyStatus.CURRENT else None,
        )
        self._session.add(key)
        await self._session.flush()
        return key

    async def get_current(self) -> SigningKey | None:
        result = await self._session.execute(
            select(SigningKey)
            .where(SigningKey.status == str(KeyStatus.CURRENT))
            .order_by(SigningKey.created_at.desc())
        )
        # `.first()` rather than `.one()`: a botched rotation could momentarily leave two
        # `current` rows, and refusing to serve any token at all would be a worse outcome
        # than signing with the newest of them.
        return result.scalars().first()

    async def get_by_kid(self, kid: str) -> SigningKey | None:
        result = await self._session.execute(select(SigningKey).where(SigningKey.kid == kid))
        return result.scalars().one_or_none()

    async def list_publishable(self) -> list[SigningKey]:
        """Keys that belong in JWKS: `current` plus any still inside its grace period."""
        result = await self._session.execute(
            select(SigningKey)
            .where(SigningKey.status.in_([str(KeyStatus.CURRENT), str(KeyStatus.RETIRING)]))
            .order_by(SigningKey.created_at.desc())
        )
        return list(result.scalars())

    async def list_all(self) -> list[SigningKey]:
        result = await self._session.execute(
            select(SigningKey).order_by(SigningKey.created_at.desc())
        )
        return list(result.scalars())

    async def mark_retiring(self, *, kid: str, retire_after: datetime) -> None:
        await self._session.execute(
            update(SigningKey)
            .where(SigningKey.kid == kid)
            .values(
                status=str(KeyStatus.RETIRING), retiring_at=func.now(), retire_after=retire_after
            )
        )

    async def mark_current(self, *, kid: str) -> None:
        await self._session.execute(
            update(SigningKey)
            .where(SigningKey.kid == kid)
            .values(status=str(KeyStatus.CURRENT), activated_at=func.now())
        )

    async def mark_retired(self, *, kid: str) -> None:
        await self._session.execute(
            update(SigningKey)
            .where(SigningKey.kid == kid)
            .values(status=str(KeyStatus.RETIRED), retired_at=func.now())
        )

    async def list_expired_retiring(self, *, now: datetime) -> list[SigningKey]:
        """`retiring` keys whose grace period has elapsed and may leave JWKS."""
        result = await self._session.execute(
            select(SigningKey).where(
                SigningKey.status == str(KeyStatus.RETIRING),
                SigningKey.retire_after.is_not(None),
                SigningKey.retire_after <= now,
            )
        )
        return list(result.scalars())
