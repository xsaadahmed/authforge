"""Refresh-token persistence, including the atomic single-use redemption (§10).

This is the most security-critical query in the system, so the mechanism is spelled out
here rather than left to the reader:

    UPDATE refresh_tokens
       SET used_at = now()
     WHERE token_hash = :hash AND used_at IS NULL AND revoked = false
    RETURNING *

Under Postgres's default READ COMMITTED isolation, two concurrent transactions running this
statement against the same row serialize on the row lock. The second one re-evaluates its
WHERE clause against the *updated* row, sees ``used_at IS NOT NULL``, and updates zero rows.
So exactly one caller receives a row and may issue new tokens; the other gets nothing and is
routed to the reuse-detection path. No advisory locks, no SELECT ... FOR UPDATE, no
application-level mutex, and nothing that depends on all requests landing on the same task.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, cast

from sqlalchemy import CursorResult, Result, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.token import RefreshToken, RevocationReason


class RefreshTokenRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        token_hash: str,
        family_id: str,
        generation: int,
        previous_token_hash: str | None,
        user_id: str,
        client_id: str,
        scopes: Sequence[str],
        auth_time: datetime,
        expires_at: datetime,
    ) -> RefreshToken:
        token = RefreshToken(
            token_hash=token_hash,
            family_id=family_id,
            generation=generation,
            previous_token_hash=previous_token_hash,
            user_id=user_id,
            client_id=client_id,
            scopes=list(scopes),
            auth_time=auth_time,
            expires_at=expires_at,
        )
        self._session.add(token)
        await self._session.flush()
        return token

    async def claim_for_rotation(self, *, token_hash: str, client_id: str) -> RefreshToken | None:
        """Atomically mark a token used and return it, or return None if unclaimable.

        ``client_id`` is part of the WHERE clause rather than checked afterwards. If it were
        checked afterwards, a client presenting *another* client's refresh token would first
        stamp ``used_at`` on it — destroying a token its rightful owner still needed, and
        tripping reuse detection on the next legitimate refresh. That is a denial-of-service
        primitive available to any registered client, so the binding has to be part of the
        same atomic statement.

        A ``None`` return means one of: unknown hash, wrong client, already redeemed, revoked,
        or expired. The caller cannot tell which from the return value — deliberately, since
        the client-facing answer is ``invalid_grant`` in every case. ``get_by_hash`` resolves
        which it was for the audit trail only.
        """
        statement = (
            update(RefreshToken)
            .where(
                RefreshToken.token_hash == token_hash,
                RefreshToken.client_id == client_id,
                RefreshToken.used_at.is_(None),
                RefreshToken.revoked.is_(False),
                RefreshToken.expires_at > func.now(),
            )
            .values(used_at=func.now())
            .returning(RefreshToken)
        )
        result = await self._session.execute(statement)
        return result.scalars().one_or_none()

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        """Read a token row regardless of state — used to classify a failed claim."""
        result = await self._session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        return result.scalars().one_or_none()

    async def revoke_family(self, family_id: str, *, reason: RevocationReason) -> int:
        """Revoke every token in a family. Returns the number of rows affected.

        Applied to *all* generations including already-used ones, so the family's history is
        unambiguously closed and a later forensic query can see when and why.
        """
        statement = (
            update(RefreshToken)
            .where(RefreshToken.family_id == family_id, RefreshToken.revoked.is_(False))
            .values(revoked=True, revoked_at=func.now(), revocation_reason=str(reason))
        )
        result = await self._session.execute(statement)
        return _affected_rows(result)

    async def revoke_all_for_user(self, user_id: str, *, reason: RevocationReason) -> int:
        statement = (
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked.is_(False))
            .values(revoked=True, revoked_at=func.now(), revocation_reason=str(reason))
        )
        result = await self._session.execute(statement)
        return _affected_rows(result)

    async def revoke_all_for_client(self, client_id: str, *, reason: RevocationReason) -> int:
        statement = (
            update(RefreshToken)
            .where(RefreshToken.client_id == client_id, RefreshToken.revoked.is_(False))
            .values(revoked=True, revoked_at=func.now(), revocation_reason=str(reason))
        )
        result = await self._session.execute(statement)
        return _affected_rows(result)

    async def revoke_for_user_and_client(
        self, *, user_id: str, client_id: str, reason: RevocationReason
    ) -> int:
        statement = (
            update(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.client_id == client_id,
                RefreshToken.revoked.is_(False),
            )
            .values(revoked=True, revoked_at=func.now(), revocation_reason=str(reason))
        )
        result = await self._session.execute(statement)
        return _affected_rows(result)

    async def list_family(self, family_id: str) -> list[RefreshToken]:
        result = await self._session.execute(
            select(RefreshToken)
            .where(RefreshToken.family_id == family_id)
            .order_by(RefreshToken.generation)
        )
        return list(result.scalars())

    async def count_active_for_user(self, user_id: str) -> int:
        result = await self._session.execute(
            select(func.count())
            .select_from(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.used_at.is_(None),
                RefreshToken.revoked.is_(False),
                RefreshToken.expires_at > func.now(),
            )
        )
        return int(result.scalar_one())

    async def delete_expired(self, *, older_than: datetime) -> int:
        """Housekeeping for a scheduled task.

        Expired rows are kept for a while after expiry so reuse detection still has history
        to reason about; only rows past ``older_than`` are removed.
        """
        result = await self._session.execute(
            delete(RefreshToken).where(RefreshToken.expires_at < older_than)
        )
        return _affected_rows(result)


def _affected_rows(result: Result[Any]) -> int:
    """Rows touched by a DML statement.

    ``Session.execute`` is typed as returning ``Result``, but every UPDATE/DELETE returns a
    ``CursorResult``, the only variant carrying ``rowcount``. The narrowing is explicit here rather
    than repeated as an ignore comment at each call site.
    """
    return cast("CursorResult[Any]", result).rowcount or 0
