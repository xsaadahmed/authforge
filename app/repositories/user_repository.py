"""User and MFA-credential persistence."""

from __future__ import annotations

import unicodedata
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import case, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.user import MfaCredential, RecoveryCode, User


def normalize_email(email: str) -> str:
    """Case-fold and NFKC-normalize so one human identity maps to one row.

    Without this, ``Alice@Example.com`` and ``alice@example.com`` are two accounts as far as
    the unique constraint is concerned, which is both a support burden and a way to confuse
    an operator investigating an incident.
    """
    return unicodedata.normalize("NFKC", email).strip().lower()


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        email: str,
        password_hash: str,
        username: str | None = None,
        full_name: str | None = None,
        given_name: str | None = None,
        family_name: str | None = None,
        email_verified: bool = False,
        is_admin: bool = False,
    ) -> User:
        user = User(
            email=normalize_email(email),
            username=username.strip().lower() if username else None,
            password_hash=password_hash,
            full_name=full_name,
            given_name=given_name,
            family_name=family_name,
            email_verified=email_verified,
            is_admin=is_admin,
        )
        self._session.add(user)
        await self._session.flush()
        return user

    async def get_by_id(self, user_id: str) -> User | None:
        result = await self._session.execute(
            select(User).where(User.id == user_id).options(selectinload(User.mfa_credential))
        )
        return result.scalars().one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        result = await self._session.execute(
            select(User)
            .where(User.email == normalize_email(email))
            .options(selectinload(User.mfa_credential))
        )
        return result.scalars().one_or_none()

    async def get_by_login_identifier(self, identifier: str) -> User | None:
        """Look up by email or username — whichever the login form received."""
        cleaned = normalize_email(identifier)
        result = await self._session.execute(
            select(User)
            .where((User.email == cleaned) | (User.username == cleaned))
            .options(selectinload(User.mfa_credential))
        )
        return result.scalars().first()

    async def list_users(self, *, limit: int = 100, offset: int = 0) -> list[User]:
        result = await self._session.execute(
            select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
        )
        return list(result.scalars())

    async def set_password_hash(self, user_id: str, password_hash: str) -> None:
        await self._session.execute(
            update(User)
            .where(User.id == user_id)
            .values(password_hash=password_hash, password_changed_at=func.now())
        )

    async def record_successful_login(self, user_id: str) -> None:
        """Clear the failure counter and lockout on a good password."""
        await self._session.execute(
            update(User)
            .where(User.id == user_id)
            .values(failed_login_count=0, locked_until=None, last_login_at=func.now())
        )

    async def record_failed_login(
        self, user_id: str, *, threshold: int, lockout_seconds: int
    ) -> tuple[int, datetime | None]:
        """Increment the durable failure counter, locking the account at the threshold.

        Done as one SQL statement so concurrent failed attempts from a distributed attacker
        cannot interleave a read-modify-write and undercount. Returns the new count and the
        lockout expiry (if any) for auditing.
        """
        new_count = User.failed_login_count + 1
        locked_until = case(
            (
                new_count >= threshold,
                func.now() + func.make_interval(0, 0, 0, 0, 0, 0, lockout_seconds),
            ),
            else_=User.locked_until,
        )
        result = await self._session.execute(
            update(User)
            .where(User.id == user_id)
            .values(failed_login_count=new_count, locked_until=locked_until)
            .returning(User.failed_login_count, User.locked_until)
        )
        row = result.one()
        return int(row[0]), row[1]

    async def clear_lockout(self, user_id: str) -> None:
        await self._session.execute(
            update(User).where(User.id == user_id).values(failed_login_count=0, locked_until=None)
        )

    async def set_active(self, user_id: str, *, is_active: bool) -> None:
        await self._session.execute(
            update(User).where(User.id == user_id).values(is_active=is_active)
        )

    # ------------------------------------------------------------------ MFA
    async def upsert_unconfirmed_mfa(self, *, user_id: str, secret_encrypted: str) -> MfaCredential:
        """Stage a TOTP secret pending proof of possession.

        Re-enrolling replaces the pending secret rather than adding a second row, so an
        abandoned enrolment cannot leave an unusable factor lying around.
        """
        existing = await self.get_mfa_credential(user_id)
        if existing is not None and existing.confirmed_at is None:
            existing.secret_encrypted = secret_encrypted
            await self._session.flush()
            return existing
        if existing is not None:
            await self._session.delete(existing)
            await self._session.flush()
        credential = MfaCredential(user_id=user_id, secret_encrypted=secret_encrypted)
        self._session.add(credential)
        await self._session.flush()
        return credential

    async def get_mfa_credential(self, user_id: str) -> MfaCredential | None:
        result = await self._session.execute(
            select(MfaCredential).where(MfaCredential.user_id == user_id)
        )
        return result.scalars().one_or_none()

    async def confirm_mfa(self, user_id: str) -> None:
        await self._session.execute(
            update(MfaCredential)
            .where(MfaCredential.user_id == user_id)
            .values(confirmed_at=func.now())
        )

    async def touch_mfa_used(self, user_id: str) -> None:
        await self._session.execute(
            update(MfaCredential)
            .where(MfaCredential.user_id == user_id)
            .values(last_used_at=func.now())
        )

    async def delete_mfa(self, user_id: str) -> None:
        credential = await self.get_mfa_credential(user_id)
        if credential is not None:
            await self._session.delete(credential)
        await self.replace_recovery_codes(user_id=user_id, code_hashes=[])

    # ------------------------------------------------------------------ recovery codes
    async def replace_recovery_codes(self, *, user_id: str, code_hashes: Sequence[str]) -> None:
        """Issuing a new set invalidates the old set — codes are never additive."""
        await self._session.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user_id))
        for code_hash in code_hashes:
            self._session.add(RecoveryCode(user_id=user_id, code_hash=code_hash))
        await self._session.flush()

    async def consume_recovery_code(self, *, user_id: str, code_hash: str) -> bool:
        """Atomically spend a recovery code; False if it is unknown or already used."""
        result = await self._session.execute(
            update(RecoveryCode)
            .where(
                RecoveryCode.user_id == user_id,
                RecoveryCode.code_hash == code_hash,
                RecoveryCode.used_at.is_(None),
            )
            .values(used_at=func.now())
            .returning(RecoveryCode.id)
        )
        return result.scalars().one_or_none() is not None

    async def count_unused_recovery_codes(self, user_id: str) -> int:
        result = await self._session.execute(
            select(func.count())
            .select_from(RecoveryCode)
            .where(RecoveryCode.user_id == user_id, RecoveryCode.used_at.is_(None))
        )
        return int(result.scalar_one())
