"""User authentication: password, TOTP second factor, sessions, lockout (§9).

Authentication answers "who is this person" and produces a browser session. It knows nothing
about clients, scopes or tokens — that separation is what keeps the login flow reusable across
every authorization request and keeps the authorization logic free of credential handling.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.errors import ConflictError, DomainError, NotFoundError, RateLimitedError
from app.core.logging import get_logger
from app.models.audit import AuditEventType
from app.models.token import RevocationReason
from app.models.user import User
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.user_repository import UserRepository
from app.security import totp as totp_lib
from app.security.encryption import DecryptionError, SecretEncryptor
from app.security.passwords import PasswordHasherService
from app.security.random_tokens import (
    hash_recovery_code,
    hash_token,
    new_recovery_code,
)
from app.services.audit import AuditService
from app.services.rate_limit import RateLimitService
from app.stores.session_store import PendingMfaState, SessionState, SessionStore

logger = get_logger(__name__)

RECOVERY_CODE_COUNT = 10


class LoginResult(StrEnum):
    SUCCESS = "success"
    MFA_REQUIRED = "mfa_required"
    INVALID_CREDENTIALS = "invalid_credentials"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_DISABLED = "account_disabled"
    RATE_LIMITED = "rate_limited"


@dataclass(frozen=True, slots=True)
class LoginOutcome:
    result: LoginResult
    # Set only on SUCCESS. The raw session ID destined for the cookie.
    session_id: str | None = None
    # Set only on MFA_REQUIRED. Identifies the interim, not-yet-authenticated state.
    pending_mfa_id: str | None = None
    user_id: str | None = None
    retry_after_seconds: int | None = None

    @property
    def authenticated(self) -> bool:
        return self.result is LoginResult.SUCCESS


@dataclass(frozen=True, slots=True)
class MfaEnrolmentChallenge:
    secret: str
    provisioning_uri: str


@dataclass(frozen=True, slots=True)
class MfaEnrolmentResult:
    recovery_codes: list[str]


class AuthenticationService:
    def __init__(
        self,
        *,
        settings: Settings,
        password_hasher: PasswordHasherService,
        session_store: SessionStore,
        rate_limiter: RateLimitService,
        audit: AuditService,
        encryptor: SecretEncryptor,
    ) -> None:
        self._settings = settings
        self._passwords = password_hasher
        self._sessions = session_store
        self._rate_limiter = rate_limiter
        self._audit = audit
        self._encryptor = encryptor

    # ------------------------------------------------------------------ password login
    async def authenticate_password(
        self,
        db: AsyncSession,
        *,
        identifier: str,
        password: str,
        ip_address: str | None,
        pending_authorize_query: str | None = None,
    ) -> LoginOutcome:
        """Verify a password and either issue a session or open an MFA challenge.

        Every failure path returns the same coarse ``INVALID_CREDENTIALS`` result to the caller
        so the login page cannot be used to enumerate accounts, and every path spends
        comparable CPU because ``PasswordHasherService.verify`` hashes even when there is no
        such user.
        """
        verdict = await self._rate_limiter.check_login_attempt(
            ip_address=ip_address, subject=identifier
        )
        if not verdict.allowed:
            await self._audit.record(
                db,
                AuditEventType.RATE_LIMIT_EXCEEDED,
                success=False,
                subject_hint=identifier,
                detail={"scope": "login", "retry_after_seconds": verdict.retry_after_seconds},
            )
            return LoginOutcome(
                result=LoginResult.RATE_LIMITED,
                retry_after_seconds=verdict.retry_after_seconds,
            )

        users = UserRepository(db)
        user = await users.get_by_login_identifier(identifier)
        password_ok = self._passwords.verify(
            password=password, password_hash=user.password_hash if user else None
        )

        if user is None or not password_ok:
            if user is not None:
                count, locked_until = await users.record_failed_login(
                    user.id,
                    threshold=self._settings.account_lockout_threshold,
                    lockout_seconds=self._settings.account_lockout_seconds,
                )
                if locked_until is not None and count >= self._settings.account_lockout_threshold:
                    await self._audit.record_in_transaction(
                        db,
                        AuditEventType.ACCOUNT_LOCKED,
                        success=False,
                        user_id=user.id,
                        subject_hint=identifier,
                        detail={"failed_attempts": count},
                    )
            await self._audit.record(
                db,
                AuditEventType.LOGIN_FAILURE,
                success=False,
                user_id=user.id if user else None,
                subject_hint=identifier,
                detail={"reason": "invalid_credentials"},
            )
            return LoginOutcome(result=LoginResult.INVALID_CREDENTIALS)

        if not user.is_active:
            await self._audit.record(
                db,
                AuditEventType.LOGIN_FAILURE,
                success=False,
                user_id=user.id,
                detail={"reason": "account_disabled"},
            )
            return LoginOutcome(result=LoginResult.ACCOUNT_DISABLED)

        # Checked after the password so a locked account is not a way to learn that an account
        # exists, and so a lockout cannot be triggered by guessing usernames alone.
        if user.locked_until is not None and user.locked_until > datetime.now(tz=UTC):
            await self._audit.record(
                db,
                AuditEventType.LOGIN_FAILURE,
                success=False,
                user_id=user.id,
                detail={
                    "reason": "account_locked",
                    "locked_until": user.locked_until.isoformat(),
                },
            )
            retry_after = int((user.locked_until - datetime.now(tz=UTC)).total_seconds())
            return LoginOutcome(
                result=LoginResult.ACCOUNT_LOCKED, retry_after_seconds=max(1, retry_after)
            )

        if self._passwords.needs_rehash(user.password_hash):
            # Opportunistic upgrade: the plaintext is only available right now, and cost
            # parameters raised in config should apply to existing accounts too.
            await users.set_password_hash(user.id, self._passwords.hash(password))

        await users.record_successful_login(user.id)
        await self._rate_limiter.clear_login_limits(ip_address=ip_address, subject=identifier)

        if user.mfa_enrolled:
            pending_id = await self._sessions.create_pending_mfa(
                PendingMfaState(
                    user_id=user.id,
                    password_verified_at=int(time.time()),
                    pending_authorize_query=pending_authorize_query,
                )
            )
            await self._audit.record(
                db, AuditEventType.MFA_CHALLENGE_ISSUED, user_id=user.id, detail={"factor": "totp"}
            )
            return LoginOutcome(
                result=LoginResult.MFA_REQUIRED, pending_mfa_id=pending_id, user_id=user.id
            )

        session_id = await self._start_session(
            user_id=user.id,
            mfa_verified=False,
            pending_authorize_query=pending_authorize_query,
        )
        await self._audit.record(
            db, AuditEventType.LOGIN_SUCCESS, user_id=user.id, detail={"mfa": False}
        )
        return LoginOutcome(result=LoginResult.SUCCESS, session_id=session_id, user_id=user.id)

    # ------------------------------------------------------------------ MFA challenge
    async def verify_mfa_challenge(
        self,
        db: AsyncSession,
        *,
        pending_mfa_id: str,
        code: str,
        use_recovery_code: bool = False,
    ) -> LoginOutcome:
        """Complete a login by presenting a TOTP code or a single-use recovery code."""
        pending = await self._sessions.get_pending_mfa(pending_mfa_id)
        if pending is None:
            # Expired or forged: the user must start again from the password step. There is no
            # path from here to a session without a fresh password verification.
            return LoginOutcome(result=LoginResult.INVALID_CREDENTIALS)

        verdict = await self._rate_limiter.check_mfa_attempt(
            pending_id_hash=hash_token(pending_mfa_id)
        )
        if not verdict.allowed:
            await self._sessions.delete_pending_mfa(pending_mfa_id)
            # Durable: the handler raises RateLimitedError, so the request transaction is about to
            # be rolled back and this is exactly the event worth keeping.
            await self._audit.record_durable(
                AuditEventType.MFA_FAILURE,
                user_id=pending.user_id,
                detail={"reason": "too_many_attempts"},
            )
            raise RateLimitedError(verdict.retry_after_seconds, "too many MFA attempts")

        users = UserRepository(db)
        user = await users.get_by_id(pending.user_id)
        if user is None or not user.is_active:
            await self._sessions.delete_pending_mfa(pending_mfa_id)
            return LoginOutcome(result=LoginResult.ACCOUNT_DISABLED)

        verified = (
            await self._verify_recovery_code(db, user=user, code=code)
            if use_recovery_code
            else await self._verify_totp_code(db, user=user, code=code)
        )
        if not verified:
            await self._audit.record(
                db,
                AuditEventType.MFA_FAILURE,
                success=False,
                user_id=user.id,
                detail={"factor": "recovery_code" if use_recovery_code else "totp"},
            )
            return LoginOutcome(result=LoginResult.INVALID_CREDENTIALS)

        await self._sessions.delete_pending_mfa(pending_mfa_id)
        session_id = await self._start_session(
            user_id=user.id,
            mfa_verified=True,
            pending_authorize_query=pending.pending_authorize_query,
        )
        await self._audit.record(db, AuditEventType.MFA_SUCCESS, user_id=user.id)
        await self._audit.record(
            db, AuditEventType.LOGIN_SUCCESS, user_id=user.id, detail={"mfa": True}
        )
        return LoginOutcome(result=LoginResult.SUCCESS, session_id=session_id, user_id=user.id)

    async def _verify_totp_code(self, db: AsyncSession, *, user: User, code: str) -> bool:
        credential = user.mfa_credential
        if credential is None or credential.confirmed_at is None:
            return False
        try:
            secret = self._encryptor.decrypt(credential.secret_encrypted)
        except DecryptionError:
            # Means the deployment's TOTP key changed without re-enrolling users. Loud, because
            # silently failing MFA looks identical to a user typing the wrong code.
            logger.error("stored TOTP secret could not be decrypted", extra={"user_id": user.id})
            return False
        if not totp_lib.verify_code(secret=secret, code=code):
            return False
        # Single-use enforcement across the whole fleet: a code observed by an attacker is
        # spent the moment the legitimate user submits it.
        claimed = await self._sessions.mark_totp_code_used(
            totp_lib.replay_key(user_id=user.id, code=code),
            ttl_seconds=totp_lib.TOTP_PERIOD_SECONDS * (2 * totp_lib.TOTP_VALID_WINDOW + 1),
        )
        if not claimed:
            logger.warning("replayed TOTP code rejected", extra={"user_id": user.id})
            return False
        await UserRepository(db).touch_mfa_used(user.id)
        return True

    async def _verify_recovery_code(self, db: AsyncSession, *, user: User, code: str) -> bool:
        consumed = await UserRepository(db).consume_recovery_code(
            user_id=user.id, code_hash=hash_recovery_code(code)
        )
        if not consumed:
            return False
        remaining = await UserRepository(db).count_unused_recovery_codes(user.id)
        await self._audit.record_in_transaction(
            db,
            AuditEventType.MFA_RECOVERY_CODE_USED,
            user_id=user.id,
            detail={"remaining_codes": remaining},
        )
        return True

    # ------------------------------------------------------------------ sessions
    async def _start_session(
        self, *, user_id: str, mfa_verified: bool, pending_authorize_query: str | None
    ) -> str:
        now = int(time.time())
        return await self._sessions.create(
            SessionState(
                user_id=user_id,
                auth_time=now,
                mfa_verified=mfa_verified,
                created_at=now,
                pending_authorize_query=pending_authorize_query,
            )
        )

    async def get_session(self, session_id: str | None) -> SessionState | None:
        if not session_id:
            return None
        return await self._sessions.get(session_id)

    async def logout(
        self, db: AsyncSession, session_id: str | None, *, user_id: str | None = None
    ) -> None:
        if session_id:
            await self._sessions.delete(session_id)
        await self._audit.record(db, AuditEventType.LOGOUT, user_id=user_id)

    async def clear_pending_authorize(self, session_id: str, state: SessionState) -> None:
        state.pending_authorize_query = None
        await self._sessions.replace(session_id, state)

    # ------------------------------------------------------------------ MFA enrolment
    async def begin_mfa_enrolment(self, db: AsyncSession, *, user_id: str) -> MfaEnrolmentChallenge:
        """Stage a TOTP secret. It is inert until confirmed with a live code."""
        users = UserRepository(db)
        user = await users.get_by_id(user_id)
        if user is None:
            raise NotFoundError("user not found")
        if user.mfa_enrolled:
            raise ConflictError("MFA is already enrolled; remove it before re-enrolling")
        secret = totp_lib.generate_secret()
        await users.upsert_unconfirmed_mfa(
            user_id=user_id, secret_encrypted=self._encryptor.encrypt(secret)
        )
        return MfaEnrolmentChallenge(
            secret=secret,
            provisioning_uri=totp_lib.provisioning_uri(
                secret=secret,
                account_name=user.email,
                issuer_name=f"AuthForge ({self._settings.environment})",
            ),
        )

    async def confirm_mfa_enrolment(
        self, db: AsyncSession, *, user_id: str, code: str
    ) -> MfaEnrolmentResult:
        """Confirm enrolment and issue recovery codes — one atomic transaction (§12).

        If any step failed independently the user could end up with a confirmed factor and no
        recovery codes (locked out if they lose their phone) or codes for a factor that was
        never confirmed. The caller's transaction makes both true or neither.
        """
        users = UserRepository(db)
        credential = await users.get_mfa_credential(user_id)
        if credential is None:
            raise DomainError("no pending MFA enrolment; start enrolment first")
        if credential.confirmed_at is not None:
            raise ConflictError("MFA is already enrolled")
        secret = self._encryptor.decrypt(credential.secret_encrypted)
        if not totp_lib.verify_code(secret=secret, code=code):
            raise DomainError("that code did not match; check the authenticator's clock")

        await users.confirm_mfa(user_id)
        codes = [new_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
        await users.replace_recovery_codes(
            user_id=user_id, code_hashes=[hash_recovery_code(code) for code in codes]
        )
        await self._audit.record_in_transaction(
            db,
            AuditEventType.MFA_ENROLLED,
            user_id=user_id,
            detail={"factor": "totp", "recovery_codes_issued": len(codes)},
        )
        return MfaEnrolmentResult(recovery_codes=codes)

    async def regenerate_recovery_codes(
        self, db: AsyncSession, *, user_id: str
    ) -> MfaEnrolmentResult:
        users = UserRepository(db)
        user = await users.get_by_id(user_id)
        if user is None or not user.mfa_enrolled:
            raise DomainError("MFA is not enrolled")
        codes = [new_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
        await users.replace_recovery_codes(
            user_id=user_id, code_hashes=[hash_recovery_code(code) for code in codes]
        )
        return MfaEnrolmentResult(recovery_codes=codes)

    # ------------------------------------------------------------------ credentials
    async def change_password(
        self, db: AsyncSession, *, user_id: str, current_password: str, new_password: str
    ) -> None:
        """Change a password and revoke every refresh token the user holds.

        A password change is usually a response to suspected compromise, so leaving live
        refresh tokens in place would defeat the point of changing it.
        """
        users = UserRepository(db)
        user = await users.get_by_id(user_id)
        if user is None:
            raise NotFoundError("user not found")
        if not self._passwords.verify(password=current_password, password_hash=user.password_hash):
            raise DomainError("current password is incorrect")
        await users.set_password_hash(user_id, self._passwords.hash(new_password))
        revoked = await RefreshTokenRepository(db).revoke_all_for_user(
            user_id, reason=RevocationReason.PASSWORD_CHANGE
        )
        await self._audit.record_in_transaction(
            db,
            AuditEventType.PASSWORD_CHANGED,
            user_id=user_id,
            detail={"refresh_tokens_revoked": revoked},
        )
