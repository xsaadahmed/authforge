"""End-user identity, password credential, and MFA enrolment state."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, ULID_LENGTH, ulid_pk


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = ulid_pk()
    # Stored already lower-cased and NFKC-normalized by UserRepository so that the unique
    # constraint actually prevents "Alice@x.com" and "alice@x.com" being two accounts.
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)

    email_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # OIDC standard `profile` scope claims. Kept minimal on purpose (§31).
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    given_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    family_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    picture_url: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Lockout counters are authoritative in Postgres (durable), while the sliding-window
    # rate limiter lives in Redis (ephemeral). Redis loss must not erase a lockout.
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    mfa_credential: Mapped[MfaCredential | None] = relationship(
        back_populates="user", cascade="all, delete-orphan", uselist=False, lazy="selectin"
    )

    __table_args__ = (Index("ix_users_email_active", "email", "is_active"),)

    @property
    def mfa_enrolled(self) -> bool:
        credential = self.mfa_credential
        return credential is not None and credential.confirmed_at is not None


class MfaCredential(Base, TimestampMixin):
    """A user's TOTP factor.

    One row per user (1:1). Supporting multiple factors later means relaxing this unique
    constraint, which is why the table is separate from `users` rather than a set of columns.
    """

    __tablename__ = "mfa_credentials"

    id: Mapped[str] = ulid_pk()
    user_id: Mapped[str] = mapped_column(
        String(ULID_LENGTH), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    factor_type: Mapped[str] = mapped_column(String(16), nullable=False, default="totp")
    # AES-256-GCM envelope from app.security.encryption — never the raw base32 secret.
    secret_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    # NULL until the user proves possession with a live code. An unconfirmed row must never
    # be treated as an enrolled factor, otherwise a half-finished enrolment locks the user out.
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="mfa_credential")


class RecoveryCode(Base):
    """Hashed, single-use MFA recovery codes."""

    __tablename__ = "recovery_codes"

    id: Mapped[str] = ulid_pk()
    user_id: Mapped[str] = mapped_column(
        String(ULID_LENGTH), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("user_id", "code_hash", name="uq_recovery_codes_user_id_code_hash"),
        # Partial index: the only lookup that matters is "this user's still-usable codes".
        Index(
            "ix_recovery_codes_user_id_unused",
            "user_id",
            postgresql_where=text("used_at IS NULL"),
        ),
    )
