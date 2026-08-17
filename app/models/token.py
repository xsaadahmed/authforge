"""Refresh-token family state — the rotation and reuse-detection state machine (§10)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Text

from app.models.base import ULID_LENGTH, Base, ulid_pk


class RevocationReason(StrEnum):
    CLIENT_REQUEST = "client_request"
    REUSE_DETECTED = "reuse_detected"
    USER_LOGOUT = "user_logout"
    ADMIN_ACTION = "admin_action"
    PASSWORD_CHANGE = "password_change"
    SUPERSEDED = "superseded"


class RefreshToken(Base):
    """One generation of one refresh-token family.

    Rotation appends a new row in the same ``family_id``; the presented row is stamped
    ``used_at``. Reuse of a stamped row means the raw token existed in two places, which we
    treat as theft and answer by revoking the whole family.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[str] = ulid_pk()
    # SHA-256 hex of the raw token. The raw value is returned to the client once and never
    # stored, so a database disclosure does not yield usable refresh tokens.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    family_id: Mapped[str] = mapped_column(String(ULID_LENGTH), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    previous_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    user_id: Mapped[str] = mapped_column(
        String(ULID_LENGTH), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    client_id: Mapped[str] = mapped_column(
        String(ULID_LENGTH), ForeignKey("oauth_clients.id", ondelete="CASCADE"), nullable=False
    )
    scopes: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    # Carried forward across rotations so a refreshed ID token reports when the user actually
    # authenticated, not when the token was minted (OIDC Core `auth_time`).
    auth_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Absolute expiry inherited from the family's first token (see docs/adr/0003).
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)

    __table_args__ = (
        Index("ix_refresh_tokens_family_id", "family_id"),
        Index("ix_refresh_tokens_user_id_client_id", "user_id", "client_id"),
        # The hot path is "find this hash if it is still redeemable"; a partial index keeps
        # the working set proportional to *active* tokens rather than all history.
        Index(
            "ix_refresh_tokens_active",
            "token_hash",
            postgresql_where=text("used_at IS NULL AND revoked = false"),
        ),
        Index("ix_refresh_tokens_expires_at", "expires_at"),
    )

    @property
    def is_spent(self) -> bool:
        return self.used_at is not None or self.revoked
