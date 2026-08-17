"""Durable security audit trail (§20)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import Boolean, DateTime, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Text

from app.models.base import Base, ulid_pk


class AuditEventType(StrEnum):
    """The security-relevant event vocabulary.

    A closed enum rather than free-form strings: alarms and dashboards are built on these
    names, so a typo must be a code error rather than a silently missing metric.
    """

    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    ACCOUNT_LOCKED = "account_locked"
    MFA_CHALLENGE_ISSUED = "mfa_challenge_issued"
    MFA_SUCCESS = "mfa_success"
    MFA_FAILURE = "mfa_failure"
    MFA_ENROLLED = "mfa_enrolled"
    MFA_RECOVERY_CODE_USED = "mfa_recovery_code_used"
    CONSENT_GRANTED = "consent_granted"
    CONSENT_DENIED = "consent_denied"
    CONSENT_REVOKED = "consent_revoked"
    AUTHZ_CODE_ISSUED = "authz_code_issued"
    AUTHZ_FAILURE = "authz_failure"
    TOKEN_ISSUED = "token_issued"
    TOKEN_REFRESHED = "token_refreshed"
    TOKEN_REVOKED = "token_revoked"
    REFRESH_REUSE_DETECTED = "refresh_reuse_detected"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    KEY_ROTATED = "key_rotated"
    KEY_RETIRED = "key_retired"
    CLIENT_CREATED = "client_created"
    CLIENT_UPDATED = "client_updated"
    CLIENT_DELETED = "client_deleted"
    USER_CREATED = "user_created"
    PASSWORD_CHANGED = "password_changed"
    ADMIN_ACTION = "admin_action"


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = ulid_pk()
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Deliberately NOT foreign keys: an audit record must survive deletion of the user or
    # client it refers to, and must be recordable for a *failed* login where the subject
    # may not exist at all.
    user_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    subject_hint: Mapped[str | None] = mapped_column(String(320), nullable=True)

    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Structured, already-redacted context: never a raw token, only identifiers such as
    # `jti`, `kid`, `family_id` or a truncated hash reference.
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_audit_log_event_type_created_at", "event_type", "created_at"),
        Index("ix_audit_log_user_id_created_at", "user_id", "created_at"),
        Index("ix_audit_log_client_id_created_at", "client_id", "created_at"),
    )
