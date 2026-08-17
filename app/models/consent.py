"""Recorded user consent per (user, client)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Text

from app.models.base import Base, TimestampMixin, ULID_LENGTH, ulid_pk


class Consent(Base, TimestampMixin):
    """The set of scopes a user has granted to a client.

    One row per (user, client) holding the cumulative granted set, rather than one row per
    scope: the question asked on every authorization request is "is the requested set a
    subset of what was granted?", which is a single read of a single row.
    """

    __tablename__ = "consents"

    id: Mapped[str] = ulid_pk()
    user_id: Mapped[str] = mapped_column(
        String(ULID_LENGTH), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    client_id: Mapped[str] = mapped_column(
        String(ULID_LENGTH), ForeignKey("oauth_clients.id", ondelete="CASCADE"), nullable=False
    )
    granted_scopes: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    # NULL means the grant stands until revoked. A finite value forces re-prompting, which
    # some deployments want for high-privilege scopes.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("user_id", "client_id", name="uq_consents_user_id_client_id"),
        Index("ix_consents_user_id", "user_id"),
    )
