"""Signing-key *metadata* (§11).

Private key material never lands in this table. Postgres holds only what is needed to build
the JWKS/discovery responses and to decide which key signs next, so an ordinary database
read (or a database backup) cannot yield the ability to mint tokens.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import DateTime, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Text

from app.models.base import Base, ulid_pk


class KeyStatus(StrEnum):
    CURRENT = "current"  # signs new tokens; published in JWKS
    RETIRING = "retiring"  # no longer signs; still published so in-flight tokens verify
    RETIRED = "retired"  # absent from JWKS; private material may be destroyed


class SigningKey(Base):
    __tablename__ = "signing_keys"

    id: Mapped[str] = ulid_pk()
    kid: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False, default="RS256")
    public_jwk: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    public_pem: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    # Where the private half lives: a Secrets Manager name, or a filename under the local
    # key directory in development. A pointer, never the material itself.
    private_key_ref: Mapped[str] = mapped_column(Text, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retiring_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # When a `retiring` key's grace period ends and it may leave JWKS.
    retire_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("ix_signing_keys_status", "status"),)
