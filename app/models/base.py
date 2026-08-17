"""Declarative base and shared column conventions."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, MetaData, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.security.random_tokens import new_identifier

# Explicit naming so Alembic autogenerate produces stable, reviewable constraint names
# instead of database-assigned ones that differ between environments.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

ULID_LENGTH = 26


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def ulid_pk() -> Mapped[str]:
    """ULID primary key.

    Chosen over a bigserial because IDs appear in tokens and audit records, and a
    monotonically increasing integer leaks how many users/clients exist. Chosen over UUIDv4
    because ULIDs sort by creation time, which keeps index inserts append-friendly.
    """
    return mapped_column(String(ULID_LENGTH), primary_key=True, default=new_identifier)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
