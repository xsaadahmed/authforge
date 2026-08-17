"""Registered OAuth clients, their redirect-URI allow-list, and scope grants."""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import ULID_LENGTH, Base, TimestampMixin, ulid_pk


class ClientType(StrEnum):
    CONFIDENTIAL = "confidential"
    PUBLIC = "public"


class TokenEndpointAuthMethod(StrEnum):
    CLIENT_SECRET_BASIC = "client_secret_basic"
    CLIENT_SECRET_POST = "client_secret_post"
    NONE = "none"


class OAuthClient(Base, TimestampMixin):
    __tablename__ = "oauth_clients"

    id: Mapped[str] = ulid_pk()
    client_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # SHA-256 of the secret. Client secrets, like refresh tokens, are high-entropy values we
    # generate ourselves, so a slow KDF would only add latency to every token request.
    # NULL for public clients, which authenticate solely by PKCE.
    client_secret_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    client_type: Mapped[str] = mapped_column(String(16), nullable=False)
    token_endpoint_auth_method: Mapped[str] = mapped_column(String(32), nullable=False)

    client_name: Mapped[str] = mapped_column(String(255), nullable=False)
    client_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    logo_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    tos_uri: Mapped[str | None] = mapped_column(Text, nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    require_consent: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Per-client overrides; NULL means "use the deployment default".
    access_token_ttl_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    refresh_token_ttl_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    allow_refresh_tokens: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    redirect_uris: Mapped[list[ClientRedirectUri]] = relationship(
        back_populates="client",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="ClientRedirectUri.uri",
    )
    allowed_scopes: Mapped[list[ClientScope]] = relationship(
        back_populates="client", cascade="all, delete-orphan", lazy="selectin"
    )

    @property
    def is_confidential(self) -> bool:
        return self.client_type == ClientType.CONFIDENTIAL

    @property
    def redirect_uri_values(self) -> list[str]:
        return [entry.uri for entry in self.redirect_uris]

    @property
    def allowed_scope_names(self) -> set[str]:
        return {entry.scope_name for entry in self.allowed_scopes}


class ClientRedirectUri(Base):
    """One registered redirect URI.

    A child table rather than an array column so the database itself enforces uniqueness
    per client and so the exact-match lookup is a plain indexed equality — there is no code
    path that could accidentally introduce prefix or wildcard matching.
    """

    __tablename__ = "client_redirect_uris"

    id: Mapped[str] = ulid_pk()
    client_id: Mapped[str] = mapped_column(
        String(ULID_LENGTH),
        ForeignKey("oauth_clients.id", ondelete="CASCADE"),
        nullable=False,
    )
    uri: Mapped[str] = mapped_column(Text, nullable=False)

    client: Mapped[OAuthClient] = relationship(back_populates="redirect_uris")

    __table_args__ = (
        UniqueConstraint("client_id", "uri", name="uq_client_redirect_uris_client_id_uri"),
    )


class Scope(Base, TimestampMixin):
    __tablename__ = "scopes"

    id: Mapped[str] = ulid_pk()
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    # OIDC-defined scopes (openid/profile/email) map to ID-token and UserInfo claims;
    # everything else is treated as an opaque API permission carried in the access token.
    is_oidc: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Included in a consent prompt's pre-ticked set; still requires an explicit grant.
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class ClientScope(Base):
    """Which scopes a client is permitted to request."""

    __tablename__ = "client_scopes"

    client_id: Mapped[str] = mapped_column(
        String(ULID_LENGTH),
        ForeignKey("oauth_clients.id", ondelete="CASCADE"),
        primary_key=True,
    )
    scope_name: Mapped[str] = mapped_column(
        String(64), ForeignKey("scopes.name", ondelete="CASCADE"), primary_key=True
    )

    client: Mapped[OAuthClient] = relationship(back_populates="allowed_scopes")

    __table_args__ = (Index("ix_client_scopes_scope_name", "scope_name"),)
