"""Admin API schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.models.client import ClientType, TokenEndpointAuthMethod


class CreateClientRequest(BaseModel):
    client_name: str = Field(min_length=1, max_length=255)
    client_type: ClientType = ClientType.CONFIDENTIAL
    redirect_uris: list[str] = Field(min_length=1)
    allowed_scopes: list[str] = Field(default_factory=list)
    client_id: str | None = Field(default=None, max_length=64)
    token_endpoint_auth_method: TokenEndpointAuthMethod | None = None
    require_consent: bool = True
    allow_refresh_tokens: bool = True
    client_uri: str | None = None
    access_token_ttl_seconds: int | None = Field(default=None, ge=60, le=3600)
    refresh_token_ttl_seconds: int | None = Field(default=None, ge=300)


class ClientResponse(BaseModel):
    client_id: str
    client_name: str
    client_type: str
    token_endpoint_auth_method: str
    redirect_uris: list[str]
    allowed_scopes: list[str]
    is_active: bool
    require_consent: bool
    allow_refresh_tokens: bool
    created_at: datetime


class CreateClientResponse(ClientResponse):
    # Present exactly once, in the registration response. Only its SHA-256 hash is persisted, so
    # a lost secret must be rotated rather than recovered.
    client_secret: str | None = None


class RotateSecretResponse(BaseModel):
    client_id: str
    client_secret: str


class ScopeResponse(BaseModel):
    name: str
    description: str
    is_oidc: bool
    is_default: bool


class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=1024)
    username: str | None = Field(default=None, max_length=64)
    full_name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    email_verified: bool = False
    is_admin: bool = False


class UserResponse(BaseModel):
    id: str
    email: str
    username: str | None
    full_name: str | None
    email_verified: bool
    is_active: bool
    is_admin: bool
    mfa_enrolled: bool
    created_at: datetime


class SigningKeyResponse(BaseModel):
    kid: str
    algorithm: str
    status: str
