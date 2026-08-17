"""Minimal authenticated admin API.

Client registration is an authenticated admin operation, never anonymous dynamic registration
(§31): open registration would let anyone create a client with a chosen name and redirect URI,
which is a phishing kit rather than a feature. The CLI (``authforge-admin``) is the primary
interface; this API exists so registration can be scripted from CI without shell access to a
running task, and it is intentionally the smallest surface that makes that possible.
"""

from __future__ import annotations

from fastapi import APIRouter, status

from app.api.deps import AdminGuard, ContainerDep, DbDep
from app.core.errors import DomainError
from app.models.audit import AuditEventType
from app.models.client import OAuthClient
from app.models.token import RevocationReason
from app.repositories.client_repository import ClientRepository
from app.repositories.scope_repository import ScopeRepository
from app.repositories.user_repository import UserRepository
from app.schemas.admin import (
    ClientResponse,
    CreateClientRequest,
    CreateClientResponse,
    CreateUserRequest,
    RotateSecretResponse,
    ScopeResponse,
    SigningKeyResponse,
    UserResponse,
)
from app.security.passwords import PasswordHasherService

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[AdminGuard])


@router.get("/clients", response_model=list[ClientResponse], summary="List registered clients")
async def list_clients(db: DbDep) -> list[ClientResponse]:
    return [_client_response(client) for client in await ClientRepository(db).list_clients()]


@router.post(
    "/clients",
    response_model=CreateClientResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a client",
)
async def create_client(
    payload: CreateClientRequest, container: ContainerDep, db: DbDep
) -> CreateClientResponse:
    result = await container.clients.register_client(
        db,
        client_name=payload.client_name,
        client_type=payload.client_type,
        redirect_uris=payload.redirect_uris,
        allowed_scopes=payload.allowed_scopes,
        client_id=payload.client_id,
        require_consent=payload.require_consent,
        allow_refresh_tokens=payload.allow_refresh_tokens,
        token_endpoint_auth_method=payload.token_endpoint_auth_method,
        client_uri=payload.client_uri,
        access_token_ttl_seconds=payload.access_token_ttl_seconds,
        refresh_token_ttl_seconds=payload.refresh_token_ttl_seconds,
    )
    await container.audit.record_in_transaction(
        db,
        AuditEventType.CLIENT_CREATED,
        client_id=result.client.client_id,
        detail={"client_name": result.client.client_name, "via": "admin_api"},
    )
    base = _client_response(result.client)
    return CreateClientResponse(**base.model_dump(), client_secret=result.client_secret)


@router.post(
    "/clients/{client_id}/rotate-secret",
    response_model=RotateSecretResponse,
    summary="Rotate a confidential client's secret",
)
async def rotate_secret(client_id: str, container: ContainerDep, db: DbDep) -> RotateSecretResponse:
    secret = await container.clients.rotate_client_secret(db, client_id=client_id)
    await container.audit.record_in_transaction(
        db, AuditEventType.CLIENT_UPDATED, client_id=client_id, detail={"action": "rotate_secret"}
    )
    return RotateSecretResponse(client_id=client_id, client_secret=secret)


@router.post(
    "/clients/{client_id}/disable",
    response_model=ClientResponse,
    summary="Disable a client without deleting its history",
)
async def disable_client(client_id: str, container: ContainerDep, db: DbDep) -> ClientResponse:
    repository = ClientRepository(db)
    client = await container.clients.get_client_or_404(db, client_id)
    await repository.set_active(client_id=client.id, is_active=False)
    # Disabling without revoking would leave live refresh tokens able to mint access tokens for a
    # client the operator just switched off.
    await container.tokens.revoke_all_for_client(
        db, client=client, reason=RevocationReason.ADMIN_ACTION
    )
    await container.audit.record_in_transaction(
        db, AuditEventType.CLIENT_UPDATED, client_id=client_id, detail={"action": "disable"}
    )
    client.is_active = False
    return _client_response(client)


@router.get("/scopes", response_model=list[ScopeResponse], summary="List the scope catalogue")
async def list_scopes(db: DbDep) -> list[ScopeResponse]:
    return [
        ScopeResponse(
            name=scope.name,
            description=scope.description,
            is_oidc=scope.is_oidc,
            is_default=scope.is_default,
        )
        for scope in await ScopeRepository(db).list_all()
    ]


@router.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a user",
)
async def create_user(
    payload: CreateUserRequest, container: ContainerDep, db: DbDep
) -> UserResponse:
    users = UserRepository(db)
    if await users.get_by_email(payload.email) is not None:
        raise DomainError("a user with that email already exists", status_code=409)
    hasher = PasswordHasherService(container.settings)
    user = await users.create(
        email=payload.email,
        password_hash=hasher.hash(payload.password),
        username=payload.username,
        full_name=payload.full_name,
        given_name=payload.given_name,
        family_name=payload.family_name,
        email_verified=payload.email_verified,
        is_admin=payload.is_admin,
    )
    await container.audit.record_in_transaction(
        db, AuditEventType.USER_CREATED, user_id=user.id, detail={"via": "admin_api"}
    )
    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        email_verified=user.email_verified,
        is_active=user.is_active,
        is_admin=user.is_admin,
        mfa_enrolled=user.mfa_enrolled,
        created_at=user.created_at,
    )


@router.get("/keys", response_model=list[SigningKeyResponse], summary="List signing keys")
async def list_keys(container: ContainerDep, db: DbDep) -> list[SigningKeyResponse]:
    return [
        SigningKeyResponse(kid=key.kid, algorithm=key.algorithm, status=key.status)
        for key in await container.keys.list_keys(db)
    ]


@router.post(
    "/keys/rotate", response_model=SigningKeyResponse, summary="Rotate the signing key now"
)
async def rotate_key(container: ContainerDep, db: DbDep) -> SigningKeyResponse:
    kid = await container.keys.rotate(reason="admin_api")
    await container.audit.record(db, AuditEventType.KEY_ROTATED, detail={"kid": kid})
    return SigningKeyResponse(kid=kid, algorithm="RS256", status="current")


def _client_response(client: OAuthClient) -> ClientResponse:
    return ClientResponse(
        client_id=client.client_id,
        client_name=client.client_name,
        client_type=client.client_type,
        token_endpoint_auth_method=client.token_endpoint_auth_method,
        redirect_uris=client.redirect_uri_values,
        allowed_scopes=sorted(client.allowed_scope_names),
        is_active=client.is_active,
        require_consent=client.require_consent,
        allow_refresh_tokens=client.allow_refresh_tokens,
        created_at=client.created_at,
    )
