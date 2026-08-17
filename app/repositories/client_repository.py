"""OAuth client persistence, including the redirect-URI allow-list."""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.client import ClientRedirectUri, ClientScope, OAuthClient


class ClientRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        client_id: str,
        client_secret_hash: str | None,
        client_type: str,
        token_endpoint_auth_method: str,
        client_name: str,
        redirect_uris: Sequence[str],
        allowed_scopes: Sequence[str],
        require_consent: bool = True,
        allow_refresh_tokens: bool = True,
        client_uri: str | None = None,
        logo_uri: str | None = None,
        access_token_ttl_seconds: int | None = None,
        refresh_token_ttl_seconds: int | None = None,
    ) -> OAuthClient:
        client = OAuthClient(
            client_id=client_id,
            client_secret_hash=client_secret_hash,
            client_type=client_type,
            token_endpoint_auth_method=token_endpoint_auth_method,
            client_name=client_name,
            require_consent=require_consent,
            allow_refresh_tokens=allow_refresh_tokens,
            client_uri=client_uri,
            logo_uri=logo_uri,
            access_token_ttl_seconds=access_token_ttl_seconds,
            refresh_token_ttl_seconds=refresh_token_ttl_seconds,
        )
        client.redirect_uris = [ClientRedirectUri(uri=uri) for uri in dict.fromkeys(redirect_uris)]
        client.allowed_scopes = [
            ClientScope(scope_name=name) for name in dict.fromkeys(allowed_scopes)
        ]
        self._session.add(client)
        await self._session.flush()
        return client

    async def get_by_client_id(self, client_id: str) -> OAuthClient | None:
        result = await self._session.execute(
            select(OAuthClient)
            .where(OAuthClient.client_id == client_id)
            .options(
                selectinload(OAuthClient.redirect_uris),
                selectinload(OAuthClient.allowed_scopes),
            )
        )
        return result.scalars().one_or_none()

    async def get_by_id(self, internal_id: str) -> OAuthClient | None:
        result = await self._session.execute(
            select(OAuthClient)
            .where(OAuthClient.id == internal_id)
            .options(
                selectinload(OAuthClient.redirect_uris),
                selectinload(OAuthClient.allowed_scopes),
            )
        )
        return result.scalars().one_or_none()

    async def list_clients(self, *, limit: int = 100, offset: int = 0) -> list[OAuthClient]:
        result = await self._session.execute(
            select(OAuthClient)
            .order_by(OAuthClient.created_at.desc())
            .limit(limit)
            .offset(offset)
            .options(
                selectinload(OAuthClient.redirect_uris),
                selectinload(OAuthClient.allowed_scopes),
            )
        )
        return list(result.scalars())

    async def replace_redirect_uris(self, *, client_id: str, redirect_uris: Sequence[str]) -> None:
        await self._session.execute(
            delete(ClientRedirectUri).where(ClientRedirectUri.client_id == client_id)
        )
        for uri in dict.fromkeys(redirect_uris):
            self._session.add(ClientRedirectUri(client_id=client_id, uri=uri))
        await self._session.flush()

    async def replace_allowed_scopes(self, *, client_id: str, scopes: Sequence[str]) -> None:
        await self._session.execute(delete(ClientScope).where(ClientScope.client_id == client_id))
        for name in dict.fromkeys(scopes):
            self._session.add(ClientScope(client_id=client_id, scope_name=name))
        await self._session.flush()

    async def set_secret_hash(self, *, client_id: str, client_secret_hash: str) -> None:
        await self._session.execute(
            update(OAuthClient)
            .where(OAuthClient.id == client_id)
            .values(client_secret_hash=client_secret_hash)
        )

    async def set_active(self, *, client_id: str, is_active: bool) -> None:
        await self._session.execute(
            update(OAuthClient).where(OAuthClient.id == client_id).values(is_active=is_active)
        )

    async def delete(self, *, client_id: str) -> None:
        await self._session.execute(delete(OAuthClient).where(OAuthClient.id == client_id))
