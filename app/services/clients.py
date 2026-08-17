"""Client registration, authentication, redirect-URI and scope validation."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlparse

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.errors import (
    ConflictError,
    DomainError,
    InvalidClientError,
    NotFoundError,
)
from app.core.logging import get_logger
from app.models.client import ClientType, OAuthClient, TokenEndpointAuthMethod
from app.repositories.client_repository import ClientRepository
from app.repositories.scope_repository import ScopeRepository
from app.security.random_tokens import hash_token, new_opaque_token, tokens_equal

logger = get_logger(__name__)

# Loopback redirects are the RFC 8252 §7.3 native-app pattern; everything else must be https
# outside development, because a token or code delivered over http is a code in cleartext.
_ALLOWED_INSECURE_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]", "::1"})


@dataclass(frozen=True, slots=True)
class ClientCredentials:
    """Credentials as presented on the token/revocation endpoint."""

    client_id: str | None
    client_secret: str | None
    used_basic_auth: bool


@dataclass(frozen=True, slots=True)
class NewClientResult:
    client: OAuthClient
    # Returned exactly once, at registration. Only its hash is stored.
    client_secret: str | None


class ClientService:
    def __init__(self, *, settings: Settings) -> None:
        self._settings = settings

    # ------------------------------------------------------------------ authentication
    @staticmethod
    def extract_credentials(
        *,
        authorization_header: str | None,
        form_client_id: str | None,
        form_client_secret: str | None,
    ) -> ClientCredentials:
        """Pull client credentials from HTTP Basic or the form body.

        RFC 6749 §2.3.1 prefers Basic. If both are present we take Basic and ignore the body
        rather than trying to merge them: accepting whichever happens to validate would let a
        caller probe two credential sets in one request.
        """
        if authorization_header and authorization_header.lower().startswith("basic "):
            client_id, client_secret = _decode_basic_auth(authorization_header)
            return ClientCredentials(
                client_id=client_id, client_secret=client_secret, used_basic_auth=True
            )
        return ClientCredentials(
            client_id=form_client_id, client_secret=form_client_secret, used_basic_auth=False
        )

    async def authenticate(
        self, session: AsyncSession, credentials: ClientCredentials
    ) -> OAuthClient:
        """Authenticate a client for the token/revocation endpoints.

        Confidential clients must present the secret registered for their declared auth
        method. Public clients present no secret at all and lean entirely on PKCE — which is
        why PKCE is mandatory rather than optional here.
        """
        if not credentials.client_id:
            raise InvalidClientError(
                "client authentication required", used_basic_auth=credentials.used_basic_auth
            )
        client = await ClientRepository(session).get_by_client_id(credentials.client_id)
        if client is None or not client.is_active:
            # Same error and shape whether the client is unknown or disabled: distinguishing
            # them would confirm which client_ids exist.
            raise InvalidClientError(
                "client authentication failed", used_basic_auth=credentials.used_basic_auth
            )

        method = client.token_endpoint_auth_method
        if method == TokenEndpointAuthMethod.NONE:
            if credentials.client_secret:
                raise InvalidClientError(
                    "this client must not present a secret",
                    used_basic_auth=credentials.used_basic_auth,
                )
            return client

        if method == TokenEndpointAuthMethod.CLIENT_SECRET_BASIC and not credentials.used_basic_auth:
            raise InvalidClientError(
                "client must authenticate with HTTP Basic",
                used_basic_auth=credentials.used_basic_auth,
            )
        if method == TokenEndpointAuthMethod.CLIENT_SECRET_POST and credentials.used_basic_auth:
            raise InvalidClientError(
                "client must authenticate with client_secret_post",
                used_basic_auth=credentials.used_basic_auth,
            )
        if not credentials.client_secret or client.client_secret_hash is None:
            raise InvalidClientError(
                "client authentication failed", used_basic_auth=credentials.used_basic_auth
            )
        if not tokens_equal(hash_token(credentials.client_secret), client.client_secret_hash):
            raise InvalidClientError(
                "client authentication failed", used_basic_auth=credentials.used_basic_auth
            )
        return client

    # ------------------------------------------------------------------ validation
    @staticmethod
    def match_redirect_uri(client: OAuthClient, redirect_uri: str) -> str | None:
        """Exact-match a redirect URI against the client's allow-list.

        Byte-for-byte equality, deliberately. No prefix matching, no wildcard hosts, no
        normalization of trailing slashes, ports or query strings — every one of those
        relaxations has produced real open-redirect and code-exfiltration bugs, because
        ``https://app.example.com/cb`` matching ``https://app.example.com/cb/../../evil`` is a
        normalization question no two libraries answer identically.
        """
        for candidate in client.redirect_uri_values:
            if tokens_equal(candidate, redirect_uri):
                return candidate
        return None

    async def resolve_scopes(
        self, session: AsyncSession, *, client: OAuthClient, requested: Sequence[str]
    ) -> list[str]:
        """Intersect the request with what the client may have. Raises on an unknown scope.

        Unknown scopes are an error (``invalid_scope``) while known-but-not-granted scopes are
        silently dropped, per RFC 6749 §3.3's allowance for the server to issue a narrower
        scope than requested. The distinction gives an honest client a clear signal about a
        typo without letting it enumerate the catalogue.
        """
        requested_list = list(dict.fromkeys(requested))
        if not requested_list:
            return []
        unknown = await ScopeRepository(session).find_unknown(requested_list)
        if unknown:
            raise DomainError(f"unknown scope(s): {', '.join(sorted(unknown))}")
        allowed = client.allowed_scope_names
        return [scope for scope in requested_list if scope in allowed]

    def validate_redirect_uri_registration(self, uri: str) -> None:
        """Policy applied when a redirect URI is *registered*, not when it is used."""
        parsed = urlparse(uri)
        if not parsed.scheme:
            raise DomainError(f"redirect_uri must be absolute: {uri}")
        if parsed.fragment:
            # RFC 6749 §3.1.2: the fragment is where the response goes; it cannot be
            # pre-registered.
            raise DomainError(f"redirect_uri must not contain a fragment: {uri}")
        if parsed.scheme == "http":
            host = (parsed.hostname or "").lower()
            if host not in _ALLOWED_INSECURE_HOSTS:
                raise DomainError(f"redirect_uri must use https (loopback excepted): {uri}")
            if self._settings.is_deployed:
                raise DomainError(f"loopback redirect_uri is not permitted in this environment: {uri}")
        elif parsed.scheme != "https" and "." not in parsed.scheme:
            # A private-use scheme (RFC 8252 §7.1) must be reverse-DNS, e.g. com.example.app.
            raise DomainError(f"custom redirect_uri scheme must be reverse-DNS: {uri}")

    # ------------------------------------------------------------------ registration
    async def register_client(
        self,
        session: AsyncSession,
        *,
        client_name: str,
        client_type: ClientType,
        redirect_uris: Sequence[str],
        allowed_scopes: Sequence[str],
        client_id: str | None = None,
        require_consent: bool = True,
        allow_refresh_tokens: bool = True,
        token_endpoint_auth_method: TokenEndpointAuthMethod | None = None,
        client_uri: str | None = None,
        access_token_ttl_seconds: int | None = None,
        refresh_token_ttl_seconds: int | None = None,
    ) -> NewClientResult:
        """Register a client. There is no anonymous/dynamic registration by design (§31)."""
        if not redirect_uris:
            raise DomainError("a client must register at least one redirect_uri")
        for uri in redirect_uris:
            self.validate_redirect_uri_registration(uri)

        unknown = await ScopeRepository(session).find_unknown(list(allowed_scopes))
        if unknown:
            raise DomainError(f"unknown scope(s): {', '.join(sorted(unknown))}")

        if token_endpoint_auth_method is None:
            token_endpoint_auth_method = (
                TokenEndpointAuthMethod.CLIENT_SECRET_BASIC
                if client_type is ClientType.CONFIDENTIAL
                else TokenEndpointAuthMethod.NONE
            )
        if client_type is ClientType.PUBLIC and token_endpoint_auth_method is not (
            TokenEndpointAuthMethod.NONE
        ):
            raise DomainError("public clients cannot hold a secret; use auth method 'none'")
        if client_type is ClientType.CONFIDENTIAL and token_endpoint_auth_method is (
            TokenEndpointAuthMethod.NONE
        ):
            raise DomainError("confidential clients must authenticate at the token endpoint")

        secret: str | None = None
        secret_hash: str | None = None
        if client_type is ClientType.CONFIDENTIAL:
            secret = new_opaque_token(32)
            secret_hash = hash_token(secret)

        try:
            client = await ClientRepository(session).create(
                client_id=client_id or f"client_{new_opaque_token(12)}",
                client_secret_hash=secret_hash,
                client_type=str(client_type),
                token_endpoint_auth_method=str(token_endpoint_auth_method),
                client_name=client_name,
                redirect_uris=redirect_uris,
                allowed_scopes=allowed_scopes,
                require_consent=require_consent,
                allow_refresh_tokens=allow_refresh_tokens,
                client_uri=client_uri,
                access_token_ttl_seconds=access_token_ttl_seconds,
                refresh_token_ttl_seconds=refresh_token_ttl_seconds,
            )
        except IntegrityError as exc:
            raise ConflictError("a client with that client_id already exists") from exc
        return NewClientResult(client=client, client_secret=secret)

    async def rotate_client_secret(self, session: AsyncSession, *, client_id: str) -> str:
        repository = ClientRepository(session)
        client = await repository.get_by_client_id(client_id)
        if client is None:
            raise NotFoundError(f"no client with client_id {client_id}")
        if not client.is_confidential:
            raise DomainError("public clients have no secret to rotate")
        secret = new_opaque_token(32)
        await repository.set_secret_hash(client_id=client.id, client_secret_hash=hash_token(secret))
        return secret

    async def get_client_or_404(self, session: AsyncSession, client_id: str) -> OAuthClient:
        client = await ClientRepository(session).get_by_client_id(client_id)
        if client is None:
            raise NotFoundError(f"no client with client_id {client_id}")
        return client


def _decode_basic_auth(header: str) -> tuple[str | None, str | None]:
    """Decode ``Basic base64(client_id:client_secret)``.

    RFC 6749 §2.3.1 requires form-urlencoding the two halves before base64, which matters for
    secrets containing ``:`` or non-ASCII characters.
    """
    from urllib.parse import unquote_plus

    try:
        decoded = base64.b64decode(header.split(" ", 1)[1], validate=True).decode("utf-8")
    except (IndexError, binascii.Error, UnicodeDecodeError):
        return None, None
    if ":" not in decoded:
        return None, None
    raw_id, raw_secret = decoded.split(":", 1)
    return unquote_plus(raw_id), unquote_plus(raw_secret)
