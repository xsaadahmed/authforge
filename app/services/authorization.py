"""The ``/authorize`` endpoint's decision logic (§8A).

The ordering of validations in ``validate_request`` is the security-relevant part, so it is
stated up front:

1. ``client_id`` must resolve to an active client.
2. ``redirect_uri`` must exact-match that client's allow-list.

Only after both hold may an error be reported *by redirecting to the client*. Anything that
fails before that point is rendered as an error page, because redirecting to an unvalidated URI
is precisely the open-redirect primitive an attacker wants. This is also why ``state`` is echoed
but never trusted, and why PKCE parameters are validated before a code can exist.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlencode

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.errors import (
    AuthorizationRequestError,
    DomainError,
    OAuthError,
    OAuthErrorCode,
)
from app.models.audit import AuditEventType
from app.models.client import OAuthClient
from app.repositories.client_repository import ClientRepository
from app.security import pkce as pkce_lib
from app.services import claims as claims_lib
from app.services.audit import AuditService
from app.services.clients import ClientService
from app.stores.auth_code_store import AuthCodeStore, AuthorizationCodePayload

SUPPORTED_RESPONSE_TYPES = ("code",)
# `prompt` values from OIDC Core §3.1.2.1 that this IdP honours. `select_account` is omitted
# because a single-session IdP has nothing to select between.
SUPPORTED_PROMPTS = frozenset({"none", "login", "consent"})


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """A validated ``/authorize`` request, ready to be acted on."""

    client: OAuthClient
    redirect_uri: str
    scopes: list[str]
    state: str | None
    nonce: str | None
    code_challenge: str
    code_challenge_method: str
    prompts: frozenset[str]
    max_age: int | None
    raw_query: str

    @property
    def requires_openid(self) -> bool:
        return claims_lib.SCOPE_OPENID in self.scopes


class AuthorizationService:
    def __init__(
        self,
        *,
        settings: Settings,
        clients: ClientService,
        auth_codes: AuthCodeStore,
        audit: AuditService,
    ) -> None:
        self._settings = settings
        self._clients = clients
        self._auth_codes = auth_codes
        self._audit = audit

    async def validate_request(
        self,
        db: AsyncSession,
        *,
        client_id: str | None,
        redirect_uri: str | None,
        response_type: str | None,
        scope: str | None,
        state: str | None,
        nonce: str | None,
        code_challenge: str | None,
        code_challenge_method: str | None,
        prompt: str | None,
        max_age: str | None,
        raw_query: str,
    ) -> AuthorizationRequest:
        # ---- Stage 1: identify the client. Errors here cannot be redirected anywhere.
        if not client_id:
            raise self._unredirectable(OAuthErrorCode.INVALID_REQUEST, "client_id is required")
        client = await ClientRepository(db).get_by_client_id(client_id)
        if client is None or not client.is_active:
            await self._audit_failure(client_id=client_id, reason="unknown_or_inactive_client")
            raise self._unredirectable(
                OAuthErrorCode.INVALID_REQUEST, "unknown or inactive client_id"
            )

        # ---- Stage 2: prove the redirect target. Still not redirectable.
        if not redirect_uri:
            # No defaulting to "the only registered URI". Requiring it explicitly means the
            # value bound into the code is always the one the client actually asked for.
            await self._audit_failure(client_id=client_id, reason="missing_redirect_uri")
            raise self._unredirectable(OAuthErrorCode.INVALID_REQUEST, "redirect_uri is required")
        matched = self._clients.match_redirect_uri(client, redirect_uri)
        if matched is None:
            await self._audit_failure(client_id=client_id, reason="redirect_uri_not_registered")
            raise self._unredirectable(
                OAuthErrorCode.INVALID_REQUEST,
                "redirect_uri does not exactly match a registered URI",
            )

        # ---- Stage 3: from here, failures may be reported to the client by redirect.
        if response_type not in SUPPORTED_RESPONSE_TYPES:
            # Implicit and hybrid flows are deliberately absent (§31): `token` and `id_token`
            # response types deliver credentials through the URL fragment, which the OAuth
            # Security BCP advises against.
            await self._audit_failure(client_id=client_id, reason="unsupported_response_type")
            raise OAuthError(
                OAuthErrorCode.UNSUPPORTED_RESPONSE_TYPE,
                "only response_type=code is supported",
            )

        if not code_challenge:
            await self._audit_failure(client_id=client_id, reason="missing_pkce")
            raise OAuthError(
                OAuthErrorCode.INVALID_REQUEST, "code_challenge is required (PKCE is mandatory)"
            )
        method = code_challenge_method or "plain"
        try:
            pkce_lib.validate_code_challenge(code_challenge, method)
        except pkce_lib.PKCEError as exc:
            await self._audit_failure(client_id=client_id, reason="invalid_pkce_parameters")
            raise OAuthError(OAuthErrorCode.INVALID_REQUEST, str(exc)) from exc

        requested_scopes = claims_lib.parse_scope_string(scope)
        try:
            granted = await self._clients.resolve_scopes(
                db, client=client, requested=requested_scopes
            )
        except DomainError as exc:
            await self._audit_failure(client_id=client_id, reason="unknown_scope")
            raise OAuthError(OAuthErrorCode.INVALID_SCOPE, exc.description) from exc
        if requested_scopes and not granted:
            await self._audit_failure(client_id=client_id, reason="no_permitted_scopes")
            raise OAuthError(
                OAuthErrorCode.INVALID_SCOPE, "this client may not request any of those scopes"
            )

        prompts = frozenset(claims_lib.parse_scope_string(prompt))
        unsupported = prompts - SUPPORTED_PROMPTS
        if unsupported:
            raise OAuthError(
                OAuthErrorCode.INVALID_REQUEST,
                f"unsupported prompt value(s): {', '.join(sorted(unsupported))}",
            )
        if "none" in prompts and len(prompts) > 1:
            # OIDC Core §3.1.2.1: `none` is mutually exclusive with every other value.
            raise OAuthError(
                OAuthErrorCode.INVALID_REQUEST, "prompt=none cannot be combined with other values"
            )

        parsed_max_age: int | None = None
        if max_age is not None:
            try:
                parsed_max_age = int(max_age)
                if parsed_max_age < 0:
                    raise ValueError
            except ValueError as exc:
                raise OAuthError(
                    OAuthErrorCode.INVALID_REQUEST, "max_age must be a non-negative integer"
                ) from exc

        return AuthorizationRequest(
            client=client,
            redirect_uri=matched,
            scopes=granted,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=method,
            prompts=prompts,
            max_age=parsed_max_age,
            raw_query=raw_query,
        )

    def requires_reauthentication(self, request: AuthorizationRequest, *, auth_time: int) -> bool:
        """Whether an existing session is too old for this request.

        Honours both ``prompt=login`` (client insists on a fresh authentication) and ``max_age``
        (client accepts a session only if the user authenticated within N seconds), per OIDC
        Core §3.1.2.1.
        """
        if "login" in request.prompts:
            return True
        if request.max_age is not None:
            return (int(time.time()) - auth_time) > request.max_age
        return False

    async def issue_code(
        self,
        session: AsyncSession,
        request: AuthorizationRequest,
        *,
        user_id: str,
        auth_time: int,
        session_id: str | None,
        granted_scopes: list[str],
    ) -> str:
        """Mint a single-use authorization code bound to this exact request."""
        code = await self._auth_codes.issue(
            AuthorizationCodePayload(
                client_id=request.client.client_id,
                user_id=user_id,
                redirect_uri=request.redirect_uri,
                scopes=granted_scopes,
                code_challenge=request.code_challenge,
                code_challenge_method=request.code_challenge_method,
                nonce=request.nonce,
                auth_time=auth_time,
                session_id=session_id,
                issued_at=int(time.time()),
            )
        )
        await self._audit.record(
            session,
            AuditEventType.AUTHZ_CODE_ISSUED,
            user_id=user_id,
            client_id=request.client.client_id,
            detail={"scopes": granted_scopes},
        )
        return code

    @staticmethod
    def build_success_redirect(request: AuthorizationRequest, *, code: str) -> str:
        params = {"code": code}
        if request.state is not None:
            # Echoed verbatim and never interpreted: `state` is the client's CSRF token, and its
            # meaning is the client's business.
            params["state"] = request.state
        return _append_query(request.redirect_uri, params)

    @staticmethod
    def build_error_redirect(
        *, redirect_uri: str, error: OAuthErrorCode, description: str | None, state: str | None
    ) -> str:
        params: dict[str, str] = {"error": str(error)}
        if description:
            params["error_description"] = description
        if state is not None:
            params["state"] = state
        return _append_query(redirect_uri, params)

    async def _audit_failure(self, *, client_id: str | None, reason: str) -> None:
        """Recorded durably: every caller of this raises, so the request transaction is
        discarded."""
        await self._audit.record_durable(
            AuditEventType.AUTHZ_FAILURE,
            client_id=client_id,
            detail={"stage": "authorize", "reason": reason},
        )

    @staticmethod
    def _unredirectable(error: OAuthErrorCode, description: str) -> AuthorizationRequestError:
        return AuthorizationRequestError(error, description)


def _append_query(uri: str, params: dict[str, str]) -> str:
    """Append query parameters, preserving any the registered URI already carries.

    RFC 6749 §3.1.2 permits a registered redirect URI to include a query component, and the
    response parameters must be added to it rather than replacing it.
    """
    separator = "&" if "?" in uri else "?"
    return f"{uri}{separator}{urlencode(params)}"
