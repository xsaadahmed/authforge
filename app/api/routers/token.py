"""The ``/token`` endpoint (§8A step 7, §8B).

Handles ``authorization_code`` and ``refresh_token``. The client is authenticated first, so
every subsequent error is attributable to a known client in the audit trail, and a per-client
rate limit is applied before any database or crypto work — an unauthenticated flood should cost
a Redis increment, not an Argon2 hash or a signature.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Form, Header, Response

from app.api.deps import ContainerDep, DbDep
from app.core.errors import (
    InvalidRequestError,
    RateLimitedError,
    UnsupportedGrantTypeError,
)
from app.services.tokens import TokenSet

router = APIRouter(tags=["oauth2"])

GRANT_AUTHORIZATION_CODE = "authorization_code"
GRANT_REFRESH_TOKEN = "refresh_token"


@router.post("/token", summary="OAuth 2.0 token endpoint")
async def token(
    container: ContainerDep,
    db: DbDep,
    response: Response,
    authorization: Annotated[str | None, Header()] = None,
    grant_type: str = Form(...),
    code: str | None = Form(default=None),
    redirect_uri: str | None = Form(default=None),
    code_verifier: str | None = Form(default=None),
    refresh_token: str | None = Form(default=None),
    scope: str | None = Form(default=None),
    client_id: str | None = Form(default=None),
    client_secret: str | None = Form(default=None),
) -> dict[str, Any]:
    # RFC 6749 §5.1: token responses must never be cached, by anyone, ever.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    credentials = container.clients.extract_credentials(
        authorization_header=authorization,
        form_client_id=client_id,
        form_client_secret=client_secret,
    )
    client = await container.clients.authenticate(db, credentials)

    verdict = await container.rate_limits.check_token_request(client_id=client.client_id)
    if not verdict.allowed:
        raise RateLimitedError(verdict.retry_after_seconds, "too many token requests")

    if grant_type == GRANT_AUTHORIZATION_CODE:
        if not code:
            raise InvalidRequestError("code is required for the authorization_code grant")
        token_set: TokenSet = await container.tokens.exchange_authorization_code(
            db,
            client=client,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )
        return dict(token_set.to_response())

    if grant_type == GRANT_REFRESH_TOKEN:
        if not refresh_token:
            raise InvalidRequestError("refresh_token is required for the refresh_token grant")
        token_set = await container.tokens.refresh(
            db, client=client, refresh_token=refresh_token, requested_scope=scope
        )
        return dict(token_set.to_response())

    # `password`, `implicit` and `client_credentials` are all absent by design (§1, §31). Naming
    # the grant back is safe and saves an integrator a guessing game.
    raise UnsupportedGrantTypeError(f"grant_type {grant_type!r} is not supported")
