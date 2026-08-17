"""The ``/userinfo`` endpoint (OIDC Core §5.3).

This is the IdP acting as a resource server for its own access tokens, and it demonstrates the
validation any resource server must perform: signature against JWKS, issuer, audience, expiry,
and then scope-based filtering of what is returned. Both GET and POST are supported as the spec
requires.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Header, Response

from app.api.deps import ContainerDep, DbDep
from app.core.errors import BearerTokenError
from app.repositories.user_repository import UserRepository
from app.services import claims as claims_lib

router = APIRouter(tags=["oidc"])


@router.get("/userinfo", summary="OpenID Connect UserInfo endpoint")
@router.post("/userinfo", summary="OpenID Connect UserInfo endpoint")
async def userinfo(
    container: ContainerDep,
    db: DbDep,
    response: Response,
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    token = _extract_bearer_token(authorization)
    verified = await container.tokens.verify_access_token(token)
    # OIDC Core §5.3.1: the `openid` scope is what entitles a token to UserInfo at all.
    container.tokens.require_scope(verified, claims_lib.SCOPE_OPENID)

    user = await UserRepository(db).get_by_id(verified.subject)
    if user is None or not user.is_active:
        # The token verifies but its subject is gone or disabled. `invalid_token` is correct
        # here per OIDC Core §5.3.3 — the token can no longer be honoured.
        raise BearerTokenError(description="the token's subject is no longer active")

    response.headers["Cache-Control"] = "no-store"
    return claims_lib.build_userinfo_response(
        user=claims_lib.UserClaimSource(
            user_id=user.id,
            email=user.email,
            email_verified=user.email_verified,
            full_name=user.full_name,
            given_name=user.given_name,
            family_name=user.family_name,
            picture_url=user.picture_url,
            updated_at_epoch=int(user.updated_at.timestamp()) if user.updated_at else None,
        ),
        granted_scopes=verified.scopes,
    )


def _extract_bearer_token(authorization: str | None) -> str:
    """RFC 6750 §2.1: the credential travels in the Authorization header, not a query parameter.

    The URI query method (§2.3) is deliberately unsupported: it puts an access token into browser
    history, Referer headers and access logs.
    """
    if not authorization:
        raise BearerTokenError(description="an access token is required")
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        raise BearerTokenError(description="expected an Authorization: Bearer header")
    return value.strip()
