"""The ``/revoke`` endpoint (RFC 7009).

The endpoint answers 200 whether the token existed, was already revoked, or was never valid.
That is not laziness: RFC 7009 §2.2 requires it, because a 404 or an error for an unknown token
would let a caller test token validity through the revocation endpoint.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Form, Header, Response, status

from app.api.deps import ContainerDep, DbDep

router = APIRouter(tags=["oauth2"])


@router.post(
    "/revoke",
    summary="OAuth 2.0 token revocation endpoint",
    status_code=status.HTTP_200_OK,
)
async def revoke(
    container: ContainerDep,
    db: DbDep,
    response: Response,
    authorization: Annotated[str | None, Header()] = None,
    token: str = Form(...),
    token_type_hint: str | None = Form(default=None),
    client_id: str | None = Form(default=None),
    client_secret: str | None = Form(default=None),
) -> Response:
    credentials = container.clients.extract_credentials(
        authorization_header=authorization,
        form_client_id=client_id,
        form_client_secret=client_secret,
    )
    # Client authentication is still required (RFC 7009 §2.1) — one client must not be able to
    # revoke another's tokens. A failure here does raise, unlike an unknown token.
    client = await container.clients.authenticate(db, credentials)

    await container.tokens.revoke(db, client=client, token=token, token_type_hint=token_type_hint)

    response.status_code = status.HTTP_200_OK
    response.headers["Cache-Control"] = "no-store"
    return response
