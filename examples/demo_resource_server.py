"""A minimal resource server protected by AuthForge access tokens.

Shares no code with the IdP and never calls it on the request path: it fetches JWKS once,
caches it, and verifies tokens locally. That is the whole point of issuing signed JWTs — a
resource server scales without a round trip to the authorization server for every request.

The five checks in ``_verify`` are the complete set a resource server owes its users.
Skipping any one of them is a real vulnerability, and the audience check is the one most
often forgotten.
"""

from __future__ import annotations

import os
import time
from typing import Annotated, Any

import httpx
import jwt
import uvicorn
from fastapi import FastAPI, Header, HTTPException

IDP_ISSUER = os.environ.get("AUTHFORGE_DEMO_ISSUER", "http://localhost:8000")
# This API's own identifier. The IdP must be configured to include it in
# AUTHFORGE_ACCESS_TOKEN_AUDIENCES, otherwise tokens will (correctly) be rejected here.
API_AUDIENCE = os.environ.get("AUTHFORGE_DEMO_API_AUDIENCE", IDP_ISSUER)
REQUIRED_SCOPE = os.environ.get("AUTHFORGE_DEMO_REQUIRED_SCOPE", "profile")
# JWKS is cached, but not forever: the cache TTL is what lets a key rotation propagate without a
# restart. Too long and a token signed by a new key is rejected; too short and every request
# pays for an HTTP round trip.
JWKS_CACHE_SECONDS = 300

app = FastAPI(title="AuthForge Demo Resource Server", docs_url=None, redoc_url=None)

_jwks_cache: tuple[float, jwt.PyJWKSet] | None = None


async def _get_jwks() -> jwt.PyJWKSet:
    global _jwks_cache
    if _jwks_cache is not None and _jwks_cache[0] > time.monotonic():
        return _jwks_cache[1]
    async with httpx.AsyncClient(timeout=10) as client:
        metadata = (await client.get(f"{IDP_ISSUER}/.well-known/openid-configuration")).json()
        jwks = (await client.get(metadata["jwks_uri"])).json()
    key_set = jwt.PyJWKSet.from_dict(jwks)
    _jwks_cache = (time.monotonic() + JWKS_CACHE_SECONDS, key_set)
    return key_set


async def _verify(authorization: str | None) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="an access token is required",
            headers={"WWW-Authenticate": 'Bearer realm="demo-api"'},
        )
    token = authorization.split(" ", 1)[1].strip()

    key_set = await _get_jwks()
    kid = jwt.get_unverified_header(token).get("kid")
    signing_key = next((key for key in key_set.keys if key.key_id == kid), None)
    if signing_key is None:
        # Either a forged token or one signed by a key rotated in since the cache was filled.
        # Refetch once before rejecting, so a rotation does not cause a burst of spurious 401s.
        global _jwks_cache
        _jwks_cache = None
        key_set = await _get_jwks()
        signing_key = next((key for key in key_set.keys if key.key_id == kid), None)
    if signing_key is None:
        raise _unauthorized("token signed by an unknown key")

    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            # Pinned, so a token claiming `alg: none` or a symmetric algorithm cannot verify.
            algorithms=["RS256"],
            # Without `audience`, a token minted for a different API of the same issuer would be
            # accepted here — the single most commonly skipped check.
            audience=API_AUDIENCE,
            issuer=IDP_ISSUER,
            options={"require": ["exp", "iat", "iss", "sub"]},
        )
    except jwt.InvalidTokenError as exc:
        raise _unauthorized(f"token rejected: {exc}") from exc

    granted = str(claims.get("scope", "")).split()
    if REQUIRED_SCOPE not in granted:
        raise HTTPException(
            status_code=403,
            detail=f"the {REQUIRED_SCOPE} scope is required",
            headers={
                "WWW-Authenticate": (
                    f'Bearer realm="demo-api", error="insufficient_scope", scope="{REQUIRED_SCOPE}"'
                )
            },
        )
    return dict(claims)


def _unauthorized(message: str) -> HTTPException:
    return HTTPException(
        status_code=401,
        detail=message,
        headers={"WWW-Authenticate": 'Bearer realm="demo-api", error="invalid_token"'},
    )


@app.get("/reports")
async def reports(authorization: Annotated[str | None, Header()] = None) -> dict[str, Any]:
    """A protected endpoint. Returns data scoped to the token's subject."""
    claims = await _verify(authorization)
    return {
        "message": "This response came from a separate service that verified your token locally.",
        "subject": claims["sub"],
        "issued_by": claims["iss"],
        "granted_scope": claims.get("scope"),
        "verified_audience": API_AUDIENCE,
        "reports": [
            {"id": "r-1", "title": "Quarterly usage", "owner": claims["sub"]},
            {"id": "r-2", "title": "Access review", "owner": claims["sub"]},
        ],
    }


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8200)
