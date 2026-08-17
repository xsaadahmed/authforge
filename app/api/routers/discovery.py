"""Authorization Server Metadata (RFC 8414) and JWKS (RFC 7517).

Both responses advertise only what this server actually implements. Advertising a capability
that is not implemented — or omitting ``code_challenge_methods_supported`` — pushes conforming
clients into insecure fallbacks, so the document is generated from the same constants the
handlers enforce rather than hand-maintained.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Response

from app.api.deps import ContainerDep, DbDep, SettingsDep
from app.repositories.scope_repository import ScopeRepository
from app.security.pkce import SUPPORTED_CODE_CHALLENGE_METHODS
from app.security.rsa_keys import JWS_ALGORITHM
from app.services.authorization import SUPPORTED_PROMPTS, SUPPORTED_RESPONSE_TYPES

router = APIRouter(tags=["discovery"])

SUPPORTED_GRANT_TYPES = ("authorization_code", "refresh_token")
SUPPORTED_TOKEN_AUTH_METHODS = ("client_secret_basic", "client_secret_post", "none")
SUPPORTED_CLAIMS = (
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "azp",
    "at_hash",
    "sid",
    "name",
    "given_name",
    "family_name",
    "picture",
    "updated_at",
    "email",
    "email_verified",
)
# Discovery is cacheable, but not for long: a shorter TTL is what lets a client notice a new
# endpoint or a rotated key set without operator involvement.
_DISCOVERY_CACHE_SECONDS = 300


@router.get("/.well-known/openid-configuration", summary="OpenID Connect discovery document")
async def openid_configuration(
    settings: SettingsDep, db: DbDep, response: Response
) -> dict[str, Any]:
    scope_names = sorted(await ScopeRepository(db).list_names())
    response.headers["Cache-Control"] = f"public, max-age={_DISCOVERY_CACHE_SECONDS}"
    return {
        "issuer": settings.issuer,
        "authorization_endpoint": settings.url_for("/authorize"),
        "token_endpoint": settings.url_for("/token"),
        "userinfo_endpoint": settings.url_for("/userinfo"),
        "revocation_endpoint": settings.url_for("/revoke"),
        "jwks_uri": settings.url_for("/.well-known/jwks.json"),
        "end_session_endpoint": settings.url_for("/logout"),
        "scopes_supported": scope_names,
        "response_types_supported": list(SUPPORTED_RESPONSE_TYPES),
        # RFC 6749 §4.1.2 / OIDC Core §3.1.2.5: only the query response mode is used, because
        # the fragment mode exists for the implicit flow this server does not implement.
        "response_modes_supported": ["query"],
        "grant_types_supported": list(SUPPORTED_GRANT_TYPES),
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [JWS_ALGORITHM],
        "userinfo_signing_alg_values_supported": ["none"],
        "token_endpoint_auth_methods_supported": list(SUPPORTED_TOKEN_AUTH_METHODS),
        "revocation_endpoint_auth_methods_supported": list(SUPPORTED_TOKEN_AUTH_METHODS),
        "code_challenge_methods_supported": list(SUPPORTED_CODE_CHALLENGE_METHODS),
        "claims_supported": list(SUPPORTED_CLAIMS),
        "claims_parameter_supported": False,
        "request_parameter_supported": False,
        "request_uri_parameter_supported": False,
        "prompt_values_supported": sorted(SUPPORTED_PROMPTS),
        # Non-standard but honest: tells an integrator that PKCE is not optional here.
        "require_pkce": True,
        "service_documentation": "https://github.com/authforge/authforge#readme",
    }


@router.get("/.well-known/jwks.json", summary="JSON Web Key Set")
async def jwks(container: ContainerDep, response: Response) -> dict[str, list[dict[str, Any]]]:
    """Publish the `current` key plus any `retiring` key still inside its grace period.

    Cached for the same short window the server caches key metadata internally, so a client's
    cache cannot outlive the server's own view by much — that bound is what makes rotation safe
    without a coordinated flush.
    """
    keys = await container.keys.get_jwks()
    response.headers["Cache-Control"] = (
        f"public, max-age={max(30, container.settings.jwks_cache_seconds)}"
    )
    return keys
