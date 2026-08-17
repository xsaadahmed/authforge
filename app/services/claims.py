"""Pure JWT claim construction and claim filtering.

Deliberately free of I/O so the exact contents of every token this IdP issues can be
asserted in fast unit tests. Nothing here reads a database, a clock it wasn't given, or a
signing key.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

# OIDC Core §5.1 claim groupings. Requesting a scope is what entitles a client to the claims
# in that group; anything not listed here is never emitted, so adding a claim is an explicit
# act rather than a side effect of adding a database column.
SCOPE_OPENID = "openid"
SCOPE_PROFILE = "profile"
SCOPE_EMAIL = "email"
SCOPE_OFFLINE_ACCESS = "offline_access"

PROFILE_CLAIMS = ("name", "given_name", "family_name", "picture", "updated_at")
EMAIL_CLAIMS = ("email", "email_verified")

# RFC 9068: typing the access token stops a resource server from being tricked into
# accepting an ID token (or vice versa) as a bearer credential.
ACCESS_TOKEN_TYPE_HEADER = "at+jwt"
ID_TOKEN_TYPE_HEADER = "JWT"


@dataclass(frozen=True, slots=True)
class UserClaimSource:
    """The subset of a user record that may ever appear in a token or UserInfo response."""

    user_id: str
    email: str
    email_verified: bool
    full_name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    picture_url: str | None = None
    updated_at_epoch: int | None = None


def build_access_token_claims(
    *,
    issuer: str,
    subject: str,
    audiences: list[str],
    client_id: str,
    scopes: list[str],
    issued_at: int,
    expires_at: int,
    jti: str,
    auth_time: int | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """RFC 9068-shaped access token.

    ``scope`` is a space-delimited string (RFC 6749 §3.3), not a JSON array: resource servers
    and off-the-shelf middleware expect the string form.
    """
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": audiences if len(audiences) > 1 else audiences[0],
        "client_id": client_id,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": expires_at,
        "jti": jti,
        "scope": " ".join(scopes),
    }
    if auth_time is not None:
        claims["auth_time"] = auth_time
    if session_id is not None:
        # A session identifier, not the session cookie value: lets a resource server or an
        # investigator correlate tokens to a login without holding a usable credential.
        claims["sid"] = session_id
    return claims


def build_id_token_claims(
    *,
    issuer: str,
    subject: str,
    client_id: str,
    issued_at: int,
    expires_at: int,
    auth_time: int,
    nonce: str | None,
    granted_scopes: list[str],
    user: UserClaimSource,
    access_token: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """OIDC Core §2 ID token.

    ``aud`` is the client, never a resource server: an ID token is a statement to the client
    about the user, and treating it as an API credential is the mistake ``at_hash`` and the
    distinct ``typ`` header exist to discourage.
    """
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": client_id,
        "azp": client_id,
        "iat": issued_at,
        "exp": expires_at,
        "auth_time": auth_time,
    }
    if nonce:
        # OIDC Core §3.1.3.7: the client compares this to the nonce it generated, which is
        # what makes an ID token non-replayable into a different login attempt.
        claims["nonce"] = nonce
    if access_token:
        claims["at_hash"] = compute_at_hash(access_token)
    if session_id:
        claims["sid"] = session_id
    claims.update(_identity_claims(user=user, granted_scopes=granted_scopes))
    return claims


def build_userinfo_response(*, user: UserClaimSource, granted_scopes: list[str]) -> dict[str, Any]:
    """OIDC Core §5.3 UserInfo response, filtered to the token's granted scopes."""
    response: dict[str, Any] = {"sub": user.user_id}
    response.update(_identity_claims(user=user, granted_scopes=granted_scopes))
    return response


def _identity_claims(*, user: UserClaimSource, granted_scopes: list[str]) -> dict[str, Any]:
    granted = set(granted_scopes)
    claims: dict[str, Any] = {}
    if SCOPE_PROFILE in granted:
        for key, value in (
            ("name", user.full_name),
            ("given_name", user.given_name),
            ("family_name", user.family_name),
            ("picture", user.picture_url),
            ("updated_at", user.updated_at_epoch),
        ):
            if value is not None:
                claims[key] = value
    if SCOPE_EMAIL in granted:
        claims["email"] = user.email
        claims["email_verified"] = user.email_verified
    return claims


def compute_at_hash(access_token: str) -> str:
    """OIDC Core §3.1.3.6: base64url of the left half of SHA-256(access_token).

    Binds the ID token to the access token delivered alongside it, so a client can detect an
    attacker substituting a different access token into the response.
    """
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")


def parse_scope_string(raw: str | None) -> list[str]:
    """Split an OAuth scope parameter, preserving request order and dropping duplicates."""
    if not raw:
        return []
    return list(dict.fromkeys(token for token in raw.replace("+", " ").split(" ") if token))


def format_scope_string(scopes: list[str]) -> str:
    return " ".join(scopes)
