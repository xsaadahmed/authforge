"""OAuth 2.0 / OIDC error taxonomy.

The wire format is fixed by RFC 6749 §5.2 (token endpoint), §4.1.2.1 (authorization
endpoint) and RFC 6750 §3 (bearer tokens), so errors are modelled as first-class objects
that know their own HTTP status, whether they may be redirected back to the client, and
what headers they require. Handlers never hand-build error JSON.
"""

from __future__ import annotations

from enum import StrEnum


class OAuthErrorCode(StrEnum):
    # RFC 6749 §4.1.2.1 — authorization endpoint
    INVALID_REQUEST = "invalid_request"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    ACCESS_DENIED = "access_denied"
    UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
    INVALID_SCOPE = "invalid_scope"
    SERVER_ERROR = "server_error"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"
    # RFC 6749 §5.2 — token endpoint
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    # RFC 6750 §3.1 — protected resources
    INVALID_TOKEN = "invalid_token"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    # OIDC Core §3.1.2.6
    LOGIN_REQUIRED = "login_required"
    CONSENT_REQUIRED = "consent_required"
    INTERACTION_REQUIRED = "interaction_required"


class OAuthError(Exception):
    """An error that must be reported to a client in OAuth's own format."""

    status_code = 400

    def __init__(
        self,
        error: OAuthErrorCode,
        description: str | None = None,
        *,
        status_code: int | None = None,
        error_uri: str | None = None,
    ) -> None:
        super().__init__(f"{error}: {description or ''}".strip())
        self.error = error
        self.description = description
        self.error_uri = error_uri
        if status_code is not None:
            self.status_code = status_code

    def to_dict(self) -> dict[str, str]:
        payload = {"error": str(self.error)}
        if self.description:
            payload["error_description"] = self.description
        if self.error_uri:
            payload["error_uri"] = self.error_uri
        return payload

    @property
    def headers(self) -> dict[str, str]:
        # RFC 6749 §5.1: token endpoint responses must not be cached.
        return {"Cache-Control": "no-store", "Pragma": "no-cache"}


class InvalidRequestError(OAuthError):
    def __init__(self, description: str | None = None) -> None:
        super().__init__(OAuthErrorCode.INVALID_REQUEST, description)


class InvalidClientError(OAuthError):
    """Client authentication failed.

    401 with ``WWW-Authenticate: Basic`` when the client attempted (and failed) HTTP Basic
    auth, per RFC 6749 §5.2; otherwise 400 so that a body-authenticating client sees a
    plain error rather than a browser credential prompt.
    """

    def __init__(self, description: str | None = None, *, used_basic_auth: bool = False) -> None:
        super().__init__(
            OAuthErrorCode.INVALID_CLIENT, description, status_code=401 if used_basic_auth else 400
        )
        self._used_basic_auth = used_basic_auth

    @property
    def headers(self) -> dict[str, str]:
        headers = super().headers
        if self._used_basic_auth:
            headers["WWW-Authenticate"] = 'Basic realm="authforge", charset="UTF-8"'
        return headers


class InvalidGrantError(OAuthError):
    def __init__(self, description: str | None = None) -> None:
        super().__init__(OAuthErrorCode.INVALID_GRANT, description)


class UnauthorizedClientError(OAuthError):
    def __init__(self, description: str | None = None) -> None:
        super().__init__(OAuthErrorCode.UNAUTHORIZED_CLIENT, description)


class UnsupportedGrantTypeError(OAuthError):
    def __init__(self, description: str | None = None) -> None:
        super().__init__(OAuthErrorCode.UNSUPPORTED_GRANT_TYPE, description)


class InvalidScopeError(OAuthError):
    def __init__(self, description: str | None = None) -> None:
        super().__init__(OAuthErrorCode.INVALID_SCOPE, description)


class AccessDeniedError(OAuthError):
    def __init__(self, description: str | None = None) -> None:
        super().__init__(OAuthErrorCode.ACCESS_DENIED, description)


class ServerError(OAuthError):
    def __init__(self, description: str | None = None) -> None:
        super().__init__(OAuthErrorCode.SERVER_ERROR, description, status_code=500)


class TemporarilyUnavailableError(OAuthError):
    def __init__(self, description: str | None = None) -> None:
        super().__init__(OAuthErrorCode.TEMPORARILY_UNAVAILABLE, description, status_code=503)


class BearerTokenError(OAuthError):
    """RFC 6750 §3 error for a protected resource (``/userinfo``)."""

    def __init__(
        self,
        error: OAuthErrorCode = OAuthErrorCode.INVALID_TOKEN,
        description: str | None = None,
        *,
        status_code: int = 401,
        required_scope: str | None = None,
    ) -> None:
        super().__init__(error, description, status_code=status_code)
        self.required_scope = required_scope

    @property
    def headers(self) -> dict[str, str]:
        # RFC 6750 §3: the challenge carries the error in auth-param form, not just JSON.
        params = ['realm="authforge"', f'error="{self.error}"']
        if self.description:
            params.append(f'error_description="{self.description}"')
        if self.required_scope:
            params.append(f'scope="{self.required_scope}"')
        return {"WWW-Authenticate": "Bearer " + ", ".join(params), "Cache-Control": "no-store"}


class AuthorizationRequestError(Exception):
    """An ``/authorize`` failure that must NOT be redirected to the client.

    Redirecting an error to an unvalidated ``redirect_uri`` would turn the IdP into an open
    redirector, so anything discovered *before* the client and redirect URI are proven valid
    (unknown ``client_id``, unregistered ``redirect_uri``, missing PKCE on an unresolvable
    request) is rendered as an error page instead.
    """

    def __init__(self, error: OAuthErrorCode, description: str, *, status_code: int = 400) -> None:
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.status_code = status_code


class RateLimitedError(Exception):
    """Raised when a caller exceeds a configured limit."""

    def __init__(self, retry_after_seconds: int, description: str = "too many requests") -> None:
        super().__init__(description)
        self.retry_after_seconds = retry_after_seconds
        self.description = description


class DomainError(Exception):
    """A non-protocol application error (admin/CLI surface, enrolment flows)."""

    def __init__(self, description: str, *, status_code: int = 400) -> None:
        super().__init__(description)
        self.description = description
        self.status_code = status_code


class NotFoundError(DomainError):
    def __init__(self, description: str = "not found") -> None:
        super().__init__(description, status_code=404)


class ConflictError(DomainError):
    def __init__(self, description: str = "conflict") -> None:
        super().__init__(description, status_code=409)
