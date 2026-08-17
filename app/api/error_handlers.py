"""Exception handlers that render errors in the format each spec requires."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse, Response

from app.core.errors import (
    AuthorizationRequestError,
    DomainError,
    OAuthError,
    OAuthErrorCode,
    RateLimitedError,
)
from app.core.logging import get_logger

logger = get_logger(__name__)


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(OAuthError)
    async def _oauth_error(request: Request, exc: OAuthError) -> Response:
        # RFC 6749 §5.2 / RFC 6750 §3: the body carries `error`, and the exception decides the
        # status and any WWW-Authenticate challenge.
        return JSONResponse(status_code=exc.status_code, content=exc.to_dict(), headers=exc.headers)

    @app.exception_handler(AuthorizationRequestError)
    async def _authorization_request_error(
        request: Request, exc: AuthorizationRequestError
    ) -> Response:
        """Render, never redirect.

        Reaching this handler means the client or its redirect URI could not be validated, so
        there is no URI we are willing to send a browser to. Rendering keeps the IdP from being
        usable as an open redirector.
        """
        from app.api.templating import render_error_page

        return render_error_page(
            request,
            error=str(exc.error),
            description=exc.description,
            status_code=exc.status_code,
        )

    @app.exception_handler(RateLimitedError)
    async def _rate_limited(request: Request, exc: RateLimitedError) -> Response:
        return JSONResponse(
            status_code=429,
            content={"error": "too_many_requests", "error_description": exc.description},
            headers={"Retry-After": str(exc.retry_after_seconds)},
        )

    @app.exception_handler(DomainError)
    async def _domain_error(request: Request, exc: DomainError) -> Response:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.description})

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> Response:
        """Map FastAPI validation failures onto OAuth's ``invalid_request``.

        A malformed token request must not answer with FastAPI's default 422 envelope: RFC 6749
        clients are written to parse ``{"error": ...}`` and would otherwise see an opaque
        failure.
        """
        return JSONResponse(
            status_code=400,
            content={
                "error": str(OAuthErrorCode.INVALID_REQUEST),
                "error_description": _summarise_validation_error(exc),
            },
            headers={"Cache-Control": "no-store"},
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> Response:
        # Logged with a stack trace (redacted by the formatter) but answered opaquely: internal
        # detail in an error body is reconnaissance material.
        logger.error("unhandled exception", exc_info=exc, extra={"http_path": request.url.path})
        return JSONResponse(
            status_code=500,
            content={
                "error": str(OAuthErrorCode.SERVER_ERROR),
                "error_description": "an unexpected error occurred",
            },
        )


def _summarise_validation_error(exc: RequestValidationError) -> str:
    parts: list[str] = []
    for error in exc.errors()[:5]:
        location = ".".join(str(item) for item in error.get("loc", ()) if item != "body")
        parts.append(f"{location or 'request'}: {error.get('msg', 'invalid')}")
    return "; ".join(parts) or "the request could not be parsed"
