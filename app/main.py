"""FastAPI application factory and lifespan.

The app is built by a factory rather than at import time so tests can construct an instance with
their own settings, and so importing ``app.main`` has no side effects on a database or a Redis.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import RedirectResponse, Response
from starlette.status import HTTP_303_SEE_OTHER

from app import __version__
from app.api.error_handlers import register_error_handlers
from app.api.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
from app.api.routers import (
    account,
    admin,
    auth_ui,
    authorize,
    discovery,
    health,
    revoke,
    token,
    userinfo,
)
from app.config import Settings, get_settings
from app.container import Container, build_container, shutdown, startup
from app.core.logging import configure_logging, get_logger
from app.core.metrics import configure_metrics

logger = get_logger(__name__)

STATIC_DIRECTORY = Path(__file__).resolve().parent / "static"

_DESCRIPTION = """
A standards-compliant OAuth 2.0 / OpenID Connect Authorization Server.

Implements the Authorization Code flow with mandatory PKCE (S256 only), RS256-signed JWT access
and ID tokens with published JWKS and rotation, opaque refresh tokens with rotation and
family-wide reuse detection, Argon2id password authentication, and TOTP multi-factor
authentication. The implicit and hybrid flows are deliberately not implemented, per the OAuth 2.0
Security Best Current Practice.
"""


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    configure_logging(level=resolved.log_level, environment=resolved.environment)
    configure_metrics(environment=resolved.environment)
    container = build_container(resolved)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await startup(container)
        app.state.container = container
        logger.info(
            "authforge started",
            extra={
                "version": __version__,
                "environment": resolved.environment,
                "issuer": resolved.issuer,
                # Which *source* the secrets came from, never their values (§19).
                "signing_key_provider": resolved.signing_key_provider,
            },
        )
        try:
            yield
        finally:
            await shutdown(container)

    app = FastAPI(
        title="AuthForge Identity Provider",
        description=_DESCRIPTION,
        version=__version__,
        lifespan=lifespan,
        # The interactive docs are useful in development and are noise (plus a small
        # information-disclosure surface) on a production authorization server.
        docs_url=None if resolved.is_deployed else "/docs",
        redoc_url=None,
        openapi_url=None if resolved.is_deployed else "/openapi.json",
    )
    app.state.container = container
    app.state.settings = resolved

    # Middleware runs in reverse registration order, so security headers are added last and
    # therefore apply to every response including error responses raised deeper in the stack.
    app.add_middleware(SecurityHeadersMiddleware, settings=resolved)
    app.add_middleware(RequestContextMiddleware)
    if resolved.is_deployed:
        # Host-header validation: the issuer and every discovery URL are absolute, so a request
        # arriving with a forged Host must not be able to influence what we advertise or to poison
        # a cache with a rewritten authorization endpoint.
        app.add_middleware(
            TrustedHostMiddleware, allowed_hosts=[_issuer_host(resolved), "localhost"]
        )

    register_error_handlers(app)

    app.mount("/static", StaticFiles(directory=str(STATIC_DIRECTORY)), name="static")
    app.include_router(health.router)
    app.include_router(discovery.router)
    app.include_router(authorize.router)
    app.include_router(token.router)
    app.include_router(revoke.router)
    app.include_router(userinfo.router)
    app.include_router(auth_ui.router)
    app.include_router(account.router)
    app.include_router(admin.router)

    @app.get("/", include_in_schema=False)
    async def root() -> Response:
        return RedirectResponse(
            url="/.well-known/openid-configuration", status_code=HTTP_303_SEE_OTHER
        )

    return app


def get_app_container(app: FastAPI) -> Container:
    container = app.state.container
    assert isinstance(container, Container)  # noqa: S101
    return container


def _issuer_host(settings: Settings) -> str:
    from urllib.parse import urlparse

    return urlparse(settings.issuer).netloc or "*"


# Module-level instance for `uvicorn app.main:app`. Constructing it opens no connections; the
# lifespan handler does that.
app = create_app()
