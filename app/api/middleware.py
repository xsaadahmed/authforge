"""Cross-cutting HTTP middleware: correlation, access logging, security headers."""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.config import Settings
from app.core.context import reset_request_context, set_request_context
from app.core.logging import get_logger
from app.core.metrics import get_metrics
from app.security.random_tokens import new_identifier

logger = get_logger("authforge.access")

REQUEST_ID_HEADER = "X-Request-ID"

# Routes whose full URL can contain a credential (an authorization `code`, a `state`) and which
# must therefore never have their query string logged.
_SENSITIVE_PATH_PREFIXES = ("/authorize", "/oauth", "/login", "/mfa", "/consent")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a correlation ID, publishes request context, and emits one access log line."""

    def __init__(self, app: ASGIApp, *, trust_forwarded_for: bool = True) -> None:
        super().__init__(app)
        self._trust_forwarded_for = trust_forwarded_for

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Reuse an inbound ID when present so a trace spans the RP, the ALB and the IdP; the
        # value is length-capped because it is echoed back and stored in audit rows.
        incoming = request.headers.get(REQUEST_ID_HEADER)
        request_id = (incoming or new_identifier())[:64]
        request.state.request_id = request_id
        tokens = set_request_context(
            request_id=request_id,
            client_ip=self._client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        started = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers[REQUEST_ID_HEADER] = request_id
            return response
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000
            route = _route_template(request)
            logger.info(
                "request completed",
                extra={
                    "http_method": request.method,
                    "http_path": request.url.path,
                    # Only for non-sensitive routes: an /authorize query string carries `state`
                    # and a redirect URI, and a callback carries a live authorization code.
                    "http_query": (
                        str(request.url.query)
                        if request.url.query and not _is_sensitive(request.url.path)
                        else None
                    ),
                    "http_status": status_code,
                    "duration_ms": round(elapsed_ms, 2),
                    "route": route,
                },
            )
            get_metrics().duration_ms(
                "RequestDuration",
                elapsed_ms,
                dimensions={"Route": route, "Status": str(status_code // 100) + "xx"},
            )
            if status_code >= 500:
                get_metrics().count("ServerError", dimensions={"Route": route})
            reset_request_context(tokens)

    def _client_ip(self, request: Request) -> str | None:
        """Resolve the caller's IP for rate limiting and audit records.

        Behind the ALB the socket peer is the load balancer, so ``X-Forwarded-For`` is required
        for per-IP limits to mean anything. The *left-most* entry is the original client; the
        ALB appends and does not sanitise, so a client-supplied header can prepend a forged
        value. That is acceptable here because the consequence is a spoofed key in a per-IP
        rate-limit bucket, not an authentication decision — and the per-account limit and the
        durable lockout counter are unaffected by it.
        """
        if self._trust_forwarded_for:
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                return forwarded.split(",")[0].strip()[:45]
        return request.client.host if request.client else None


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Applies defence-in-depth response headers to every response."""

    def __init__(self, app: ASGIApp, *, settings: Settings) -> None:
        super().__init__(app)
        self._settings = settings

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        headers = response.headers
        headers.setdefault("X-Content-Type-Options", "nosniff")
        # The login and consent pages must never be framed: a framed consent screen is a
        # clickjacking primitive for silently approving scopes.
        headers.setdefault("X-Frame-Options", "DENY")
        # Referrer-Policy matters specifically for an IdP: without it, a browser can send the
        # full /authorize URL (client_id, scopes, state) as a Referer to third-party resources.
        headers.setdefault("Referrer-Policy", "no-referrer")
        headers.setdefault(
            "Content-Security-Policy",
            # No inline script and no external origins: the auth UI is server-rendered Jinja2
            # with a single stylesheet, so the strictest useful policy costs nothing (§31).
            "default-src 'none'; img-src 'self' data:; style-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        )
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if self._settings.is_deployed:
            headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if _is_sensitive(request.url.path):
            # Keeps an authorization code or a rendered consent screen out of shared caches and
            # the browser's back-button cache.
            headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            headers["Pragma"] = "no-cache"
        return response


def _is_sensitive(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in _SENSITIVE_PATH_PREFIXES)


def _route_template(request: Request) -> str:
    """The route pattern rather than the concrete path, so metrics do not explode in cardinality."""
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return str(path) if path else request.url.path
