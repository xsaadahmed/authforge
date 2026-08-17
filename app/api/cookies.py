"""Cookie handling for the browser-facing auth UI.

Two cookies exist and both are `HttpOnly`:

* the **session cookie**, naming a server-side session in Redis;
* a **flow cookie**, a pre-authentication browser identifier whose only job is to give the
  synchronizer CSRF token something to be bound to before a session exists.

``SameSite=Lax`` is the right setting rather than ``Strict``: the browser arrives at
``/authorize`` through a top-level cross-site redirect from the relying party, and ``Strict``
would withhold the session cookie on exactly that navigation, forcing a re-login on every
authorization request. ``Lax`` still withholds it from cross-site POSTs, which is the case CSRF
cares about, and the synchronizer token covers the rest.
"""

from __future__ import annotations

from starlette.responses import Response

from app.config import Settings
from app.security.random_tokens import new_opaque_token

FLOW_COOKIE_NAME = "authforge_flow"
_FLOW_COOKIE_MAX_AGE = 900


def set_session_cookie(response: Response, *, settings: Settings, session_id: str) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=session_id,
        max_age=settings.session_ttl_seconds,
        # No Expires/Domain: a host-only, session-TTL-bounded cookie is the narrowest scope that
        # still works, and omitting Domain keeps it off sibling subdomains.
        path="/",
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
    )


def clear_session_cookie(response: Response, *, settings: Settings) -> None:
    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
    )


def set_flow_cookie(response: Response, *, settings: Settings, flow_id: str) -> None:
    response.set_cookie(
        key=FLOW_COOKIE_NAME,
        value=flow_id,
        max_age=_FLOW_COOKIE_MAX_AGE,
        path="/",
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
    )


def clear_flow_cookie(response: Response, *, settings: Settings) -> None:
    response.delete_cookie(
        key=FLOW_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
    )


def new_flow_id() -> str:
    return new_opaque_token(24)
