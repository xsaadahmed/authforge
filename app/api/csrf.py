"""Synchronizer-token CSRF protection for the auth UI forms.

The login, MFA and consent forms are the only state-changing, cookie-authenticated,
browser-facing endpoints in the system, and consent in particular is worth attacking: a
successful CSRF there silently grants a client access to a victim's account. ``SameSite=Lax``
handles most of it; this adds the server-side half so the defence does not rest on a single
browser attribute.

The token is bound to whatever identifier the browser already carries — the session ID after
login, the flow ID before it — so a token lifted from one browser is useless in another.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from app.api.cookies import FLOW_COOKIE_NAME, new_flow_id
from app.container import Container
from app.core.errors import DomainError
from app.security.random_tokens import tokens_equal

_FLOW_CSRF_TTL_SECONDS = 900


class CsrfError(DomainError):
    def __init__(self) -> None:
        super().__init__("this form has expired; reload the page and try again", status_code=400)


@dataclass(frozen=True, slots=True)
class FlowToken:
    token: str
    flow_id: str
    # True when a flow cookie has to be written onto the outgoing response.
    is_new_flow: bool


async def issue_token_for_flow(request: Request, container: Container) -> FlowToken:
    """Issue a CSRF token for a pre-authentication form, reusing the flow cookie if present."""
    existing = request.cookies.get(FLOW_COOKIE_NAME)
    flow_id = existing or new_flow_id()
    token = await container.sessions.issue_csrf_token(
        flow_id, ttl_seconds=_FLOW_CSRF_TTL_SECONDS
    )
    return FlowToken(token=token, flow_id=flow_id, is_new_flow=existing is None)


async def issue_token_for_session(container: Container, session_id: str) -> str:
    return await container.sessions.issue_csrf_token(session_id)


async def validate_flow_token(request: Request, container: Container, submitted: str) -> None:
    flow_id = request.cookies.get(FLOW_COOKIE_NAME)
    if not flow_id:
        raise CsrfError()
    await _compare(container, key=flow_id, submitted=submitted)


async def validate_session_token(container: Container, *, session_id: str, submitted: str) -> None:
    await _compare(container, key=session_id, submitted=submitted)


async def _compare(container: Container, *, key: str, submitted: str) -> None:
    expected = await container.sessions.get_csrf_token(key)
    if not expected or not submitted or not tokens_equal(expected, submitted):
        raise CsrfError()
