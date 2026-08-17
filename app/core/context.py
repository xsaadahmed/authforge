"""Request-scoped correlation context.

Held in ``ContextVar``s so that any layer — a repository, an audit write, a log record —
can attach the current request ID without threading it through every signature. Safe under
asyncio: each task gets its own copy of the context.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from typing import Any

_request_id: ContextVar[str | None] = ContextVar("authforge_request_id", default=None)
_client_ip: ContextVar[str | None] = ContextVar("authforge_client_ip", default=None)
_user_agent: ContextVar[str | None] = ContextVar("authforge_user_agent", default=None)


@dataclass(slots=True)
class RequestContext:
    request_id: str | None = None
    client_ip: str | None = None
    user_agent: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def set_request_context(
    *, request_id: str, client_ip: str | None, user_agent: str | None
) -> tuple[Token[str | None], Token[str | None], Token[str | None]]:
    return (
        _request_id.set(request_id),
        _client_ip.set(client_ip),
        _user_agent.set(user_agent),
    )


def reset_request_context(
    tokens: tuple[Token[str | None], Token[str | None], Token[str | None]],
) -> None:
    request_token, ip_token, ua_token = tokens
    _request_id.reset(request_token)
    _client_ip.reset(ip_token)
    _user_agent.reset(ua_token)


def current_context() -> RequestContext:
    return RequestContext(
        request_id=_request_id.get(),
        client_ip=_client_ip.get(),
        user_agent=_user_agent.get(),
    )


def current_request_id() -> str | None:
    return _request_id.get()
