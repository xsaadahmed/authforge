"""FastAPI dependencies.

The container is built once at startup and stashed on ``app.state``; these functions expose
slices of it to handlers. Per-request database sessions are yielded as a unit of work so a
handler that raises leaves nothing half-committed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.container import Container
from app.core.errors import DomainError
from app.security.random_tokens import tokens_equal
from app.stores.session_store import SessionState


def get_container(request: Request) -> Container:
    container = getattr(request.app.state, "container", None)
    if not isinstance(container, Container):  # pragma: no cover - indicates a broken startup
        raise RuntimeError("application container is not initialised")
    return container


def get_settings_dep(container: Container = Depends(get_container)) -> Settings:
    return container.settings


async def get_db(container: Container = Depends(get_container)) -> AsyncIterator[AsyncSession]:
    """One transaction per request: commits on a clean return, rolls back on any exception."""
    async with container.database.session() as session:
        yield session


ContainerDep = Annotated[Container, Depends(get_container)]
SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
DbDep = Annotated[AsyncSession, Depends(get_db)]


async def get_current_session(
    request: Request, container: ContainerDep
) -> tuple[str, SessionState] | None:
    """Resolve the browser session from its cookie, if any."""
    cookie = request.cookies.get(container.settings.session_cookie_name)
    if not cookie:
        return None
    state = await container.authentication.get_session(cookie)
    if state is None:
        return None
    return cookie, state


CurrentSessionDep = Annotated[tuple[str, SessionState] | None, Depends(get_current_session)]


async def require_admin_token(request: Request, container: ContainerDep) -> None:
    """Guard for the minimal admin API.

    A static bearer token, compared in constant time, and disabled unless configured. The
    primary admin path is the CLI (§31); this exists so an operator can script client
    registration without shell access to a task, and it is intentionally the smallest possible
    surface rather than a second authentication system.
    """
    expected = container.settings.admin_api_token
    if not expected:
        raise DomainError("the admin API is disabled in this deployment", status_code=404)
    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer" or not presented or not tokens_equal(presented, expected):
        raise DomainError("admin authentication required", status_code=401)


AdminGuard = Depends(require_admin_token)
