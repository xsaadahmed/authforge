"""Jinja2 setup for the server-rendered auth UI.

Server-rendered HTML rather than a JS front end (§31): the login, MFA and consent screens are
three forms, and a SPA would add a build pipeline, a token-in-the-browser problem and a CORS
surface for no gain on a project whose subject is the backend and its security properties.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates
from starlette.responses import HTMLResponse

TEMPLATE_DIRECTORY = Path(__file__).resolve().parent.parent / "templates"

# autoescape is on by default in Jinja2Templates; every value rendered into these pages
# (client names, scope descriptions, error text) is attacker-influenced, so it stays on.
templates = Jinja2Templates(directory=str(TEMPLATE_DIRECTORY))


def render(
    request: Request,
    template_name: str,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name=template_name,
        context=context or {},
        status_code=status_code,
        headers=headers,
    )


def render_error_page(
    request: Request,
    *,
    error: str,
    description: str | None,
    status_code: int = 400,
) -> HTMLResponse:
    return render(
        request,
        "error.html",
        {"error": error, "description": description},
        status_code=status_code,
    )
