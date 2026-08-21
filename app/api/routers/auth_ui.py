"""Server-rendered login, MFA and consent screens (§9).

These are the only cookie-authenticated, state-changing, browser-facing endpoints in the
system, so they carry the browser-specific defences: synchronizer CSRF tokens, session-ID
rotation on privilege change, and a strict rule that the post-login destination can only ever be
this server's own ``/authorize``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import parse_qs, urlencode

from fastapi import APIRouter, Form, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse, Response
from starlette.status import HTTP_303_SEE_OTHER

from app.api import cookies, csrf
from app.api.deps import ContainerDep, CurrentSessionDep, DbDep
from app.api.routers.authorize import strip_prompt_value
from app.api.templating import render
from app.container import Container
from app.core.errors import OAuthErrorCode, RateLimitedError
from app.core.logging import get_logger
from app.repositories.client_repository import ClientRepository
from app.repositories.user_repository import UserRepository
from app.services.authentication import LoginResult
from app.services.authorization import AuthorizationService
from app.services.claims import parse_scope_string
from app.services.consent import IMPLIED_SCOPES

logger = get_logger(__name__)

router = APIRouter(tags=["auth-ui"], include_in_schema=False)

# One message for every credential failure. Distinguishing "no such account" from "wrong
# password" would turn the login form into an account-enumeration oracle.
_GENERIC_LOGIN_ERROR = "That email or password is not correct."


@router.get("/login", summary="Login form")
async def login_form(
    request: Request,
    container: ContainerDep,
    db: DbDep,
    current: CurrentSessionDep,
    next: str | None = Query(default=None),
) -> Response:
    resume = _sanitize_resume_query(next)
    if current is not None and resume:
        # Already signed in and carrying a request to resume: hand it straight back to /authorize.
        return RedirectResponse(url=f"/authorize?{resume}", status_code=HTTP_303_SEE_OTHER)

    flow = await csrf.issue_token_for_flow(request, container)
    response = render(
        request,
        "login.html",
        {
            "csrf_token": flow.token,
            "next_url": resume,
            "client_name": await _resume_client_name(db, resume),
        },
    )
    _attach_flow_cookie(response, container, flow)
    return response


@router.post("/login", summary="Submit credentials")
async def login_submit(
    request: Request,
    container: ContainerDep,
    db: DbDep,
    identifier: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    next: str = Form(default=""),
) -> Response:
    await csrf.validate_flow_token(request, container, csrf_token)
    resume = _sanitize_resume_query(next)

    outcome = await container.authentication.authenticate_password(
        db,
        identifier=identifier,
        password=password,
        ip_address=_client_ip(request),
        pending_authorize_query=resume,
    )

    if outcome.result is LoginResult.MFA_REQUIRED and outcome.pending_mfa_id:
        # No session cookie yet: the password alone does not authenticate anyone.
        return RedirectResponse(
            url=f"/mfa?{urlencode({'pending_id': outcome.pending_mfa_id})}",
            status_code=HTTP_303_SEE_OTHER,
        )

    if outcome.result is LoginResult.SUCCESS and outcome.session_id:
        return _post_authentication_redirect(
            container=container, session_id=outcome.session_id, resume=resume
        )

    message = {
        LoginResult.RATE_LIMITED: "Too many sign-in attempts. Wait a few minutes and try again.",
        LoginResult.ACCOUNT_LOCKED: (
            "This account is temporarily locked after repeated failed attempts."
        ),
        LoginResult.ACCOUNT_DISABLED: "This account has been disabled.",
    }.get(outcome.result, _GENERIC_LOGIN_ERROR)

    # 200 with a re-rendered form, not 401: a 401 makes browsers offer a native credential
    # dialog for an endpoint that does not use HTTP authentication.
    response = render(
        request,
        "login.html",
        {
            "error": message,
            # The identifier is echoed for usability; the password never is.
            "identifier": identifier,
            "next_url": resume,
            "csrf_token": csrf_token,
            "client_name": await _resume_client_name(db, resume),
        },
    )
    if outcome.retry_after_seconds:
        response.headers["Retry-After"] = str(outcome.retry_after_seconds)
    return response


@router.get("/mfa", summary="Second-factor form")
async def mfa_form(
    request: Request,
    container: ContainerDep,
    pending_id: str = Query(...),
    use_recovery_code: bool = Query(default=False),
) -> Response:
    flow = await csrf.issue_token_for_flow(request, container)
    response = render(
        request,
        "mfa.html",
        {
            "pending_id": pending_id,
            "csrf_token": flow.token,
            "use_recovery_code": use_recovery_code,
        },
    )
    _attach_flow_cookie(response, container, flow)
    return response


@router.post("/mfa", summary="Submit second factor")
async def mfa_submit(
    request: Request,
    container: ContainerDep,
    db: DbDep,
    pending_id: str = Form(...),
    code: str = Form(...),
    csrf_token: str = Form(...),
    use_recovery_code: str = Form(default="false"),
) -> Response:
    await csrf.validate_flow_token(request, container, csrf_token)
    recovery = use_recovery_code.lower() == "true"

    try:
        outcome = await container.authentication.verify_mfa_challenge(
            db, pending_mfa_id=pending_id, code=code, use_recovery_code=recovery
        )
    except RateLimitedError as exc:
        # The pending state was destroyed, so there is nothing left to retry against: the user
        # is sent back to the password step rather than to a form that can no longer succeed.
        # Rendered with a real 429 and Retry-After so the status is meaningful to a proxy or a
        # monitor, while the body stays readable to the person who hit the limit.
        flow = await csrf.issue_token_for_flow(request, container)
        response = render(
            request,
            "login.html",
            {
                "error": "Too many verification attempts. Please sign in again.",
                "csrf_token": flow.token,
            },
            status_code=429,
            headers={"Retry-After": str(exc.retry_after_seconds)},
        )
        _attach_flow_cookie(response, container, flow)
        return response

    if outcome.result is LoginResult.SUCCESS and outcome.session_id:
        # The pending record is already consumed; the resumed request survives on the new session.
        resume = _sanitize_resume_query(await _resume_from_session(container, outcome.session_id))
        return _post_authentication_redirect(
            container=container, session_id=outcome.session_id, resume=resume
        )

    return render(
        request,
        "mfa.html",
        {
            "error": "That code is not valid. Codes expire after about a minute.",
            "pending_id": pending_id,
            "csrf_token": csrf_token,
            "use_recovery_code": recovery,
        },
    )


@router.post("/consent", summary="Record a consent decision")
async def consent_submit(
    request: Request,
    container: ContainerDep,
    db: DbDep,
    current: CurrentSessionDep,
    authorize_query: str = Form(...),
    csrf_token: str = Form(...),
    decision: str = Form(...),
    scope: list[str] = Form(default=[]),
) -> Response:
    resume = _sanitize_resume_query(authorize_query)
    if current is None:
        return RedirectResponse(
            url=f"/login?{urlencode({'next': resume or ''})}", status_code=HTTP_303_SEE_OTHER
        )
    session_id, session_state = current
    await csrf.validate_session_token(container, session_id=session_id, submitted=csrf_token)
    if not resume:
        return RedirectResponse(url="/session", status_code=HTTP_303_SEE_OTHER)

    # Re-validated from scratch rather than trusted: this form field round-tripped through the
    # user's browser, so the client, redirect URI and scopes must all be proven again before
    # anything is recorded.
    params = parse_qs(resume, keep_blank_values=True)
    client_id = params.get("client_id", [""])[0]
    client = await ClientRepository(db).get_by_client_id(client_id)
    if client is None or not client.is_active:
        return render(
            request,
            "error.html",
            {"error": "invalid_request", "description": "unknown or inactive client"},
            status_code=400,
        )

    requested = await container.clients.resolve_scopes(
        db, client=client, requested=parse_scope_string(params.get("scope", [""])[0])
    )
    redirect_uri = params.get("redirect_uri", [""])[0]
    state = params.get("state", [None])[0]

    if decision != "allow":
        await container.consent.deny(
            db, user_id=session_state.user_id, client=client, scopes=requested
        )
        if container.clients.match_redirect_uri(client, redirect_uri) is None:
            # Without a validated redirect target there is nowhere safe to report the denial.
            return render(
                request,
                "error.html",
                {"error": "access_denied", "description": "you denied this request"},
                status_code=400,
            )
        return RedirectResponse(
            url=AuthorizationService.build_error_redirect(
                redirect_uri=redirect_uri,
                error=OAuthErrorCode.ACCESS_DENIED,
                description="the user denied the request",
                state=state,
            ),
            status_code=HTTP_303_SEE_OTHER,
        )

    # The grant is the intersection of what the user ticked with what the client may request, so a
    # forged or injected checkbox value cannot widen it beyond the client's registration.
    ticked = set(scope)
    approved = [name for name in requested if name in ticked or name in IMPLIED_SCOPES]
    await container.consent.grant(
        db,
        user_id=session_state.user_id,
        client=client,
        approved_scopes=approved,
        requested_scopes=requested,
    )

    # `prompt=consent` has now been satisfied; leaving it in would re-prompt forever.
    return RedirectResponse(
        url=f"/authorize?{strip_prompt_value(resume, 'consent')}", status_code=HTTP_303_SEE_OTHER
    )


@router.get("/session", summary="Current session overview")
async def session_overview(
    request: Request, container: ContainerDep, db: DbDep, current: CurrentSessionDep
) -> Response:
    if current is None:
        return RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)
    session_id, state = current
    user = await UserRepository(db).get_by_id(state.user_id)
    return render(
        request,
        "session.html",
        {
            "user_email": user.email if user else "",
            "mfa_verified": state.mfa_verified,
            "mfa_enrolled": bool(user and user.mfa_enrolled),
            "auth_time": datetime.fromtimestamp(state.auth_time, tz=UTC).isoformat(
                timespec="seconds"
            ),
            "csrf_token": await csrf.issue_token_for_session(container, session_id),
        },
    )


@router.post("/logout", summary="End the browser session")
async def logout(
    request: Request,
    container: ContainerDep,
    db: DbDep,
    current: CurrentSessionDep,
    csrf_token: str = Form(default=""),
) -> Response:
    if current is not None:
        session_id, state = current
        await csrf.validate_session_token(container, session_id=session_id, submitted=csrf_token)
        await container.authentication.logout(db, session_id, user_id=state.user_id)
    response = render(request, "logged_out.html", {})
    cookies.clear_session_cookie(response, settings=container.settings)
    cookies.clear_flow_cookie(response, settings=container.settings)
    return response


# ---------------------------------------------------------------------------- helpers
def _post_authentication_redirect(
    *, container: Container, session_id: str, resume: str | None
) -> Response:
    destination = f"/authorize?{resume}" if resume else "/session"
    response = RedirectResponse(url=destination, status_code=HTTP_303_SEE_OTHER)
    # A freshly minted session ID, never one carried in from before login: any value an attacker
    # planted in the victim's browser is now meaningless (session fixation).
    cookies.set_session_cookie(response, settings=container.settings, session_id=session_id)
    cookies.clear_flow_cookie(response, settings=container.settings)
    return response


def _attach_flow_cookie(response: Response, container: Container, flow: csrf.FlowToken) -> None:
    if flow.is_new_flow:
        cookies.set_flow_cookie(response, settings=container.settings, flow_id=flow.flow_id)


def _sanitize_resume_query(candidate: str | None) -> str | None:
    """Accept a post-login destination only as a query string for this server's ``/authorize``.

    The value round-trips through a form field and a query parameter, so it is attacker-
    influenced and is never treated as a URL. Rejecting anything containing ``/``, ``\\`` or
    ``:`` makes a scheme, a host, a path and a protocol-relative reference all unrepresentable,
    so an open redirect through the login page is impossible by construction rather than by
    careful string handling. A genuine authorize query is percent-encoded and contains none of
    those characters.
    """
    if not candidate:
        return None
    cleaned = candidate.strip()
    if not cleaned or len(cleaned) > 4096:
        return None
    if any(character in cleaned for character in ("/", "\\", ":")):
        return None
    if "client_id=" not in cleaned:
        return None
    return cleaned


async def _resume_client_name(db: AsyncSession, resume: str | None) -> str | None:
    """Name the requesting client on the login page so the user knows who is asking."""
    if not resume:
        return None
    client_id = parse_qs(resume).get("client_id", [""])[0]
    if not client_id:
        return None
    client = await ClientRepository(db).get_by_client_id(client_id)
    return client.client_name if client and client.is_active else None


async def _resume_from_session(container: Container, session_id: str) -> str | None:
    state = await container.authentication.get_session(session_id)
    return state.pending_authorize_query if state else None


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None
