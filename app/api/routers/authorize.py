"""The ``/authorize`` endpoint (§8A).

This handler is a state machine with one exit per state, and it is the only place an
authorization code is minted:

    validate → authenticated? → fresh enough? → consented? → issue code and redirect

Every "no" answer either redirects the browser into the auth UI (carrying the original request
so it can be resumed) or returns an OAuth error to the client. The flow always re-enters here
afterwards, so the code-issuing path is reached by exactly one route no matter how the user got
there.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse

from fastapi import APIRouter, Request
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse, Response
from starlette.status import HTTP_303_SEE_OTHER

from app.api import csrf
from app.api.deps import ContainerDep, CurrentSessionDep, DbDep
from app.api.templating import render
from app.container import Container
from app.core.errors import OAuthError, OAuthErrorCode
from app.repositories.scope_repository import ScopeRepository
from app.repositories.user_repository import UserRepository
from app.security.random_tokens import hash_token
from app.services.authorization import AuthorizationRequest, AuthorizationService
from app.stores.session_store import SessionState

router = APIRouter(tags=["oauth2"])

# Scopes displayed as context on the consent screen rather than as an individual choice.
_IMPLIED_SCOPES = frozenset({"openid"})


@router.get("/authorize", summary="OAuth 2.0 authorization endpoint")
async def authorize(
    request: Request, container: ContainerDep, db: DbDep, current: CurrentSessionDep
) -> Response:
    raw_query = str(request.url.query)
    params = request.query_params
    authorization = container.authorization

    # Raises AuthorizationRequestError (rendered, never redirected) if the client or redirect URI
    # cannot be validated; raises OAuthError afterwards, which we translate into a redirect below.
    try:
        validated = await authorization.validate_request(
            db,
            client_id=params.get("client_id"),
            redirect_uri=params.get("redirect_uri"),
            response_type=params.get("response_type"),
            scope=params.get("scope"),
            state=params.get("state"),
            nonce=params.get("nonce"),
            code_challenge=params.get("code_challenge"),
            code_challenge_method=params.get("code_challenge_method"),
            prompt=params.get("prompt"),
            max_age=params.get("max_age"),
            raw_query=raw_query,
        )
    except OAuthError as exc:
        # Client and redirect URI are proven at this point, so reporting the error to the client
        # is safe and is what the spec requires (RFC 6749 §4.1.2.1).
        return _redirect_error(
            redirect_uri=params.get("redirect_uri", ""),
            error=exc.error,
            description=exc.description,
            state=params.get("state"),
        )

    session_state = current[1] if current else None
    session_id = current[0] if current else None

    needs_login = session_state is None or authorization.requires_reauthentication(
        validated, auth_time=session_state.auth_time
    )
    if needs_login:
        if "none" in validated.prompts:
            # OIDC Core §3.1.2.1: prompt=none forbids any user interaction, so an unauthenticated
            # user is an error rather than a login page.
            return _redirect_error(
                redirect_uri=validated.redirect_uri,
                error=OAuthErrorCode.LOGIN_REQUIRED,
                description="no active session and prompt=none was requested",
                state=validated.state,
            )
        # `prompt=login` is satisfied by the login we are about to perform, so it is stripped from
        # the resumed request. Leaving it in would send the user straight back to login forever.
        resume_query = strip_prompt_value(raw_query, "login")
        return RedirectResponse(
            url=f"/login?{urlencode({'next': resume_query})}", status_code=HTTP_303_SEE_OTHER
        )

    assert session_state is not None  # noqa: S101 - narrowed by `needs_login` above

    decision = await container.consent.evaluate(
        db, user_id=session_state.user_id, client=validated.client, requested_scopes=validated.scopes
    )
    force_consent = "consent" in validated.prompts
    if decision.consent_required or force_consent:
        if "none" in validated.prompts:
            return _redirect_error(
                redirect_uri=validated.redirect_uri,
                error=OAuthErrorCode.CONSENT_REQUIRED,
                description="consent has not been granted and prompt=none was requested",
                state=validated.state,
            )
        return await _render_consent(
            request,
            container=container,
            db=db,
            validated=validated,
            session_id=session_id,
            session_state=session_state,
            raw_query=raw_query,
        )

    code = await authorization.issue_code(
        validated,
        user_id=session_state.user_id,
        auth_time=session_state.auth_time,
        session_id=_session_reference(session_id),
        granted_scopes=validated.scopes,
    )
    return RedirectResponse(
        url=authorization.build_success_redirect(validated, code=code),
        status_code=HTTP_303_SEE_OTHER,
    )


async def _render_consent(
    request: Request,
    *,
    container: Container,
    db: AsyncSession,
    validated: AuthorizationRequest,
    session_id: str | None,
    session_state: SessionState,
    raw_query: str,
) -> Response:
    """Render the consent screen, describing each scope in human terms."""
    catalogue = {scope.name: scope.description for scope in await ScopeRepository(db).list_all()}
    user = await UserRepository(db).get_by_id(session_state.user_id)

    # `openid` is shown as context rather than a choice: refusing it would not narrow access, it
    # would just make the request fail in a way the user cannot interpret.
    promptable = [
        {"name": name, "description": catalogue.get(name, name)}
        for name in validated.scopes
        if name not in _IMPLIED_SCOPES
    ]
    implied = [
        {"name": name, "description": catalogue.get(name, name)}
        for name in validated.scopes
        if name in _IMPLIED_SCOPES
    ]

    token = await csrf.issue_token_for_session(container, session_id) if session_id else ""
    return render(
        request,
        "consent.html",
        {
            "client": validated.client,
            "user_email": user.email if user else "",
            "promptable_scopes": promptable,
            "implied_scopes": implied,
            # The exact request is carried through the form so that POST /consent can hand the
            # browser straight back to /authorize, keeping code issuance in one place.
            "authorize_query": raw_query,
            "csrf_token": token,
            "redirect_host": urlparse(validated.redirect_uri).netloc,
        },
    )


def _redirect_error(
    *, redirect_uri: str, error: OAuthErrorCode, description: str | None, state: str | None
) -> Response:
    return RedirectResponse(
        url=AuthorizationService.build_error_redirect(
            redirect_uri=redirect_uri, error=error, description=description, state=state
        ),
        status_code=HTTP_303_SEE_OTHER,
    )


def strip_prompt_value(query: str, value: str) -> str:
    """Remove one value from the ``prompt`` parameter, preserving everything else verbatim."""
    pairs = parse_qsl(query, keep_blank_values=True)
    rebuilt: list[tuple[str, str]] = []
    for key, item in pairs:
        if key != "prompt":
            rebuilt.append((key, item))
            continue
        remaining = [token for token in item.split(" ") if token and token != value]
        if remaining:
            rebuilt.append((key, " ".join(remaining)))
    return urlencode(rebuilt)


def _session_reference(session_id: str | None) -> str | None:
    """A stable, non-credential reference to the session for the ``sid`` claim.

    The raw session ID must never appear in a token: a token is shown to clients and resource
    servers, and the session ID is a bearer credential for the browser session.
    """
    if not session_id:
        return None
    return hash_token(session_id)[:32]
