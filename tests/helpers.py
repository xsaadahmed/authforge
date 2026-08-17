"""Helpers that drive the browser-facing half of the flow from tests.

A real authorization-code flow involves three HTML forms and five redirects. Encoding that once
here keeps each test focused on the property it is asserting instead of on form scraping, and it
means the tests exercise the same path a browser takes — including the CSRF tokens, the cookies
and the session-ID rotation — rather than calling services directly.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

from httpx import AsyncClient, Response

from tests.conftest import Seeded

_HIDDEN_INPUT = re.compile(
    r'<input[^>]*type="hidden"[^>]*name="(?P<name>[^"]+)"[^>]*value="(?P<value>[^"]*)"',
    re.IGNORECASE,
)
_CHECKBOX = re.compile(
    r'<input[^>]*type="checkbox"[^>]*name="scope"[^>]*value="(?P<value>[^"]+)"', re.IGNORECASE
)


def hidden_fields(markup: str) -> dict[str, str]:
    """Extract hidden form fields, undoing HTML entity escaping.

    Jinja2 autoescapes attribute values, so an authorize query round-tripping through a hidden field
    arrives as `client_id=x&amp;scope=y`. A browser unescapes before submitting; so must this.
    """
    return {
        match.group("name"): html.unescape(match.group("value"))
        for match in _HIDDEN_INPUT.finditer(markup)
    }


def checkbox_scopes(markup: str) -> list[str]:
    return [match.group("value") for match in _CHECKBOX.finditer(markup)]


def redirect_params(response: Response) -> dict[str, str]:
    """Parse the query parameters of a redirect's Location header."""
    location = response.headers["location"]
    return {key: values[0] for key, values in parse_qs(urlparse(location).query).items()}


@dataclass(slots=True)
class AuthorizationCodeResult:
    code: str
    state: str | None
    redirect_location: str


async def login(
    client: AsyncClient,
    seeded: Seeded,
    *,
    next_query: str | None = None,
    password: str | None = None,
) -> Response:
    """Complete the password step and return the POST /login response."""
    form_page = await client.get("/login", params={"next": next_query} if next_query else None)
    assert form_page.status_code == 200, form_page.text
    fields = hidden_fields(form_page.text)
    return await client.post(
        "/login",
        data={
            "identifier": seeded.user_email,
            "password": password if password is not None else seeded.password,
            "csrf_token": fields["csrf_token"],
            "next": next_query or "",
        },
    )


async def submit_mfa(
    client: AsyncClient, *, pending_id: str, code: str, use_recovery_code: bool = False
) -> Response:
    form_page = await client.get(
        "/mfa",
        params={
            "pending_id": pending_id,
            "use_recovery_code": "true" if use_recovery_code else "false",
        },
    )
    assert form_page.status_code == 200, form_page.text
    fields = hidden_fields(form_page.text)
    return await client.post(
        "/mfa",
        data={
            "pending_id": pending_id,
            "code": code,
            "csrf_token": fields["csrf_token"],
            "use_recovery_code": "true" if use_recovery_code else "false",
        },
    )


async def complete_authorization(
    client: AsyncClient,
    seeded: Seeded,
    *,
    query: str,
    approve_scopes: list[str] | None = None,
) -> AuthorizationCodeResult:
    """Drive /authorize through login and consent, returning the issued authorization code.

    Adaptive rather than scripted: it follows whichever of the three exits /authorize takes, exactly
    as a browser would, so a test does not have to declare in advance whether a session or a consent
    record already exists.
    """
    response = await client.get(f"/authorize?{query}")

    if response.status_code == 303 and response.headers["location"].startswith("/login?"):
        resume = redirect_params(response)["next"]
        login_response = await login(client, seeded, next_query=resume)
        assert login_response.status_code == 303, login_response.text
        response = await client.get(login_response.headers["location"])

    if response.status_code == 200:
        # The consent screen. Approve everything the form offers unless told otherwise.
        fields = hidden_fields(response.text)
        offered = checkbox_scopes(response.text)
        chosen = approve_scopes if approve_scopes is not None else offered
        consent_response = await client.post(
            "/consent",
            data={
                "authorize_query": fields["authorize_query"],
                "csrf_token": fields["csrf_token"],
                "decision": "allow",
                # A list value becomes repeated form fields, which is how a browser submits
                # several ticked checkboxes sharing one name.
                "scope": chosen,
            },
        )
        assert consent_response.status_code == 303, consent_response.text
        response = await client.get(consent_response.headers["location"])

    assert response.status_code == 303, response.text
    location = response.headers["location"]
    params = redirect_params(response)
    assert "code" in params, location
    return AuthorizationCodeResult(
        code=params["code"], state=params.get("state"), redirect_location=location
    )


async def exchange_code(
    client: AsyncClient,
    seeded: Seeded,
    *,
    code: str,
    code_verifier: str,
    redirect_uri: str,
    use_basic_auth: bool = True,
) -> Response:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    if use_basic_auth:
        return await client.post("/token", data=data, auth=(seeded.client_id, seeded.client_secret))
    data["client_id"] = seeded.client_id
    data["client_secret"] = seeded.client_secret
    return await client.post("/token", data=data)


async def refresh(
    client: AsyncClient, seeded: Seeded, *, refresh_token: str, scope: str | None = None
) -> Response:
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    if scope is not None:
        data["scope"] = scope
    return await client.post("/token", data=data, auth=(seeded.client_id, seeded.client_secret))


async def full_flow_tokens(
    client: AsyncClient, seeded: Seeded, *, pkce_pair: tuple[str, str], scope: str | None = None
) -> dict[str, str]:
    """Shorthand: run the whole flow and return the parsed token response."""
    verifier, challenge = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge, **({"scope": scope} if scope else {}))
    result = await complete_authorization(client, seeded, query=query)
    from tests.conftest import TEST_REDIRECT_URI

    response = await exchange_code(
        client,
        seeded,
        code=result.code,
        code_verifier=verifier,
        redirect_uri=TEST_REDIRECT_URI,
    )
    assert response.status_code == 200, response.text
    return dict(response.json())
