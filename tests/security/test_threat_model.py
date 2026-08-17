"""One passing test per mitigation in the specification's threat-model table (§22).

Grouped by threat so that the mapping from "documented control" to "demonstrated behaviour" is
readable at a glance rather than inferred. Phase 3's exit criterion is that every row of that table
is exercised here.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.container import Container
from app.models.user import User
from app.security.pkce import compute_s256_challenge, generate_code_verifier
from app.security.random_tokens import new_opaque_token
from tests.conftest import TEST_REDIRECT_URI, Seeded
from tests.helpers import (
    complete_authorization,
    exchange_code,
    full_flow_tokens,
    hidden_fields,
    login,
    redirect_params,
    refresh,
)

pytestmark = [pytest.mark.integration, pytest.mark.security]


# --------------------------------------------------------------- open redirect / redirect URI
async def test_unregistered_redirect_uri_renders_an_error_instead_of_redirecting(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """The open-redirect defence.

    An unvalidated redirect URI must never receive a redirect — not even an error redirect — or the
    IdP becomes an open redirector that lends its domain's reputation to an attacker's link.
    """
    _, challenge = pkce_pair
    query = seeded.authorize_query(
        code_challenge=challenge, redirect_uri="https://evil.example.test/steal"
    )
    response = await app_client.get(f"/authorize?{query}")
    assert response.status_code == 400
    assert "location" not in response.headers
    assert "invalid_request" in response.text


async def test_unknown_client_id_renders_an_error_instead_of_redirecting(
    app_client: AsyncClient, pkce_pair: tuple[str, str]
) -> None:
    _, challenge = pkce_pair
    response = await app_client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "no-such-client",
            "redirect_uri": TEST_REDIRECT_URI,
            "scope": "openid",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert response.status_code == 400
    assert "location" not in response.headers


async def test_a_disabled_client_cannot_start_an_authorization(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    from app.repositories.client_repository import ClientRepository

    async with container.database.session() as session:
        await ClientRepository(session).set_active(
            client_id=seeded.client_internal_id, is_active=False
        )
    _, challenge = pkce_pair
    response = await app_client.get(
        f"/authorize?{seeded.authorize_query(code_challenge=challenge)}"
    )
    assert response.status_code == 400
    assert "location" not in response.headers


async def test_code_cannot_be_exchanged_with_a_different_redirect_uri(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """RFC 6749 §4.1.3. Blocks exchanging a code obtained through an injected redirect."""
    verifier, challenge = pkce_pair
    result = await complete_authorization(
        app_client, seeded, query=seeded.authorize_query(code_challenge=challenge)
    )
    response = await exchange_code(
        app_client,
        seeded,
        code=result.code,
        code_verifier=verifier,
        redirect_uri="https://rp.example.test/other",
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


async def test_code_exchange_requires_the_redirect_uri(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    verifier, challenge = pkce_pair
    result = await complete_authorization(
        app_client, seeded, query=seeded.authorize_query(code_challenge=challenge)
    )
    response = await app_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": result.code,
            "code_verifier": verifier,
        },
        auth=(seeded.client_id, seeded.client_secret),
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


# --------------------------------------------------------------- PKCE
async def test_missing_pkce_is_rejected_for_a_confidential_client(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    """PKCE is mandatory for *every* client type, not just public ones (§2, §22)."""
    response = await app_client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": seeded.client_id,
            "redirect_uri": TEST_REDIRECT_URI,
            "scope": "openid",
            "state": "s",
        },
    )
    assert response.status_code == 303
    params = redirect_params(response)
    assert params["error"] == "invalid_request"
    assert "code_challenge" in params["error_description"]


async def test_plain_code_challenge_method_is_rejected(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    """PKCE downgrade. `plain` makes the challenge equal the verifier, which defeats the point."""
    verifier = generate_code_verifier()
    query = seeded.authorize_query(code_challenge=verifier, code_challenge_method="plain")
    response = await app_client.get(f"/authorize?{query}")
    assert response.status_code == 303
    assert redirect_params(response)["error"] == "invalid_request"


async def test_omitted_code_challenge_method_does_not_default_to_plain(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """RFC 7636 says a missing method defaults to `plain`; since `plain` is refused, so is omission.

    Silently treating an omitted method as S256 would be worse: a client that genuinely sent a plain
    challenge would appear to work while its codes were unprotected.
    """
    _, challenge = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge, code_challenge_method=None)
    response = await app_client.get(f"/authorize?{query}")
    assert response.status_code == 303
    assert redirect_params(response)["error"] == "invalid_request"


async def test_wrong_code_verifier_is_rejected(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """The central PKCE guarantee: an intercepted code is useless without the verifier."""
    _, challenge = pkce_pair
    result = await complete_authorization(
        app_client, seeded, query=seeded.authorize_query(code_challenge=challenge)
    )
    response = await exchange_code(
        app_client,
        seeded,
        code=result.code,
        code_verifier=generate_code_verifier(),
        redirect_uri=TEST_REDIRECT_URI,
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


async def test_missing_code_verifier_is_rejected(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    _, challenge = pkce_pair
    result = await complete_authorization(
        app_client, seeded, query=seeded.authorize_query(code_challenge=challenge)
    )
    response = await app_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": TEST_REDIRECT_URI,
        },
        auth=(seeded.client_id, seeded.client_secret),
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


# --------------------------------------------------------------- codes: replay and expiry
async def test_expired_authorization_code_is_rejected(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    """Expiry is a Redis TTL, so this deletes the key to simulate the TTL having fired.

    (The TTL's own correctness is asserted directly against Redis in the Redis behaviour tests.)
    """
    verifier, challenge = pkce_pair
    result = await complete_authorization(
        app_client, seeded, query=seeded.authorize_query(code_challenge=challenge)
    )
    await container.auth_codes.discard(result.code)

    response = await exchange_code(
        app_client,
        seeded,
        code=result.code,
        code_verifier=verifier,
        redirect_uri=TEST_REDIRECT_URI,
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


async def test_a_code_issued_to_one_client_cannot_be_redeemed_by_another(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    from app.models.client import ClientType

    verifier, challenge = pkce_pair
    result = await complete_authorization(
        app_client, seeded, query=seeded.authorize_query(code_challenge=challenge)
    )
    async with container.database.session() as session:
        other = await container.clients.register_client(
            session,
            client_name="Other",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=[TEST_REDIRECT_URI],
            allowed_scopes=["openid"],
            client_id="attacker-client",
        )

    response = await app_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": TEST_REDIRECT_URI,
            "code_verifier": verifier,
        },
        auth=("attacker-client", other.client_secret or ""),
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


# --------------------------------------------------------------- client authentication
async def test_wrong_client_secret_is_rejected(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    verifier, challenge = pkce_pair
    result = await complete_authorization(
        app_client, seeded, query=seeded.authorize_query(code_challenge=challenge)
    )
    response = await app_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": result.code,
            "redirect_uri": TEST_REDIRECT_URI,
            "code_verifier": verifier,
        },
        auth=(seeded.client_id, "wrong-secret"),
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"
    # RFC 6749 §5.2: a failed Basic attempt gets a challenge back.
    assert response.headers["www-authenticate"].startswith("Basic")


async def test_missing_client_authentication_is_rejected(app_client: AsyncClient) -> None:
    response = await app_client.post("/token", data={"grant_type": "refresh_token"})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client"


async def test_unknown_and_disabled_clients_are_indistinguishable(
    app_client: AsyncClient, seeded: Seeded, container: Container
) -> None:
    """Distinguishing them would confirm which client_ids exist."""
    from app.repositories.client_repository import ClientRepository

    unknown = await app_client.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": "x"},
        auth=("does-not-exist", "secret"),
    )
    async with container.database.session() as session:
        await ClientRepository(session).set_active(
            client_id=seeded.client_internal_id, is_active=False
        )
    disabled = await app_client.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": "x"},
        auth=(seeded.client_id, seeded.client_secret),
    )
    assert unknown.status_code == disabled.status_code
    assert unknown.json() == disabled.json()


# --------------------------------------------------------------- token validation
async def test_tampered_access_token_signature_is_rejected(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    header, payload, signature = tokens["access_token"].split(".")
    flipped = signature[:-4] + ("AAAA" if not signature.endswith("AAAA") else "BBBB")
    response = await app_client.get(
        "/userinfo", headers={"Authorization": f"Bearer {header}.{payload}.{flipped}"}
    )
    assert response.status_code == 401
    assert 'error="invalid_token"' in response.headers["www-authenticate"]


async def test_token_with_alg_none_is_rejected(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """The classic JWT attack: strip the signature and set `alg: none`.

    Blocked by pinning `algorithms=["RS256"]` at verification rather than trusting the header.
    """
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    unsigned = jwt.encode(claims, key="", algorithm="none")
    response = await app_client.get("/userinfo", headers={"Authorization": f"Bearer {unsigned}"})
    assert response.status_code == 401


async def test_token_signed_with_an_attacker_key_is_rejected(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """Same `kid`, different key. Only the published key for that `kid` may verify a token."""
    from app.security.rsa_keys import generate_keypair

    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    header = jwt.get_unverified_header(tokens["access_token"])
    attacker = generate_keypair(header["kid"])
    forged = jwt.encode(
        claims, attacker.private_pem, algorithm="RS256", headers={"kid": header["kid"]}
    )
    response = await app_client.get("/userinfo", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


async def test_token_with_an_unknown_kid_is_rejected(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    from app.security.rsa_keys import generate_keypair

    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    attacker = generate_keypair("never-published-kid")
    forged = jwt.encode(
        claims, attacker.private_pem, algorithm="RS256", headers={"kid": "never-published-kid"}
    )
    response = await app_client.get("/userinfo", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


async def test_expired_access_token_is_rejected(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    """Signed with the server's real key but already expired, so only `exp` can reject it."""
    signing_key = await container.keys.get_signing_key()
    now = int(time.time())
    expired = jwt.encode(
        {
            "iss": container.settings.issuer,
            "sub": seeded.user_id,
            "aud": container.settings.issuer,
            "client_id": seeded.client_id,
            "scope": "openid",
            "iat": now - 7200,
            "exp": now - 3600,
            "jti": new_opaque_token(8),
        },
        signing_key.private_key,  # type: ignore[arg-type]
        algorithm="RS256",
        headers={"kid": signing_key.kid, "typ": "at+jwt"},
    )
    response = await app_client.get("/userinfo", headers={"Authorization": f"Bearer {expired}"})
    assert response.status_code == 401


async def test_token_for_the_wrong_audience_is_rejected(
    app_client: AsyncClient, seeded: Seeded, container: Container
) -> None:
    """A token minted for another resource server must not be accepted here (RFC 9068 §4)."""
    signing_key = await container.keys.get_signing_key()
    now = int(time.time())
    wrong_audience = jwt.encode(
        {
            "iss": container.settings.issuer,
            "sub": seeded.user_id,
            "aud": "https://someone-elses-api.example.test",
            "client_id": seeded.client_id,
            "scope": "openid",
            "iat": now,
            "exp": now + 600,
            "jti": new_opaque_token(8),
        },
        signing_key.private_key,  # type: ignore[arg-type]
        algorithm="RS256",
        headers={"kid": signing_key.kid, "typ": "at+jwt"},
    )
    response = await app_client.get(
        "/userinfo", headers={"Authorization": f"Bearer {wrong_audience}"}
    )
    assert response.status_code == 401


async def test_token_from_a_different_issuer_is_rejected(
    app_client: AsyncClient, seeded: Seeded, container: Container
) -> None:
    signing_key = await container.keys.get_signing_key()
    now = int(time.time())
    wrong_issuer = jwt.encode(
        {
            "iss": "https://evil-idp.example.test",
            "sub": seeded.user_id,
            "aud": container.settings.issuer,
            "client_id": seeded.client_id,
            "scope": "openid",
            "iat": now,
            "exp": now + 600,
            "jti": new_opaque_token(8),
        },
        signing_key.private_key,  # type: ignore[arg-type]
        algorithm="RS256",
        headers={"kid": signing_key.kid, "typ": "at+jwt"},
    )
    response = await app_client.get(
        "/userinfo", headers={"Authorization": f"Bearer {wrong_issuer}"}
    )
    assert response.status_code == 401


async def test_an_id_token_is_not_accepted_as_a_bearer_credential(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """An ID token is a statement to the client, not an API credential.

    It is signed by the same key and carries a valid `iss`/`exp`, so only the audience check and the
    RFC 9068 `typ` distinction stand between it and being honoured as an access token.
    """
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    response = await app_client.get(
        "/userinfo", headers={"Authorization": f"Bearer {tokens['id_token']}"}
    )
    assert response.status_code == 401


async def test_access_token_without_the_openid_scope_cannot_read_userinfo(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """OIDC Core §5.3.1, answered with 403 + `insufficient_scope` per RFC 6750 §3.1."""
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair, scope="profile")
    response = await app_client.get(
        "/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert response.status_code == 403
    assert 'error="insufficient_scope"' in response.headers["www-authenticate"]


async def test_userinfo_rejects_a_token_in_the_query_string(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """RFC 6750 §2.3's URI method is deliberately unsupported: it writes tokens into browser
    Referer headers and access logs."""
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    response = await app_client.get("/userinfo", params={"access_token": tokens["access_token"]})
    assert response.status_code == 401


# --------------------------------------------------------------- CSRF / sessions / cookies
async def test_login_without_a_csrf_token_is_rejected(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    response = await app_client.post(
        "/login", data={"identifier": seeded.user_email, "password": seeded.password}
    )
    assert response.status_code in (400, 422)
    assert app_client.cookies.get("authforge_session") is None


async def test_login_with_a_forged_csrf_token_is_rejected(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    await app_client.get("/login")  # establishes the flow cookie
    response = await app_client.post(
        "/login",
        data={
            "identifier": seeded.user_email,
            "password": seeded.password,
            "csrf_token": new_opaque_token(24),
        },
    )
    assert response.status_code == 400
    assert app_client.cookies.get("authforge_session") is None


async def test_consent_with_a_forged_csrf_token_is_rejected(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """The highest-value CSRF target: a forged consent silently grants a client account access."""
    _, challenge = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge)
    initial = await app_client.get(f"/authorize?{query}")
    resume = redirect_params(initial)["next"]
    login_response = await login(app_client, seeded, next_query=resume)
    consent_page = await app_client.get(login_response.headers["location"])
    fields = hidden_fields(consent_page.text)

    response = await app_client.post(
        "/consent",
        data={
            "authorize_query": fields["authorize_query"],
            "csrf_token": new_opaque_token(24),
            "decision": "allow",
            "scope": ["openid", "profile", "email"],
        },
    )
    assert response.status_code == 400


async def test_session_cookie_is_httponly_and_samesite(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    """HttpOnly keeps XSS from reading it; SameSite=Lax keeps it off cross-site POSTs."""
    response = await login(app_client, seeded)
    cookie_header = next(
        value
        for key, value in response.headers.multi_items()
        if key.lower() == "set-cookie" and value.startswith("authforge_session=")
    )
    assert "HttpOnly" in cookie_header
    assert "SameSite=lax" in cookie_header.replace("Lax", "lax")
    assert "Path=/" in cookie_header


async def test_session_id_is_regenerated_on_login(app_client: AsyncClient, seeded: Seeded) -> None:
    """Session fixation.

    An attacker who plants a known session ID in the victim's browser before login must find that
    value worthless afterwards, so the post-login ID is always freshly minted.
    """
    planted = new_opaque_token()
    app_client.cookies.set("authforge_session", planted, domain="idp.example.test")
    response = await login(app_client, seeded)
    assert response.status_code == 303
    issued = app_client.cookies.get("authforge_session")
    assert issued is not None
    assert issued != planted


async def test_logout_destroys_the_server_side_session(
    app_client: AsyncClient, seeded: Seeded, container: Container
) -> None:
    """Server-side sessions mean logout is immediate rather than a wait for a cookie to expire."""
    await login(app_client, seeded)
    session_id = app_client.cookies.get("authforge_session")
    assert session_id is not None
    assert await container.sessions.get(session_id) is not None

    overview = await app_client.get("/session")
    fields = hidden_fields(overview.text)
    await app_client.post("/logout", data={"csrf_token": fields["csrf_token"]})

    assert await container.sessions.get(session_id) is None


async def test_a_forged_session_cookie_is_not_accepted(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """Sessions are opaque server-side records, so a guessed cookie names nothing."""
    app_client.cookies.set("authforge_session", new_opaque_token(), domain="idp.example.test")
    _, challenge = pkce_pair
    response = await app_client.get(
        f"/authorize?{seeded.authorize_query(code_challenge=challenge)}"
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


async def test_login_next_parameter_cannot_be_used_as_an_open_redirect(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    """`next` is only ever a query string for our own /authorize, never a URL."""
    for attempt in (
        "https://evil.example.test/",
        "//evil.example.test",
        "/../../evil",
        "http://evil.example.test?client_id=x",
    ):
        response = await login(app_client, seeded, next_query=attempt)
        assert response.status_code == 303
        location = response.headers["location"]
        assert urlparse(location).netloc == ""
        assert "evil.example.test" not in location


# --------------------------------------------------------------- scope / privilege
async def test_an_unknown_scope_is_rejected(app_client: AsyncClient, seeded: Seeded) -> None:
    """Unknown scopes are an error, while known-but-not-granted ones are dropped (RFC 6749 §3.3)."""
    verifier = generate_code_verifier()
    query = seeded.authorize_query(
        code_challenge=compute_s256_challenge(verifier), scope="openid not-a-real-scope"
    )
    response = await app_client.get(f"/authorize?{query}")
    assert response.status_code == 303
    assert redirect_params(response)["error"] == "invalid_scope"


async def test_a_forged_consent_checkbox_cannot_grant_an_unregistered_scope(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """The checkbox is a UI affordance; the client's registration is the authority."""
    verifier, challenge = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge, scope="openid profile")
    result = await complete_authorization(
        app_client,
        seeded,
        query=query,
        approve_scopes=["profile", "reports:read", "email"],
    )
    tokens = (
        await exchange_code(
            app_client,
            seeded,
            code=result.code,
            code_verifier=verifier,
            redirect_uri=TEST_REDIRECT_URI,
        )
    ).json()
    granted = set(tokens["scope"].split())
    assert "reports:read" not in granted
    assert "email" not in granted


# --------------------------------------------------------------- unsupported flows
@pytest.mark.parametrize("response_type", ["token", "id_token", "code token", "code id_token"])
async def test_implicit_and_hybrid_response_types_are_refused(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str], response_type: str
) -> None:
    """Deliberately not implemented (§31): these deliver credentials in the URL fragment, which the
    OAuth 2.0 Security BCP advises against."""
    _, challenge = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge, response_type=response_type)
    response = await app_client.get(f"/authorize?{query}")
    assert response.status_code == 303
    assert redirect_params(response)["error"] == "unsupported_response_type"


@pytest.mark.parametrize(
    "grant_type",
    ["password", "client_credentials", "implicit", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
)
async def test_unsupported_grant_types_are_refused(
    app_client: AsyncClient, seeded: Seeded, grant_type: str
) -> None:
    response = await app_client.post(
        "/token",
        data={"grant_type": grant_type, "username": "x", "password": "y"},
        auth=(seeded.client_id, seeded.client_secret),
    )
    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_grant_type"


# --------------------------------------------------------------- brute force / lockout
async def test_repeated_failures_lock_the_account(
    app_client: AsyncClient, seeded: Seeded, container: Container
) -> None:
    """Lockout is a durable Postgres counter, not a Redis one, so a cache flush cannot clear it."""
    threshold = container.settings.account_lockout_threshold
    for _ in range(threshold):
        response = await login(app_client, seeded, password="wrong-password-entirely")
        assert response.status_code == 200

    async with container.database.session() as session:
        user = (
            (await session.execute(select(User).where(User.id == seeded.user_id))).scalars().one()
        )
    assert user.failed_login_count >= threshold
    assert user.locked_until is not None

    # The correct password is now refused too, which is the point of a lockout.
    blocked = await login(app_client, seeded)
    assert blocked.status_code == 200
    assert app_client.cookies.get("authforge_session") is None


async def test_a_successful_login_clears_the_failure_counter(
    app_client: AsyncClient, seeded: Seeded, container: Container
) -> None:
    await login(app_client, seeded, password="wrong-password-entirely")
    await login(app_client, seeded)
    async with container.database.session() as session:
        user = (
            (await session.execute(select(User).where(User.id == seeded.user_id))).scalars().one()
        )
    assert user.failed_login_count == 0
    assert user.locked_until is None


async def test_login_failures_are_indistinguishable_between_unknown_and_wrong_password(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    """Account enumeration. The rendered page must be identical apart from the echoed identifier."""
    unknown = await login(app_client, seeded, password="wrong")
    form = await app_client.get("/login")
    fields = hidden_fields(form.text)
    nonexistent = await app_client.post(
        "/login",
        data={
            "identifier": "nobody@example.test",
            "password": "wrong",
            "csrf_token": fields["csrf_token"],
        },
    )
    assert unknown.status_code == nonexistent.status_code == 200
    marker = "That email or password is not correct."
    assert marker in unknown.text
    assert marker in nonexistent.text


# --------------------------------------------------------------- transport / headers
async def test_security_headers_are_present_on_the_auth_ui(app_client: AsyncClient) -> None:
    response = await app_client.get("/login")
    headers = response.headers
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    # No inline script: the auth UI is server-rendered with an external stylesheet only.
    assert "script-src" not in headers["content-security-policy"]
    assert headers["cache-control"].startswith("no-store")


async def test_every_response_carries_a_correlation_id(app_client: AsyncClient) -> None:
    response = await app_client.get("/health")
    assert response.headers["x-request-id"]


async def test_an_inbound_correlation_id_is_reused(app_client: AsyncClient) -> None:
    response = await app_client.get("/health", headers={"X-Request-ID": "trace-from-the-alb"})
    assert response.headers["x-request-id"] == "trace-from-the-alb"


# --------------------------------------------------------------- revocation
async def test_revoked_refresh_token_stops_working(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    revocation = await app_client.post(
        "/revoke",
        data={"token": tokens["refresh_token"], "token_type_hint": "refresh_token"},
        auth=(seeded.client_id, seeded.client_secret),
    )
    assert revocation.status_code == 200

    response = await refresh(app_client, seeded, refresh_token=tokens["refresh_token"])
    assert response.status_code == 400


async def test_revocation_returns_200_for_an_unknown_token(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    """RFC 7009 §2.2. Anything else would make the endpoint a token-validity oracle."""
    response = await app_client.post(
        "/revoke",
        data={"token": "never-existed"},
        auth=(seeded.client_id, seeded.client_secret),
    )
    assert response.status_code == 200


async def test_one_client_cannot_revoke_another_clients_token(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    from app.models.client import ClientType

    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    async with container.database.session() as session:
        other = await container.clients.register_client(
            session,
            client_name="Other",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://other.example.test/cb"],
            allowed_scopes=["openid"],
            client_id="other-client",
        )

    # Still 200, because the response must not reveal whether the token exists...
    response = await app_client.post(
        "/revoke",
        data={"token": tokens["refresh_token"]},
        auth=("other-client", other.client_secret or ""),
    )
    assert response.status_code == 200

    # ...but nothing was actually revoked.
    still_valid = await refresh(app_client, seeded, refresh_token=tokens["refresh_token"])
    assert still_valid.status_code == 200


async def test_revoked_access_token_is_refused_by_userinfo(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """Access-token revocation via the bounded `jti` denylist (RFC 7009's optional part)."""
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    assert (
        await app_client.get(
            "/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
    ).status_code == 200

    await app_client.post(
        "/revoke",
        data={"token": tokens["access_token"], "token_type_hint": "access_token"},
        auth=(seeded.client_id, seeded.client_secret),
    )
    after = await app_client.get(
        "/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert after.status_code == 401


# --------------------------------------------------------------- SQL injection
@pytest.mark.parametrize(
    "payload",
    [
        "' OR 1=1 --",
        "admin'--",
        "'; DROP TABLE users; --",
        '" OR ""="',
        "' UNION SELECT NULL,NULL,NULL --",
    ],
)
async def test_sql_injection_payloads_in_the_login_form_are_inert(
    app_client: AsyncClient, seeded: Seeded, container: Container, payload: str
) -> None:
    """Parameterised queries throughout, so these are ordinary strings that match no user.

    The table still existing afterwards is the assertion that matters.
    """
    form = await app_client.get("/login")
    fields = hidden_fields(form.text)
    response = await app_client.post(
        "/login",
        data={"identifier": payload, "password": payload, "csrf_token": fields["csrf_token"]},
    )
    assert response.status_code == 200
    assert app_client.cookies.get("authforge_session") is None

    async with container.database.session() as session:
        users = (await session.execute(select(User))).scalars().all()
    assert len(users) == 1


# --------------------------------------------------------------- prompt=none
async def test_prompt_none_without_a_session_returns_login_required(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """OIDC Core §3.1.2.1: no interaction permitted, so an unauthenticated user is an error."""
    _, challenge = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge, extra={"prompt": "none"})
    response = await app_client.get(f"/authorize?{query}")
    assert response.status_code == 303
    assert redirect_params(response)["error"] == "login_required"


async def test_prompt_none_without_consent_returns_consent_required(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    await login(app_client, seeded)
    _, challenge = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge, extra={"prompt": "none"})
    response = await app_client.get(f"/authorize?{query}")
    assert response.status_code == 303
    assert redirect_params(response)["error"] == "consent_required"


async def test_prompt_none_cannot_be_combined_with_other_values(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    _, challenge = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge, extra={"prompt": "none login"})
    response = await app_client.get(f"/authorize?{query}")
    assert response.status_code == 303
    assert redirect_params(response)["error"] == "invalid_request"


async def test_max_age_forces_reauthentication_of_an_old_session(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    """OIDC Core `max_age`: a client may accept a session only if it is recent enough."""
    await login(app_client, seeded)
    session_id = app_client.cookies.get("authforge_session")
    assert session_id is not None
    state = await container.sessions.get(session_id)
    assert state is not None
    state.auth_time = int(time.time()) - 7200
    await container.sessions.replace(session_id, state)

    _, challenge = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge, extra={"max_age": "60"})
    response = await app_client.get(f"/authorize?{query}")
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


async def test_prompt_login_forces_reauthentication_without_looping(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """`prompt=login` must be satisfied by the login it triggers, not re-trigger it forever."""
    await login(app_client, seeded)
    _, challenge = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge, extra={"prompt": "login"})

    response = await app_client.get(f"/authorize?{query}")
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")
    resume = redirect_params(response)["next"]
    assert "prompt" not in parse_qs(resume)

    result = await complete_authorization(app_client, seeded, query=resume)
    assert result.code
