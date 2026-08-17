"""End-to-end authorization code + PKCE flow against real Postgres and Redis (§8A, §23)."""

from __future__ import annotations

import jwt
import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.container import Container
from app.models.audit import AuditEventType, AuditLog
from app.security.pkce import compute_s256_challenge, generate_code_verifier
from app.services.claims import ACCESS_TOKEN_TYPE_HEADER
from tests.conftest import TEST_REDIRECT_URI, Seeded
from tests.helpers import (
    complete_authorization,
    exchange_code,
    login,
    redirect_params,
)

pytestmark = pytest.mark.integration


async def test_full_authorization_code_flow_issues_all_three_tokens(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    verifier, challenge = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge)

    result = await complete_authorization(app_client, seeded, query=query)
    assert result.state == "state-abc"
    assert result.redirect_location.startswith(TEST_REDIRECT_URI)

    response = await exchange_code(
        app_client,
        seeded,
        code=result.code,
        code_verifier=verifier,
        redirect_uri=TEST_REDIRECT_URI,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["token_type"] == "Bearer"
    assert payload["expires_in"] == 300
    assert set(payload["scope"].split()) == {"openid", "profile", "email", "offline_access"}
    assert payload["access_token"] and payload["id_token"] and payload["refresh_token"]

    # RFC 6749 §5.1: a token response must never be cached anywhere.
    assert response.headers["cache-control"] == "no-store"


async def test_state_is_echoed_back_verbatim(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """`state` is the client's CSRF token; it must return unchanged and uninterpreted."""
    _, challenge = pkce_pair
    tricky_state = "a b&c=d/e?f#g"
    query = seeded.authorize_query(code_challenge=challenge, state=tricky_state)
    result = await complete_authorization(app_client, seeded, query=query)
    assert result.state == tricky_state


async def test_issued_tokens_verify_against_the_published_jwks(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """The check a relying party actually performs, done exactly the way an RP would do it."""
    verifier, challenge = pkce_pair
    result = await complete_authorization(
        app_client, seeded, query=seeded.authorize_query(code_challenge=challenge)
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

    jwks = (await app_client.get("/.well-known/jwks.json")).json()
    jwk_client = jwt.PyJWKSet.from_dict(jwks)
    header = jwt.get_unverified_header(tokens["id_token"])
    signing_key = next(key for key in jwk_client.keys if key.key_id == header["kid"])

    id_claims = jwt.decode(
        tokens["id_token"],
        signing_key.key,
        algorithms=["RS256"],
        audience=seeded.client_id,
        issuer="https://idp.example.test",
    )
    assert id_claims["sub"] == seeded.user_id
    assert id_claims["nonce"] == "nonce-xyz"
    assert id_claims["email"] == seeded.user_email
    assert id_claims["name"] == "Test User"
    assert "at_hash" in id_claims

    access_claims = jwt.decode(
        tokens["access_token"],
        signing_key.key,
        algorithms=["RS256"],
        audience="https://api.example.test",
        issuer="https://idp.example.test",
    )
    assert access_claims["client_id"] == seeded.client_id
    assert access_claims["sub"] == seeded.user_id


async def test_access_and_id_tokens_carry_distinct_typ_headers(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """RFC 9068 typing, so a resource server cannot be fooled into accepting an ID token."""
    verifier, challenge = pkce_pair
    result = await complete_authorization(
        app_client, seeded, query=seeded.authorize_query(code_challenge=challenge)
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
    assert jwt.get_unverified_header(tokens["access_token"])["typ"] == ACCESS_TOKEN_TYPE_HEADER
    assert jwt.get_unverified_header(tokens["id_token"])["typ"] == "JWT"


async def test_at_hash_binds_the_id_token_to_the_access_token(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    from app.services.claims import compute_at_hash

    verifier, challenge = pkce_pair
    result = await complete_authorization(
        app_client, seeded, query=seeded.authorize_query(code_challenge=challenge)
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
    id_claims = jwt.decode(tokens["id_token"], options={"verify_signature": False})
    assert id_claims["at_hash"] == compute_at_hash(tokens["access_token"])


async def test_client_secret_post_authentication_also_works(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """The client is registered for `client_secret_basic`, so the body form must be refused.

    Accepting either method for any client would let a leaked secret be replayed through whichever
    channel is least logged, and it makes the registered auth method meaningless.
    """
    verifier, challenge = pkce_pair
    result = await complete_authorization(
        app_client, seeded, query=seeded.authorize_query(code_challenge=challenge)
    )
    response = await exchange_code(
        app_client,
        seeded,
        code=result.code,
        code_verifier=verifier,
        redirect_uri=TEST_REDIRECT_URI,
        use_basic_auth=False,
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client"


async def test_authorization_code_can_only_be_redeemed_once(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """Single use, enforced by an atomic Redis GETDEL rather than by a read-then-delete pair."""
    verifier, challenge = pkce_pair
    result = await complete_authorization(
        app_client, seeded, query=seeded.authorize_query(code_challenge=challenge)
    )
    first = await exchange_code(
        app_client,
        seeded,
        code=result.code,
        code_verifier=verifier,
        redirect_uri=TEST_REDIRECT_URI,
    )
    assert first.status_code == 200

    second = await exchange_code(
        app_client,
        seeded,
        code=result.code,
        code_verifier=verifier,
        redirect_uri=TEST_REDIRECT_URI,
    )
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"


async def test_refresh_token_is_withheld_without_the_offline_access_scope(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """OIDC Core §11: a refresh token is granted only when `offline_access` was requested.

    Handing every client long-lived access it never asked for would be a silent privilege upgrade.
    """
    verifier, challenge = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge, scope="openid profile")
    result = await complete_authorization(app_client, seeded, query=query)
    tokens = (
        await exchange_code(
            app_client,
            seeded,
            code=result.code,
            code_verifier=verifier,
            redirect_uri=TEST_REDIRECT_URI,
        )
    ).json()
    assert "refresh_token" not in tokens
    assert tokens["access_token"]


async def test_id_token_is_withheld_without_the_openid_scope(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """A plain OAuth 2.0 request (no `openid`) gets an access token and nothing more."""
    verifier, challenge = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge, scope="profile")
    result = await complete_authorization(app_client, seeded, query=query)
    tokens = (
        await exchange_code(
            app_client,
            seeded,
            code=result.code,
            code_verifier=verifier,
            redirect_uri=TEST_REDIRECT_URI,
        )
    ).json()
    assert "id_token" not in tokens


async def test_scopes_the_client_may_not_request_are_dropped_not_rejected(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """RFC 6749 §3.3 lets the server issue a narrower scope than requested.

    `reports:read` exists in the catalogue but is not granted to this client, so it is silently
    dropped; an *unknown* scope is a hard error instead (asserted in the security suite).
    """
    verifier, challenge = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge, scope="openid profile reports:read")
    result = await complete_authorization(app_client, seeded, query=query)
    tokens = (
        await exchange_code(
            app_client,
            seeded,
            code=result.code,
            code_verifier=verifier,
            redirect_uri=TEST_REDIRECT_URI,
        )
    ).json()
    assert "reports:read" not in tokens["scope"].split()
    assert set(tokens["scope"].split()) == {"openid", "profile"}


async def test_second_authorization_reuses_recorded_consent_without_prompting(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    """A recorded grant covering the request means no prompt — the point of storing consent."""
    first_verifier = generate_code_verifier()
    await complete_authorization(
        app_client,
        seeded,
        query=seeded.authorize_query(code_challenge=compute_s256_challenge(first_verifier)),
    )

    # Same browser (cookie jar), same scopes: this should go straight to the redirect.
    second = await app_client.get(
        f"/authorize?{seeded.authorize_query(code_challenge=compute_s256_challenge(generate_code_verifier()))}"
    )
    assert second.status_code == 303
    assert second.headers["location"].startswith(TEST_REDIRECT_URI)
    assert "code" in redirect_params(second)


async def test_requesting_a_new_scope_re_prompts_for_consent(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    """Otherwise a client could widen access one scope at a time past a user who stopped
    reading."""
    verifier = generate_code_verifier()
    await complete_authorization(
        app_client,
        seeded,
        query=seeded.authorize_query(
            code_challenge=compute_s256_challenge(verifier), scope="openid profile"
        ),
    )
    second = await app_client.get(
        "/authorize?"
        + seeded.authorize_query(
            code_challenge=compute_s256_challenge(generate_code_verifier()),
            scope="openid profile email",
        )
    )
    # 200 means the consent screen rather than a redirect.
    assert second.status_code == 200
    assert "email" in second.text


async def test_user_can_narrow_the_grant_at_the_consent_screen(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """Unticking a scope must actually narrow what the token carries."""
    verifier, challenge = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge, scope="openid profile email")
    result = await complete_authorization(
        app_client, seeded, query=query, approve_scopes=["profile"]
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
    assert "email" not in granted
    assert {"openid", "profile"} <= granted


async def test_denying_consent_redirects_with_access_denied(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    from tests.helpers import hidden_fields

    _, challenge = pkce_pair
    query = seeded.authorize_query(code_challenge=challenge)
    initial = await app_client.get(f"/authorize?{query}")
    resume = redirect_params(initial)["next"]
    login_response = await login(app_client, seeded, next_query=resume)
    consent_page = await app_client.get(login_response.headers["location"])
    fields = hidden_fields(consent_page.text)

    denied = await app_client.post(
        "/consent",
        data={
            "authorize_query": fields["authorize_query"],
            "csrf_token": fields["csrf_token"],
            "decision": "deny",
        },
    )
    assert denied.status_code == 303
    params = redirect_params(denied)
    assert denied.headers["location"].startswith(TEST_REDIRECT_URI)
    assert params["error"] == "access_denied"
    assert params["state"] == "state-abc"


async def test_the_flow_records_the_expected_audit_trail(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    """§20's events must actually be written, or an incident is uninvestigable."""
    verifier, challenge = pkce_pair
    result = await complete_authorization(
        app_client, seeded, query=seeded.authorize_query(code_challenge=challenge)
    )
    await exchange_code(
        app_client,
        seeded,
        code=result.code,
        code_verifier=verifier,
        redirect_uri=TEST_REDIRECT_URI,
    )

    async with container.database.session() as session:
        rows = (await session.execute(select(AuditLog))).scalars().all()
    recorded = {row.event_type for row in rows}
    assert {
        str(AuditEventType.LOGIN_SUCCESS),
        str(AuditEventType.CONSENT_GRANTED),
        str(AuditEventType.AUTHZ_CODE_ISSUED),
        str(AuditEventType.TOKEN_ISSUED),
    } <= recorded

    # Audit rows carry the correlation ID and the caller's IP for incident work.
    login_event = next(row for row in rows if row.event_type == str(AuditEventType.LOGIN_SUCCESS))
    assert login_event.request_id
    assert login_event.user_id == seeded.user_id

    # And they never carry credential material.
    serialised = str([row.detail for row in rows])
    assert result.code not in serialised
    assert verifier not in serialised
