"""Discovery, JWKS and signing-key rotation (§8D, §11).

The rotation tests are the important half: they assert that a key change never invalidates a token
that was already issued, which is the property that makes rotation safe to automate.
"""

from __future__ import annotations

import base64

import jwt
import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.container import Container
from app.models.signing_key import KeyStatus, SigningKey
from tests.conftest import Seeded
from tests.helpers import full_flow_tokens

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------- discovery
async def test_discovery_document_advertises_the_required_metadata(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    response = await app_client.get("/.well-known/openid-configuration")
    assert response.status_code == 200
    document = response.json()

    # RFC 8414 §2 / OIDC Discovery §3 required fields.
    for field in (
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
    ):
        assert document[field], f"{field} must be present in the discovery document"

    assert document["issuer"] == "https://idp.example.test"
    assert document["token_endpoint"] == "https://idp.example.test/token"
    assert document["jwks_uri"] == "https://idp.example.test/.well-known/jwks.json"
    assert document["id_token_signing_alg_values_supported"] == ["RS256"]


async def test_discovery_advertises_pkce_support(app_client: AsyncClient) -> None:
    """Omitting this field pushes a conforming client into not using PKCE at all."""
    document = (await app_client.get("/.well-known/openid-configuration")).json()
    assert document["code_challenge_methods_supported"] == ["S256"]
    assert "plain" not in document["code_challenge_methods_supported"]


async def test_discovery_advertises_only_the_flows_that_exist(app_client: AsyncClient) -> None:
    """Advertising a capability that is not implemented is worse than omitting it: a client will
    choose it and fail in a way that looks like a server bug."""
    document = (await app_client.get("/.well-known/openid-configuration")).json()
    assert document["response_types_supported"] == ["code"]
    assert document["response_modes_supported"] == ["query"]
    assert set(document["grant_types_supported"]) == {"authorization_code", "refresh_token"}
    assert document["claims_parameter_supported"] is False
    assert document["request_parameter_supported"] is False


async def test_discovery_lists_the_actual_scope_catalogue(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    document = (await app_client.get("/.well-known/openid-configuration")).json()
    assert {"openid", "profile", "email", "offline_access"} <= set(document["scopes_supported"])


async def test_discovery_is_cacheable(app_client: AsyncClient) -> None:
    response = await app_client.get("/.well-known/openid-configuration")
    assert "max-age" in response.headers["cache-control"]


# ---------------------------------------------------------------------------- JWKS
async def test_jwks_publishes_only_public_key_material(app_client: AsyncClient) -> None:
    response = await app_client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    keys = response.json()["keys"]
    assert keys

    for key in keys:
        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert key["alg"] == "RS256"
        assert key["kid"]
        # The private half would be a total compromise of the signing key.
        assert set(key) == {"kty", "use", "alg", "kid", "n", "e"}
        assert not {"d", "p", "q", "dp", "dq", "qi"} & set(key)


async def test_published_modulus_is_a_valid_2048_bit_key(app_client: AsyncClient) -> None:
    key = (await app_client.get("/.well-known/jwks.json")).json()["keys"][0]
    modulus = base64.urlsafe_b64decode(key["n"] + "=" * (-len(key["n"]) % 4))
    assert len(modulus) == 256
    assert modulus[0] != 0, "Base64urlUInt must be minimum-length (RFC 7518 §2)"


async def test_jwks_is_usable_by_a_standard_client_library(app_client: AsyncClient) -> None:
    """Parsed by PyJWT's own JWKS handling, so the response is proven interoperable rather than just
    structurally plausible."""
    jwks = (await app_client.get("/.well-known/jwks.json")).json()
    key_set = jwt.PyJWKSet.from_dict(jwks)
    assert key_set.keys


# ---------------------------------------------------------------------------- rotation
async def test_rotation_creates_a_new_current_key_and_retires_the_previous_one(
    app_client: AsyncClient, container: Container
) -> None:
    original = (await app_client.get("/.well-known/jwks.json")).json()["keys"][0]["kid"]
    new_kid = await container.keys.rotate(reason="test")
    assert new_kid != original

    async with container.database.session() as session:
        rows = {
            row.kid: row.status
            for row in (await session.execute(select(SigningKey))).scalars().all()
        }
    assert rows[new_kid] == str(KeyStatus.CURRENT)
    assert rows[original] == str(KeyStatus.RETIRING)


async def test_both_current_and_retiring_keys_stay_in_jwks(
    app_client: AsyncClient, container: Container
) -> None:
    """The grace period is what makes rotation non-disruptive: a token signed a millisecond
    before the rotation must still verify for its entire lifetime."""
    original = (await app_client.get("/.well-known/jwks.json")).json()["keys"][0]["kid"]
    new_kid = await container.keys.rotate(reason="test")

    jwks = (await app_client.get("/.well-known/jwks.json")).json()["keys"]
    published = {key["kid"] for key in jwks}
    assert published == {original, new_kid}


async def test_a_token_issued_before_rotation_still_verifies_after_it(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    """The single most important rotation property, asserted end to end through /userinfo."""
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    before = await app_client.get(
        "/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert before.status_code == 200

    await container.keys.rotate(reason="test")

    after = await app_client.get(
        "/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert after.status_code == 200, "rotation must not invalidate already-issued tokens"


async def test_new_tokens_are_signed_by_the_new_key_after_rotation(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    first = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    original_kid = jwt.get_unverified_header(first["access_token"])["kid"]

    new_kid = await container.keys.rotate(reason="test")

    # A refresh is the cheapest way to obtain a freshly signed token set.
    refreshed = await app_client.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"]},
        auth=(seeded.client_id, seeded.client_secret),
    )
    assert refreshed.status_code == 200
    header = jwt.get_unverified_header(refreshed.json()["access_token"])
    assert header["kid"] == new_kid != original_kid


async def test_a_swept_retired_key_leaves_jwks(
    app_client: AsyncClient, container: Container
) -> None:
    """After the grace period a key must disappear, or JWKS grows without bound and a
    compromised old key would keep verifying forever."""
    from datetime import UTC, datetime, timedelta

    from app.repositories.signing_key_repository import SigningKeyRepository

    original = (await app_client.get("/.well-known/jwks.json")).json()["keys"][0]["kid"]
    await container.keys.rotate(reason="test")

    # Bring the grace period's end forward rather than waiting an hour for it.
    async with container.database.session() as session:
        await SigningKeyRepository(session).mark_retiring(
            kid=original, retire_after=datetime.now(tz=UTC) - timedelta(seconds=1)
        )
    retired = await container.keys.sweep_retired_keys(destroy_private_material=False)
    assert original in retired

    jwks = (await app_client.get("/.well-known/jwks.json")).json()["keys"]
    published = {key["kid"] for key in jwks}
    assert original not in published


async def test_a_token_signed_by_a_swept_key_is_refused(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    from datetime import UTC, datetime, timedelta

    from app.repositories.signing_key_repository import SigningKeyRepository

    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    original = jwt.get_unverified_header(tokens["access_token"])["kid"]
    await container.keys.rotate(reason="test")

    async with container.database.session() as session:
        await SigningKeyRepository(session).mark_retiring(
            kid=original, retire_after=datetime.now(tz=UTC) - timedelta(seconds=1)
        )
    await container.keys.sweep_retired_keys(destroy_private_material=False)

    response = await app_client.get(
        "/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert response.status_code == 401


async def test_private_key_material_is_never_stored_in_postgres(
    container: Container,
) -> None:
    """§11's storage rule: the database holds public material and a *reference*, so a database dump
    cannot be used to mint tokens."""
    async with container.database.session() as session:
        rows = (await session.execute(select(SigningKey))).scalars().all()
    assert rows
    for row in rows:
        assert "PRIVATE KEY" not in row.public_pem
        assert "PRIVATE KEY" not in str(row.public_jwk)
        # The reference is a filename or a Secrets Manager name, not the key.
        assert "BEGIN" not in row.private_key_ref


async def test_key_initialisation_is_idempotent(container: Container) -> None:
    """Every task runs this at startup simultaneously; only one key should ever result."""
    first = await container.keys.ensure_initialized()
    second = await container.keys.ensure_initialized()
    assert first == second

    async with container.database.session() as session:
        current = [
            row
            for row in (await session.execute(select(SigningKey))).scalars().all()
            if row.status == str(KeyStatus.CURRENT)
        ]
    assert len(current) == 1
