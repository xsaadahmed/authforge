"""Refresh-token rotation, reuse detection and concurrency (§10, §23).

The concurrency test at the bottom is, per the specification, the single most important test in the
project: it proves that two simultaneous refreshes of the same token cannot both succeed, and that
the loser is routed into reuse detection. It runs two genuinely separate transactions against a real
Postgres, because the guarantee being tested belongs to Postgres's row locking under READ
COMMITTED — a mock would assert only that the code calls a method.
"""

from __future__ import annotations

import asyncio

import jwt
import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.container import Container
from app.models.audit import AuditEventType, AuditLog
from app.models.token import RefreshToken, RevocationReason
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.security.random_tokens import hash_token
from tests.conftest import Seeded
from tests.helpers import full_flow_tokens, refresh

pytestmark = pytest.mark.integration


async def test_refresh_issues_a_new_token_set(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)

    response = await refresh(app_client, seeded, refresh_token=tokens["refresh_token"])
    assert response.status_code == 200, response.text
    refreshed = response.json()
    assert refreshed["access_token"] != tokens["access_token"]
    assert refreshed["refresh_token"] != tokens["refresh_token"]
    assert refreshed["scope"] == tokens["scope"]


async def test_rotation_records_a_new_generation_in_the_same_family(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    refreshed = (await refresh(app_client, seeded, refresh_token=tokens["refresh_token"])).json()

    async with container.database.session() as session:
        rows = (
            (await session.execute(select(RefreshToken).order_by(RefreshToken.generation)))
            .scalars()
            .all()
        )
    assert len(rows) == 2
    first, second = rows
    assert first.family_id == second.family_id
    assert (first.generation, second.generation) == (0, 1)
    assert second.previous_token_hash == first.token_hash
    assert first.used_at is not None, "the presented token must be spent"
    assert second.used_at is None, "the newly issued token must be redeemable"
    assert second.token_hash == hash_token(refreshed["refresh_token"])


async def test_only_hashes_of_refresh_tokens_are_stored(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    """A database disclosure must not yield usable refresh tokens."""
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    async with container.database.session() as session:
        rows = (await session.execute(select(RefreshToken))).scalars().all()
    stored = {row.token_hash for row in rows}
    assert tokens["refresh_token"] not in stored
    assert hash_token(tokens["refresh_token"]) in stored


async def test_rotated_token_inherits_the_family_expiry_rather_than_extending_it(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    """Absolute family lifetime (docs/adr/0003).

    A sliding expiry would let an attacker who steals a token keep refreshing it indefinitely; an
    absolute one bounds the compromise window to a value the operator chose up front.
    """
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    await refresh(app_client, seeded, refresh_token=tokens["refresh_token"])
    async with container.database.session() as session:
        rows = (
            (await session.execute(select(RefreshToken).order_by(RefreshToken.generation)))
            .scalars()
            .all()
        )
    assert rows[0].expires_at == rows[1].expires_at


async def test_auth_time_survives_rotation(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """A refreshed ID token must report when the user authenticated, not when it was minted.

    Relying parties use `auth_time` with `max_age` to decide whether to force a re-login; resetting
    it on every refresh would make a months-old session look brand new.
    """
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    original = jwt.decode(tokens["id_token"], options={"verify_signature": False})
    refreshed_tokens = (
        await refresh(app_client, seeded, refresh_token=tokens["refresh_token"])
    ).json()
    refreshed = jwt.decode(refreshed_tokens["id_token"], options={"verify_signature": False})
    assert refreshed["auth_time"] == original["auth_time"]
    assert refreshed["iat"] >= original["iat"]


async def test_refreshed_id_token_carries_no_nonce(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """OIDC Core §12.2. A nonce belongs to one authentication event; echoing it into a token issued
    later would let a client's replay check pass for a request it never made."""
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    refreshed = (await refresh(app_client, seeded, refresh_token=tokens["refresh_token"])).json()
    assert "nonce" not in jwt.decode(refreshed["id_token"], options={"verify_signature": False})


async def test_a_chain_of_refreshes_all_succeed(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    current = tokens["refresh_token"]
    for expected_generation in range(1, 6):
        response = await refresh(app_client, seeded, refresh_token=current)
        assert response.status_code == 200, (expected_generation, response.text)
        current = response.json()["refresh_token"]


# --------------------------------------------------------------------------- reuse detection
async def test_reusing_a_spent_token_revokes_the_entire_family(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    """The core theft response.

    Presenting a token whose `used_at` is already set means the raw value existed in two places.
    Rejecting only the replayed token would leave the thief's copy working, so the whole family dies
    and the user must re-authenticate.
    """
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    stolen = tokens["refresh_token"]

    legitimate = (await refresh(app_client, seeded, refresh_token=stolen)).json()
    assert legitimate["refresh_token"]

    replay = await refresh(app_client, seeded, refresh_token=stolen)
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"

    # The token the legitimate client is now holding is dead too — that is the point.
    followup = await refresh(app_client, seeded, refresh_token=legitimate["refresh_token"])
    assert followup.status_code == 400

    async with container.database.session() as session:
        rows = (await session.execute(select(RefreshToken))).scalars().all()
    assert rows, "expected refresh token rows to exist"
    assert all(row.revoked for row in rows)
    assert all(row.revocation_reason == str(RevocationReason.REUSE_DETECTED) for row in rows)


async def test_reuse_detection_emits_the_audit_event_used_for_alarming(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    """§20 lists a spike in this event as an alarm-worthy signal of token theft in progress."""
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    await refresh(app_client, seeded, refresh_token=tokens["refresh_token"])
    await refresh(app_client, seeded, refresh_token=tokens["refresh_token"])

    async with container.database.session() as session:
        events = (
            (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.event_type == str(AuditEventType.REFRESH_REUSE_DETECTED)
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(events) == 1
    event = events[0]
    assert event.success is False
    assert event.user_id == seeded.user_id
    assert event.client_id == seeded.client_id
    assert event.detail["tokens_revoked"] >= 2
    assert "family_id" in event.detail
    # Identifiers only: no raw token anywhere in the record.
    assert tokens["refresh_token"] not in str(event.detail)


async def test_an_entirely_unknown_refresh_token_is_rejected(
    app_client: AsyncClient, seeded: Seeded
) -> None:
    response = await refresh(app_client, seeded, refresh_token="not-a-real-token")
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


async def test_a_revoked_family_cannot_be_refreshed(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    async with container.database.session() as session:
        row = await RefreshTokenRepository(session).get_by_hash(hash_token(tokens["refresh_token"]))
        assert row is not None
        await RefreshTokenRepository(session).revoke_family(
            row.family_id, reason=RevocationReason.ADMIN_ACTION
        )

    response = await refresh(app_client, seeded, refresh_token=tokens["refresh_token"])
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


# --------------------------------------------------------------------------- scope narrowing
async def test_refresh_may_narrow_the_scope(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """RFC 6749 §6 permits a narrower scope on refresh."""
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    response = await refresh(
        app_client, seeded, refresh_token=tokens["refresh_token"], scope="openid profile"
    )
    assert response.status_code == 200, response.text
    assert set(response.json()["scope"].split()) == {"openid", "profile"}


async def test_refresh_may_not_widen_the_scope(
    app_client: AsyncClient, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """Privilege escalation via refresh.

    If a token granted `openid profile` could refresh into `email`, the consent screen would be
    advisory rather than binding.
    """
    verifier, challenge = pkce_pair
    tokens = await full_flow_tokens(
        app_client, seeded, pkce_pair=(verifier, challenge), scope="openid offline_access"
    )
    response = await refresh(
        app_client,
        seeded,
        refresh_token=tokens["refresh_token"],
        scope="openid email offline_access",
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"


# --------------------------------------------------------------------------- concurrency
async def test_two_concurrent_refreshes_of_the_same_token_yield_exactly_one_success(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    """The specification's most important test (§23).

    Both requests race the same atomic statement:

        UPDATE refresh_tokens SET used_at = now()
         WHERE token_hash = :h AND client_id = :c AND used_at IS NULL AND revoked = false
        RETURNING *

    Under READ COMMITTED the second transaction blocks on the row lock, then re-evaluates its WHERE
    clause against the committed update, matches nothing, and updates zero rows. So exactly one
    caller can mint tokens. The loser is indistinguishable from a replay — which is intentional, and
    the pessimistic reading is the safe one — so the family is revoked and re-authentication is
    required.
    """
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    token = tokens["refresh_token"]

    first, second = await asyncio.gather(
        refresh(app_client, seeded, refresh_token=token),
        refresh(app_client, seeded, refresh_token=token),
        return_exceptions=False,
    )

    statuses = sorted([first.status_code, second.status_code])
    assert statuses == [200, 400], (first.status_code, first.text, second.status_code, second.text)

    winner = first if first.status_code == 200 else second
    loser = second if first.status_code == 200 else first
    assert winner.json()["refresh_token"] != token
    assert loser.json()["error"] == "invalid_grant"

    async with container.database.session() as session:
        rows = (await session.execute(select(RefreshToken))).scalars().all()
        reuse_events = (
            (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.event_type == str(AuditEventType.REFRESH_REUSE_DETECTED)
                    )
                )
            )
            .scalars()
            .all()
        )

    # Exactly one rotation happened: two rows, not three.
    assert len(rows) == 2
    # And the ambiguous loser was treated as reuse, so the family is closed.
    assert len(reuse_events) == 1
    assert all(row.revoked for row in rows)


async def test_ten_concurrent_refreshes_still_yield_exactly_one_success(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    """Scaled up, because a two-way race can pass by luck while a ten-way race cannot."""
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    token = tokens["refresh_token"]

    responses = await asyncio.gather(
        *[refresh(app_client, seeded, refresh_token=token) for _ in range(10)]
    )
    successes = [response for response in responses if response.status_code == 200]
    failures = [response for response in responses if response.status_code != 200]

    assert len(successes) == 1, [response.status_code for response in responses]
    assert len(failures) == 9
    assert all(response.json()["error"] == "invalid_grant" for response in failures)

    async with container.database.session() as session:
        rows = (await session.execute(select(RefreshToken))).scalars().all()
    assert len(rows) == 2, "exactly one new generation should have been created"


async def test_the_atomic_claim_is_bound_to_the_owning_client(
    app_client: AsyncClient, seeded: Seeded, container: Container, pkce_pair: tuple[str, str]
) -> None:
    """A second client presenting someone else's refresh token must not even spend it.

    If the client check happened *after* the claim, any registered client could stamp `used_at` on a
    token it does not own, destroying a token the rightful owner still needed and tripping reuse
    detection on their next refresh — a denial-of-service primitive available to every client.
    """
    from app.models.client import ClientType

    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    async with container.database.session() as session:
        other = await container.clients.register_client(
            session,
            client_name="Other Client",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=["https://other.example.test/callback"],
            allowed_scopes=["openid", "offline_access"],
            client_id="other-client",
        )
        other_secret = other.client_secret or ""

    stolen_attempt = await app_client.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]},
        auth=("other-client", other_secret),
    )
    assert stolen_attempt.status_code == 400
    assert stolen_attempt.json()["error"] == "invalid_grant"

    # The rightful owner's token is untouched and still works.
    legitimate = await refresh(app_client, seeded, refresh_token=tokens["refresh_token"])
    assert legitimate.status_code == 200, legitimate.text
