"""Database constraint and Redis behaviour tests (§23).

These assert the guarantees the design *delegates* to Postgres and Redis rather than implements in
Python. A unique constraint, a partial index, a TTL and the atomicity of ``GETDEL`` are all load-bearing
here, and each is only real if the engine actually provides it.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.container import Container
from app.models.client import ClientRedirectUri, ClientType
from app.models.consent import Consent
from app.models.token import RefreshToken, RevocationReason
from app.models.user import RecoveryCode
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.user_repository import UserRepository, normalize_email
from app.security.random_tokens import hash_token, new_opaque_token
from app.stores.auth_code_store import AuthorizationCodePayload
from tests.conftest import Seeded

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------- Postgres constraints
async def test_email_uniqueness_is_enforced_by_the_database(
    container: Container, seeded: Seeded
) -> None:
    """Enforced in the schema, not only in application code: two concurrent signups can both pass an
    application-level "does this email exist" check, and only a constraint stops both committing."""
    with pytest.raises(IntegrityError):
        async with container.database.session() as session:
            await UserRepository(session).create(
                email=seeded.user_email, password_hash="irrelevant"
            )


async def test_email_normalisation_prevents_case_variant_duplicates(
    container: Container, seeded: Seeded
) -> None:
    """Without folding, `User@Example.test` and `user@example.test` would be two accounts for one
    human — a support burden and a genuine source of confusion during an incident."""
    assert normalize_email("  User@Example.TEST ") == "user@example.test"
    with pytest.raises(IntegrityError):
        async with container.database.session() as session:
            await UserRepository(session).create(
                email="USER@EXAMPLE.TEST", password_hash="irrelevant"
            )


async def test_refresh_token_hash_is_unique(container: Container, seeded: Seeded) -> None:
    shared_hash = hash_token(new_opaque_token())
    common = {
        "family_id": "01FAMILY",
        "generation": 0,
        "previous_token_hash": None,
        "user_id": seeded.user_id,
        "client_id": seeded.client_internal_id,
        "scopes": ["openid"],
        "auth_time": datetime.now(tz=UTC),
        "expires_at": datetime.now(tz=UTC) + timedelta(days=1),
    }
    async with container.database.session() as session:
        await RefreshTokenRepository(session).create(token_hash=shared_hash, **common)

    with pytest.raises(IntegrityError):
        async with container.database.session() as session:
            await RefreshTokenRepository(session).create(token_hash=shared_hash, **common)


async def test_one_consent_row_per_user_and_client(container: Container, seeded: Seeded) -> None:
    from app.repositories.consent_repository import ConsentRepository

    async with container.database.session() as session:
        await ConsentRepository(session).grant(
            user_id=seeded.user_id,
            client_id=seeded.client_internal_id,
            granted_scopes=["openid"],
            considered_scopes=["openid"],
        )
    async with container.database.session() as session:
        # The upsert must update rather than insert a second row.
        await ConsentRepository(session).grant(
            user_id=seeded.user_id,
            client_id=seeded.client_internal_id,
            granted_scopes=["openid", "profile"],
            considered_scopes=["openid", "profile"],
        )
    async with container.database.session() as session:
        rows = (await session.execute(select(Consent))).scalars().all()
    assert len(rows) == 1
    assert set(rows[0].granted_scopes) == {"openid", "profile"}


async def test_a_client_cannot_register_the_same_redirect_uri_twice(
    container: Container, seeded: Seeded
) -> None:
    async with container.database.session() as session:
        rows = (
            (
                await session.execute(
                    select(ClientRedirectUri).where(
                        ClientRedirectUri.client_id == seeded.client_internal_id
                    )
                )
            )
            .scalars()
            .all()
        )
        existing = rows[0].uri

    with pytest.raises(IntegrityError):
        async with container.database.session() as session:
            session.add(
                ClientRedirectUri(client_id=seeded.client_internal_id, uri=existing)
            )
            await session.flush()


async def test_deleting_a_user_cascades_to_their_tokens_and_consents(
    container: Container, seeded: Seeded
) -> None:
    """A deleted account must not leave live refresh tokens behind, which is what ON DELETE CASCADE
    guarantees even for a path that forgets to clean up."""
    from app.repositories.consent_repository import ConsentRepository

    async with container.database.session() as session:
        await RefreshTokenRepository(session).create(
            token_hash=hash_token(new_opaque_token()),
            family_id="01FAMILY",
            generation=0,
            previous_token_hash=None,
            user_id=seeded.user_id,
            client_id=seeded.client_internal_id,
            scopes=["openid"],
            auth_time=datetime.now(tz=UTC),
            expires_at=datetime.now(tz=UTC) + timedelta(days=1),
        )
        await ConsentRepository(session).grant(
            user_id=seeded.user_id,
            client_id=seeded.client_internal_id,
            granted_scopes=["openid"],
            considered_scopes=["openid"],
        )
        session.add(RecoveryCode(user_id=seeded.user_id, code_hash=hash_token("code")))

    async with container.database.session() as session:
        user = await UserRepository(session).get_by_id(seeded.user_id)
        assert user is not None
        await session.delete(user)

    async with container.database.session() as session:
        assert (await session.execute(select(RefreshToken))).scalars().all() == []
        assert (await session.execute(select(Consent))).scalars().all() == []
        assert (await session.execute(select(RecoveryCode))).scalars().all() == []


async def test_the_partial_index_on_active_refresh_tokens_has_the_intended_predicate(
    container: Container,
) -> None:
    """The hot path is "find this hash if it is still redeemable", so the index covers only live rows.

    Spent generations accumulate for forensics without inflating the index the refresh endpoint uses.
    """
    async with container.database.session() as session:
        definition = (
            await session.execute(
                text(
                    "SELECT indexdef FROM pg_indexes "
                    "WHERE tablename = 'refresh_tokens' AND indexname = 'ix_refresh_tokens_active'"
                )
            )
        ).scalar_one()
    assert "token_hash" in definition
    assert "WHERE" in definition.upper()
    assert "used_at IS NULL" in definition
    assert "revoked = false" in definition


async def test_the_partial_index_is_usable_for_the_refresh_lookup(
    container: Container, seeded: Seeded
) -> None:
    """Asserted by disabling sequential scans rather than by inserting enough rows to sway the planner.

    On a small table Postgres will correctly prefer a sequential scan whatever indexes exist, so a
    plain EXPLAIN would test the row count rather than the index. Forcing the planner's hand proves the
    index actually *covers* this predicate — which is what a future schema change could silently break.
    """
    async with container.database.session() as session:
        for index in range(20):
            await RefreshTokenRepository(session).create(
                token_hash=hash_token(f"token-{index}"),
                family_id=f"01FAMILY{index}",
                generation=0,
                previous_token_hash=None,
                user_id=seeded.user_id,
                client_id=seeded.client_internal_id,
                scopes=["openid"],
                auth_time=datetime.now(tz=UTC),
                expires_at=datetime.now(tz=UTC) + timedelta(days=1),
            )

    async with container.database.session() as session:
        await session.execute(text("ANALYZE refresh_tokens"))
        await session.execute(text("SET LOCAL enable_seqscan = off"))
        plan = (
            await session.execute(
                text(
                    "EXPLAIN SELECT * FROM refresh_tokens "
                    "WHERE token_hash = :hash AND used_at IS NULL AND revoked = false"
                ),
                {"hash": hash_token("token-7")},
            )
        ).scalars()
        rendered = "\n".join(str(line) for line in plan)
    assert "ix_refresh_tokens_active" in rendered, rendered


async def test_family_revocation_touches_every_generation(
    container: Container, seeded: Seeded
) -> None:
    async with container.database.session() as session:
        repository = RefreshTokenRepository(session)
        for generation in range(4):
            await repository.create(
                token_hash=hash_token(f"gen-{generation}"),
                family_id="01SHAREDFAMILY",
                generation=generation,
                previous_token_hash=None,
                user_id=seeded.user_id,
                client_id=seeded.client_internal_id,
                scopes=["openid"],
                auth_time=datetime.now(tz=UTC),
                expires_at=datetime.now(tz=UTC) + timedelta(days=1),
            )

    async with container.database.session() as session:
        count = await RefreshTokenRepository(session).revoke_family(
            "01SHAREDFAMILY", reason=RevocationReason.REUSE_DETECTED
        )
    assert count == 4

    async with container.database.session() as session:
        rows = await RefreshTokenRepository(session).list_family("01SHAREDFAMILY")
    assert all(row.revoked for row in rows)
    assert all(row.revocation_reason == "reuse_detected" for row in rows)


async def test_expired_token_cleanup_leaves_live_tokens_alone(
    container: Container, seeded: Seeded
) -> None:
    async with container.database.session() as session:
        repository = RefreshTokenRepository(session)
        await repository.create(
            token_hash=hash_token("stale"),
            family_id="01OLD",
            generation=0,
            previous_token_hash=None,
            user_id=seeded.user_id,
            client_id=seeded.client_internal_id,
            scopes=["openid"],
            auth_time=datetime.now(tz=UTC) - timedelta(days=90),
            expires_at=datetime.now(tz=UTC) - timedelta(days=60),
        )
        await repository.create(
            token_hash=hash_token("live"),
            family_id="01NEW",
            generation=0,
            previous_token_hash=None,
            user_id=seeded.user_id,
            client_id=seeded.client_internal_id,
            scopes=["openid"],
            auth_time=datetime.now(tz=UTC),
            expires_at=datetime.now(tz=UTC) + timedelta(days=30),
        )

    async with container.database.session() as session:
        removed = await RefreshTokenRepository(session).delete_expired(
            older_than=datetime.now(tz=UTC) - timedelta(days=30)
        )
    assert removed == 1

    async with container.database.session() as session:
        remaining = (await session.execute(select(RefreshToken))).scalars().all()
    assert [row.token_hash for row in remaining] == [hash_token("live")]


# ---------------------------------------------------------------------------- Redis behaviour
def _payload(client_id: str, user_id: str) -> AuthorizationCodePayload:
    return AuthorizationCodePayload(
        client_id=client_id,
        user_id=user_id,
        redirect_uri="https://rp.example.test/callback",
        scopes=["openid"],
        code_challenge="x" * 43,
        code_challenge_method="S256",
        nonce=None,
        auth_time=int(datetime.now(tz=UTC).timestamp()),
        session_id=None,
        issued_at=int(datetime.now(tz=UTC).timestamp()),
    )


async def test_authorization_code_redemption_is_atomic_under_concurrency(
    container: Container, seeded: Seeded
) -> None:
    """``GETDEL`` in one round trip.

    A read-then-delete pair leaves a window in which two concurrent exchanges both read the payload
    and both mint tokens. Fifty simultaneous attempts must yield exactly one payload.
    """
    code = await container.auth_codes.issue(_payload(seeded.client_id, seeded.user_id))
    results = await asyncio.gather(*[container.auth_codes.redeem(code) for _ in range(50)])
    assert sum(1 for result in results if result is not None) == 1


async def test_authorization_code_key_carries_a_ttl(container: Container, seeded: Seeded) -> None:
    """Expiry is delegated to Redis, so an unredeemed code dies without any sweeper running."""
    code = await container.auth_codes.issue(_payload(seeded.client_id, seeded.user_id))
    key = f"authz_code:{hash_token(code)}"
    ttl = await container.redis.client.ttl(key)
    assert 0 < ttl <= container.settings.authorization_code_ttl_seconds


async def test_an_expired_authorization_code_key_cannot_be_redeemed(
    container: Container, seeded: Seeded
) -> None:
    """Drives the TTL to a real one-second expiry rather than simulating it, so the behaviour being
    relied on is the engine's own."""
    code = await container.auth_codes.issue(_payload(seeded.client_id, seeded.user_id))
    await container.redis.client.expire(f"authz_code:{hash_token(code)}", 1)
    await asyncio.sleep(1.2)
    assert await container.auth_codes.redeem(code) is None


async def test_the_raw_authorization_code_never_appears_in_redis(
    container: Container, seeded: Seeded
) -> None:
    """A Redis dump, MONITOR session or slowlog must not yield a redeemable code."""
    code = await container.auth_codes.issue(_payload(seeded.client_id, seeded.user_id))
    keys = [str(key) async for key in container.redis.client.scan_iter(match="authz_code:*")]
    assert keys
    assert all(code not in key for key in keys)


async def test_the_raw_session_id_never_appears_in_redis(container: Container) -> None:
    from app.stores.session_store import SessionState

    session_id = await container.sessions.create(
        SessionState(user_id="01USER", auth_time=0, mfa_verified=False, created_at=0)
    )
    keys = [str(key) async for key in container.redis.client.scan_iter(match="session:*")]
    assert keys
    assert all(session_id not in key for key in keys)


async def test_session_replacement_preserves_the_remaining_ttl(container: Container) -> None:
    """Refreshing the expiry on every request would silently turn a bounded session into an indefinite
    one."""
    from app.stores.session_store import SessionState

    session_id = await container.sessions.create(
        SessionState(user_id="01USER", auth_time=0, mfa_verified=False, created_at=0)
    )
    await container.redis.client.expire(
        f"session:{hash_token(session_id)}", 120
    )
    state = await container.sessions.get(session_id)
    assert state is not None
    state.mfa_verified = True
    await container.sessions.replace(session_id, state)

    ttl = await container.sessions.ttl(session_id)
    assert 0 < ttl <= 120


async def test_session_rotation_destroys_the_previous_identifier(container: Container) -> None:
    from app.stores.session_store import SessionState

    state = SessionState(user_id="01USER", auth_time=0, mfa_verified=False, created_at=0)
    original = await container.sessions.create(state)
    rotated = await container.sessions.rotate(original, state)

    assert rotated != original
    assert await container.sessions.get(original) is None
    assert await container.sessions.get(rotated) is not None


async def test_a_totp_code_can_be_claimed_only_once_even_under_concurrency(
    container: Container,
) -> None:
    """``SET NX``, so an attacker replaying an observed code against several tasks at once still only
    gets one acceptance."""
    key = "totp_used:01USER:abc"
    results = await asyncio.gather(
        *[container.sessions.mark_totp_code_used(key, ttl_seconds=90) for _ in range(20)]
    )
    assert sum(1 for claimed in results if claimed) == 1


# ---------------------------------------------------------------------------- rate limiter
async def test_the_sliding_window_admits_up_to_the_limit_then_blocks(
    container: Container,
) -> None:
    from app.stores.rate_limit_store import RateLimitStore

    store = RateLimitStore(container.redis.client)
    verdicts = [
        await store.consume(key="test:window", limit=3, window_seconds=60) for _ in range(5)
    ]
    assert [verdict.allowed for verdict in verdicts] == [True, True, True, False, False]
    assert verdicts[-1].retry_after_seconds > 0


async def test_the_sliding_window_is_atomic_under_concurrency(container: Container) -> None:
    """Prune, count, decide and record happen in one Lua script.

    Separate commands let N concurrent callers each observe ``count == limit - 1`` and all admit,
    which is exactly the case a limiter exists to prevent.
    """
    from app.stores.rate_limit_store import RateLimitStore

    store = RateLimitStore(container.redis.client)
    verdicts = await asyncio.gather(
        *[
            store.consume(key="test:concurrent", limit=5, window_seconds=60)
            for _ in range(40)
        ]
    )
    assert sum(1 for verdict in verdicts if verdict.allowed) == 5


async def test_peeking_does_not_consume_from_the_window(container: Container) -> None:
    from app.stores.rate_limit_store import RateLimitStore

    store = RateLimitStore(container.redis.client)
    await store.consume(key="test:peek", limit=2, window_seconds=60)
    for _ in range(5):
        assert (await store.peek(key="test:peek", limit=2, window_seconds=60)).allowed
    assert (await store.consume(key="test:peek", limit=2, window_seconds=60)).allowed
    assert not (await store.consume(key="test:peek", limit=2, window_seconds=60)).allowed


async def test_the_window_key_always_carries_a_ttl(container: Container) -> None:
    """A counter without an expiry would block a caller forever after one burst."""
    from app.stores.rate_limit_store import RateLimitStore

    store = RateLimitStore(container.redis.client)
    await store.consume(key="test:ttl", limit=5, window_seconds=30)
    ttl = await container.redis.client.pttl("test:ttl")
    assert 0 < ttl <= 30_000


async def test_resetting_a_window_clears_it(container: Container) -> None:
    from app.stores.rate_limit_store import RateLimitStore

    store = RateLimitStore(container.redis.client)
    for _ in range(3):
        await store.consume(key="test:reset", limit=3, window_seconds=60)
    assert not (await store.consume(key="test:reset", limit=3, window_seconds=60)).allowed
    await store.reset(key="test:reset")
    assert (await store.consume(key="test:reset", limit=3, window_seconds=60)).allowed


async def test_client_registration_rejects_duplicate_client_ids(
    container: Container, seeded: Seeded
) -> None:
    from app.core.errors import ConflictError

    with pytest.raises(ConflictError):
        async with container.database.session() as session:
            await container.clients.register_client(
                session,
                client_name="Duplicate",
                client_type=ClientType.CONFIDENTIAL,
                redirect_uris=["https://dup.example.test/cb"],
                allowed_scopes=["openid"],
                client_id=seeded.client_id,
            )


async def test_only_the_hash_of_a_client_secret_is_stored(
    app_client: AsyncClient, container: Container, seeded: Seeded
) -> None:
    from app.repositories.client_repository import ClientRepository

    async with container.database.session() as session:
        client = await ClientRepository(session).get_by_client_id(seeded.client_id)
    assert client is not None
    assert client.client_secret_hash == hash_token(seeded.client_secret)
    assert client.client_secret_hash != seeded.client_secret
