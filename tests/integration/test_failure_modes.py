"""Failure and recovery behaviour (§21, §23).

The specification's §21 table documents what should happen when a dependency fails. These tests
verify it actually happens rather than assuming it, which is the difference between a documented
failure mode and a hoped-for one.

Dependencies are broken by pointing the store at an unreachable address, so the code under test takes
its real error path — a mock that raises would prove only that the ``except`` clause is reachable.
"""

from __future__ import annotations

import pytest
import redis.asyncio as redis
from httpx import AsyncClient

from app.container import Container
from app.services.rate_limit import RateLimitService
from app.stores.rate_limit_store import RateLimitStore
from app.stores.token_denylist import TokenDenylistStore
from tests.conftest import Seeded
from tests.helpers import full_flow_tokens, login

pytestmark = pytest.mark.integration

# Port 1 is reserved and never listening, so a connection attempt fails immediately rather than
# hanging for the socket timeout.
UNREACHABLE_REDIS = "redis://127.0.0.1:1/0"


def _broken_redis() -> redis.Redis:
    return redis.from_url(
        UNREACHABLE_REDIS, decode_responses=True, socket_connect_timeout=0.05, socket_timeout=0.05
    )


async def test_rate_limiting_fails_open_when_redis_is_unreachable(
    container: Container,
) -> None:
    """The documented default (docs/adr/0005).

    Failing closed would convert a cache outage into a total authentication outage for every user — a
    self-inflicted denial of service far more likely than the brute-force campaign the limiter defends
    against. The controls that actually stop credential attacks do not live in Redis: Argon2id makes
    each guess expensive, and the failure counter and lockout are durable rows in Postgres.
    """
    service = RateLimitService(
        settings=container.settings, store=RateLimitStore(_broken_redis())
    )
    verdict = await service.check_login_attempt(ip_address="203.0.113.5", subject="user@x.test")
    assert verdict.allowed is True
    # Flagged, so a degraded decision is never mistaken for a real pass in the logs or metrics.
    assert verdict.degraded is True


async def test_rate_limiting_can_be_configured_to_fail_closed(container: Container) -> None:
    """A deployment with a different threat model flips one setting and gets the opposite behaviour."""
    strict = container.settings.model_copy(update={"rate_limit_fail_open": False})
    service = RateLimitService(settings=strict, store=RateLimitStore(_broken_redis()))
    verdict = await service.check_login_attempt(ip_address="203.0.113.5", subject="user@x.test")
    assert verdict.allowed is False
    assert verdict.degraded is True
    assert verdict.retry_after_seconds > 0


async def test_the_access_token_denylist_fails_open(container: Container) -> None:
    """Bounded exposure, deliberately.

    Failing closed would break every API call in the deployment during a Redis outage. Failing open
    only affects tokens explicitly revoked inside the current access-token lifetime — minutes — and the
    refresh token underneath was revoked in Postgres, so the session cannot be extended either way.
    """
    denylist = TokenDenylistStore(_broken_redis())
    assert await denylist.is_revoked("some-jti") is False


async def test_login_fails_cleanly_when_redis_is_unreachable(
    app_client: AsyncClient, container: Container, seeded: Seeded
) -> None:
    """Sessions are a hard dependency on Redis, and that is the correct trade-off.

    §21 distinguishes an availability dependency from a security one: without Redis there is nowhere to
    put a session, so login legitimately cannot complete. What must not happen is a 500 with a stack
    trace, or worse, a login that appears to succeed without a session.
    """
    original = container.redis._client  # noqa: SLF001 - deliberately breaking the dependency
    container.redis._client = _broken_redis()  # noqa: SLF001
    try:
        response = await login(app_client, seeded)
        assert response.status_code in (400, 500, 503)
        assert app_client.cookies.get("authforge_session") is None
        # An internal error must not leak a stack trace or a driver message to the caller.
        assert "Traceback" not in response.text
        assert "127.0.0.1:1" not in response.text
    finally:
        container.redis._client = original  # noqa: SLF001


async def test_the_liveness_probe_stays_green_when_datastores_are_down(
    app_client: AsyncClient, container: Container
) -> None:
    """The reason /health and /ready are separate endpoints.

    If the ALB's health check touched Postgres, a brief RDS failover would fail every task's check at
    once and ECS would replace the whole fleet — turning a recoverable blip into an outage. Liveness
    answers only "can this process serve HTTP".
    """
    original = container.redis._client  # noqa: SLF001
    container.redis._client = _broken_redis()  # noqa: SLF001
    try:
        response = await app_client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
    finally:
        container.redis._client = original  # noqa: SLF001


async def test_the_readiness_probe_reports_a_failed_dependency(
    app_client: AsyncClient, container: Container
) -> None:
    """Readiness is where a dependency failure should show, for smoke tests and for humans."""
    original = container.redis._client  # noqa: SLF001
    container.redis._client = _broken_redis()  # noqa: SLF001
    try:
        response = await app_client.get("/ready")
        assert response.status_code == 503
        payload = response.json()
        assert payload["status"] == "not_ready"
        assert payload["checks"]["redis"] == "unavailable"
        assert payload["checks"]["postgres"] == "ok"
    finally:
        container.redis._client = original  # noqa: SLF001


async def test_readiness_is_green_when_everything_is_reachable(app_client: AsyncClient) -> None:
    response = await app_client.get("/ready")
    assert response.status_code == 200
    assert response.json()["checks"] == {
        "postgres": "ok",
        "redis": "ok",
        "signing_key": "ok",
    }


async def test_token_verification_survives_a_redis_outage(
    app_client: AsyncClient, container: Container, seeded: Seeded, pkce_pair: tuple[str, str]
) -> None:
    """Stateless verification means resource-server traffic is unaffected by a cache outage.

    This is the concrete payoff of signing access tokens instead of storing them: /userinfo needs only
    the signing key's public half, which is cached from Postgres.
    """
    tokens = await full_flow_tokens(app_client, seeded, pkce_pair=pkce_pair)
    original = container.redis._client  # noqa: SLF001
    container.redis._client = _broken_redis()  # noqa: SLF001
    try:
        response = await app_client.get(
            "/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        assert response.status_code == 200
    finally:
        container.redis._client = original  # noqa: SLF001


async def test_discovery_and_jwks_survive_a_redis_outage(
    app_client: AsyncClient, container: Container
) -> None:
    """A relying party bootstrapping during a cache outage must still be able to discover the IdP."""
    original = container.redis._client  # noqa: SLF001
    container.redis._client = _broken_redis()  # noqa: SLF001
    try:
        assert (await app_client.get("/.well-known/openid-configuration")).status_code == 200
        assert (await app_client.get("/.well-known/jwks.json")).status_code == 200
    finally:
        container.redis._client = original  # noqa: SLF001


async def test_an_unexpected_error_is_reported_without_internal_detail(
    app_client: AsyncClient, container: Container, seeded: Seeded
) -> None:
    """Internal detail in an error body is reconnaissance material.

    The exception is logged in full, with a request ID to correlate it, but the caller receives OAuth's
    own opaque ``server_error``.
    """
    original = container.database._engine  # noqa: SLF001
    container.database._engine = None  # noqa: SLF001
    try:
        response = await app_client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": "irrelevant"},
            auth=(seeded.client_id, seeded.client_secret),
        )
        assert response.status_code == 500
        assert response.json() == {
            "error": "server_error",
            "error_description": "an unexpected error occurred",
        }
        # Still correlated, so the opaque response can be tied to the logged stack trace.
        assert response.headers["x-request-id"]
    finally:
        container.database._engine = original  # noqa: SLF001


async def test_a_signing_key_whose_private_material_is_missing_fails_loudly(
    container: Container,
) -> None:
    """Almost always a deployment-wiring mistake: a database restored from one environment against
    another environment's secret store. It must be an obvious error, not a silent inability to sign."""
    from app.services.key_providers import PrivateKeyNotFoundError

    async with container.database.session() as session:
        from app.repositories.signing_key_repository import SigningKeyRepository

        current = await SigningKeyRepository(session).get_current()
        assert current is not None
        current.private_key_ref = "does-not-exist.pem"

    container.keys.invalidate_cache()
    with pytest.raises(PrivateKeyNotFoundError):
        await container.keys.get_signing_key()
