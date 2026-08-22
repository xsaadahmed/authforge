"""Shared test fixtures.

Integration tests run against a **real Postgres and a real Redis**, never fakes. The behaviours
this project most needs to prove — an atomic ``UPDATE ... WHERE used_at IS NULL`` serialising two
concurrent refreshes, ``GETDEL`` making an authorization code single-use, a partial index, a TTL
expiring — are properties of those engines. A fake would let the code pass while the guarantee
was absent, which is the one outcome worth engineering against here.

The schema is created by running the real Alembic migrations rather than
``metadata.create_all``, so every test also exercises the migration path production uses.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.container import Container, build_container, shutdown, startup
from app.core.metrics import get_metrics
from app.main import create_app
from app.models.client import ClientType
from app.repositories.scope_repository import ScopeRepository
from app.repositories.user_repository import UserRepository
from app.security import pkce as pkce_lib
from app.security.passwords import PasswordHasherService

REPO_ROOT = Path(__file__).resolve().parent.parent

TEST_DATABASE_URL = os.environ.get(
    "AUTHFORGE_TEST_DATABASE_URL",
    "postgresql+asyncpg://authforge:authforge@127.0.0.1:5432/authforge_test",
)
# A dedicated logical database so a test run can flush it without touching a developer's data.
TEST_REDIS_URL = os.environ.get("AUTHFORGE_TEST_REDIS_URL", "redis://127.0.0.1:6379/15")

TEST_USER_EMAIL = "user@example.test"
TEST_USER_PASSWORD = "correct-horse-battery-staple-9"
TEST_CLIENT_ID = "test-web-client"
TEST_REDIRECT_URI = "https://rp.example.test/callback"
TEST_SCOPES = "openid profile email offline_access"

SCOPE_CATALOGUE: tuple[tuple[str, str, bool], ...] = (
    ("openid", "Confirm your identity", True),
    ("profile", "See your profile details", True),
    ("email", "See your email address", True),
    ("offline_access", "Stay signed in", True),
    ("reports:read", "Read your reports", False),
)

_ALL_TABLES = (
    "audit_log",
    "recovery_codes",
    "mfa_credentials",
    "refresh_tokens",
    "consents",
    "client_scopes",
    "client_redirect_uris",
    "oauth_clients",
    "scopes",
    "users",
    "signing_keys",
)


@pytest.fixture(scope="session")
def test_settings(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    key_directory = tmp_path_factory.mktemp("authforge-keys")
    return Settings(
        environment="test",
        issuer="https://idp.example.test",
        database_url=TEST_DATABASE_URL,  # type: ignore[arg-type]
        redis_url=TEST_REDIS_URL,  # type: ignore[arg-type]
        log_level="WARNING",
        signing_key_provider="local",
        local_key_directory=str(key_directory),
        # Argon2 at production cost would dominate the suite's runtime. The verification *logic* is
        # identical at any cost; the parameter values themselves are asserted separately and the
        # deployed values live in Terraform.
        argon2_time_cost=1,
        argon2_memory_cost_kib=8192,
        argon2_parallelism=1,
        session_cookie_secure=False,
        totp_encryption_key="test-only-totp-encryption-key-0123456789",
        admin_api_token="test-admin-token",
        # No key caching, so a rotation performed by a test is visible to the very next request
        # instead of up to `jwks_cache_seconds` later.
        jwks_cache_seconds=0,
        access_token_ttl_seconds=300,
        key_rotation_grace_seconds=1200,
        access_token_audiences=["https://api.example.test"],
        # The concurrency tests fire ten simultaneous requests, each holding one connection for the
        # duration of its transaction, and the durable-audit path can transiently want a second.
        # Sized with headroom so a pool timeout can never be mistaken for the lock-contention
        # behaviour those tests exist to observe.
        database_pool_size=10,
        database_max_overflow=10,
    )


@pytest.fixture(scope="session", autouse=True)
def _migrated_database(test_settings: Settings) -> Iterator[None]:
    """Bring the test database to head with the real migrations, once per session."""
    environment = {
        **os.environ,
        "AUTHFORGE_DATABASE_URL": str(test_settings.database_url),
        "AUTHFORGE_ENVIRONMENT": "test",
    }
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(f"alembic upgrade head failed:\n{result.stdout}\n{result.stderr}")
    yield


@pytest.fixture(scope="session", autouse=True)
def _silence_metrics() -> None:
    """EMF metric lines are real stdout writes; keep them out of captured test output."""
    get_metrics().disable()


@pytest.fixture(autouse=True)
def _reset_settings_cache() -> Iterator[None]:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@dataclass(slots=True)
class Api:
    """A live ASGI app plus the container behind it."""

    app: FastAPI
    client: AsyncClient
    container: Container


@pytest_asyncio.fixture
async def api(test_settings: Settings) -> AsyncIterator[Api]:
    """An HTTP client wired straight to the ASGI app, with a real container behind it.

    ASGITransport rather than a live uvicorn: same middleware, same dependency graph, same
    lifespan semantics, without binding a port or racing a startup.
    """
    application = create_app(test_settings)
    # create_app installs a fresh metrics emitter, so silencing has to happen after it.
    get_metrics().disable()
    built = build_container(test_settings)
    await startup(built, ensure_signing_key=True)
    application.state.container = built
    async with AsyncClient(
        transport=ASGITransport(app=application, raise_app_exceptions=False),
        base_url=test_settings.issuer,
        follow_redirects=False,
    ) as client:
        try:
            yield Api(app=application, client=client, container=built)
        finally:
            await _truncate_all(built)
            await built.redis.client.flushdb()
            await shutdown(built)


@pytest_asyncio.fixture
async def app_client(api: Api) -> AsyncClient:
    return api.client


@pytest_asyncio.fixture
async def container(api: Api) -> Container:
    return api.container


@pytest_asyncio.fixture
async def db(container: Container) -> AsyncIterator[AsyncSession]:
    """A session for arranging fixtures and asserting directly on stored state."""
    async with container.database.session() as session:
        yield session


@dataclass(slots=True)
class Seeded:
    """Handles to the seeded fixtures, plus a helper for building authorize queries."""

    container: Container
    user_id: str
    user_email: str
    password: str
    client_id: str
    client_secret: str
    client_internal_id: str

    def authorize_query(
        self,
        *,
        code_challenge: str,
        scope: str = TEST_SCOPES,
        state: str | None = "state-abc",
        nonce: str | None = "nonce-xyz",
        redirect_uri: str = TEST_REDIRECT_URI,
        response_type: str = "code",
        code_challenge_method: str | None = "S256",
        extra: dict[str, str] | None = None,
    ) -> str:
        params: dict[str, str] = {
            "response_type": response_type,
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "code_challenge": code_challenge,
        }
        if code_challenge_method is not None:
            params["code_challenge_method"] = code_challenge_method
        if state is not None:
            params["state"] = state
        if nonce is not None:
            params["nonce"] = nonce
        if extra:
            params.update(extra)
        return urlencode(params)


@pytest_asyncio.fixture
async def seeded(container: Container) -> Seeded:
    """A scope catalogue, one user and one confidential client — the minimum for a real flow."""
    hasher = PasswordHasherService(container.settings)
    async with container.database.session() as session:
        scopes = ScopeRepository(session)
        for name, description, is_oidc in SCOPE_CATALOGUE:
            await scopes.upsert(name=name, description=description, is_oidc=is_oidc)

        user = await UserRepository(session).create(
            email=TEST_USER_EMAIL,
            password_hash=hasher.hash(TEST_USER_PASSWORD),
            full_name="Test User",
            given_name="Test",
            family_name="User",
            email_verified=True,
        )
        result = await container.clients.register_client(
            session,
            client_name="Test Web Client",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=[TEST_REDIRECT_URI],
            allowed_scopes=["openid", "profile", "email", "offline_access"],
            client_id=TEST_CLIENT_ID,
        )
        return Seeded(
            container=container,
            user_id=user.id,
            user_email=user.email,
            password=TEST_USER_PASSWORD,
            client_id=result.client.client_id,
            client_secret=result.client_secret or "",
            client_internal_id=result.client.id,
        )


@pytest.fixture
def pkce_pair() -> tuple[str, str]:
    """A fresh (verifier, challenge) pair."""
    verifier = pkce_lib.generate_code_verifier()
    return verifier, pkce_lib.compute_s256_challenge(verifier)


async def _truncate_all(container: Container) -> None:
    """Wipe every table between tests.

    TRUNCATE rather than an enclosing rolled-back transaction, because the concurrency tests need
    two genuinely separate transactions committing against the same rows — which an enclosing
    transaction would make impossible.
    """
    async with container.database.session() as session:
        await session.execute(text(f"TRUNCATE {', '.join(_ALL_TABLES)} RESTART IDENTITY CASCADE"))
