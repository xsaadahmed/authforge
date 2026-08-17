"""Composition root.

All wiring happens here, once, at startup. Services receive their collaborators as
constructor arguments and never reach for a global, which is what makes them unit-testable
with fakes and what keeps the dependency graph visible in one file instead of implied across
twenty.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.config import Settings
from app.core.database import Database
from app.core.logging import get_logger
from app.core.redis_client import RedisProvider
from app.security.encryption import SecretEncryptor
from app.security.passwords import PasswordHasherService
from app.services.audit import AuditService
from app.services.authentication import AuthenticationService
from app.services.authorization import AuthorizationService
from app.services.clients import ClientService
from app.services.consent import ConsentService
from app.services.key_management import KeyManagementService
from app.services.key_providers import build_key_provider
from app.services.rate_limit import RateLimitService
from app.services.tokens import TokenService
from app.stores.auth_code_store import AuthCodeStore
from app.stores.rate_limit_store import RateLimitStore
from app.stores.session_store import SessionStore
from app.stores.token_denylist import TokenDenylistStore

logger = get_logger(__name__)


@dataclass(slots=True)
class Container:
    settings: Settings
    database: Database
    redis: RedisProvider
    audit: AuditService
    keys: KeyManagementService
    clients: ClientService
    consent: ConsentService
    tokens: TokenService
    authorization: AuthorizationService
    authentication: AuthenticationService
    rate_limits: RateLimitService
    sessions: SessionStore
    auth_codes: AuthCodeStore
    denylist: TokenDenylistStore


def build_container(settings: Settings) -> Container:
    """Construct the graph. Datastore connections are opened separately, in ``startup``.

    Splitting construction from connection means a CLI command can build the container, use
    only the pieces it needs, and shut down cleanly — and it keeps import-time side effects at
    zero.
    """
    database = Database(settings)
    redis_provider = RedisProvider(settings)

    audit = AuditService(settings=settings, database=database)
    keys = KeyManagementService(
        settings=settings, database=database, key_provider=build_key_provider(settings)
    )
    clients = ClientService(settings=settings)
    consent = ConsentService(settings=settings, audit=audit)

    # Redis-backed collaborators resolve `redis_provider.client` lazily via property access, so
    # they can be constructed before the connection pool exists.
    auth_codes = AuthCodeStore(
        _LazyRedis(redis_provider), ttl_seconds=settings.authorization_code_ttl_seconds
    )
    sessions = SessionStore(
        _LazyRedis(redis_provider),
        session_ttl_seconds=settings.session_ttl_seconds,
        pending_mfa_ttl_seconds=settings.pending_mfa_ttl_seconds,
    )
    denylist = TokenDenylistStore(_LazyRedis(redis_provider))
    rate_limit_store = RateLimitStore(_LazyRedis(redis_provider))
    rate_limits = RateLimitService(settings=settings, store=rate_limit_store)

    tokens = TokenService(
        settings=settings, keys=keys, auth_codes=auth_codes, denylist=denylist, audit=audit
    )
    authorization = AuthorizationService(
        settings=settings, clients=clients, auth_codes=auth_codes, audit=audit
    )
    authentication = AuthenticationService(
        settings=settings,
        password_hasher=PasswordHasherService(settings),
        session_store=sessions,
        rate_limiter=rate_limits,
        audit=audit,
        encryptor=SecretEncryptor(settings.totp_encryption_key),
    )

    return Container(
        settings=settings,
        database=database,
        redis=redis_provider,
        audit=audit,
        keys=keys,
        clients=clients,
        consent=consent,
        tokens=tokens,
        authorization=authorization,
        authentication=authentication,
        rate_limits=rate_limits,
        sessions=sessions,
        auth_codes=auth_codes,
        denylist=denylist,
    )


async def startup(container: Container, *, ensure_signing_key: bool = True) -> None:
    container.database.connect()
    container.redis.connect()
    if ensure_signing_key:
        # Idempotent and safe to run from every task simultaneously: whichever wins, the others
        # observe a `current` key and do nothing.
        kid = await container.keys.ensure_initialized()
        logger.info("signing key ready", extra={"kid": kid})


async def shutdown(container: Container) -> None:
    await container.redis.disconnect()
    await container.database.disconnect()


class _LazyRedis:
    """Forwards attribute access to the provider's live client.

    Lets stores be constructed at import/composition time while the connection pool is created
    during startup, without every store having to carry a ``connect()`` step of its own.
    """

    __slots__ = ("_provider",)

    def __init__(self, provider: RedisProvider) -> None:
        self._provider = provider

    def __getattr__(self, item: str) -> object:
        return getattr(self._provider.client, item)
