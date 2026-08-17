"""Signing-key lifecycle, JWKS materialization and rotation (§11).

The design goal is that rotation never requires a deploy and never invalidates a token that
was already issued:

* Only the ``current`` key signs.
* ``current`` and ``retiring`` keys are both published in JWKS, so a token signed one
  millisecond before a rotation still verifies for its whole lifetime.
* A ``retiring`` key's grace period is at least twice the access-token TTL (enforced in
  ``Settings``), after which it leaves JWKS and its private material can be destroyed.
* Running tasks pick up a new ``current`` key through a short-lived in-process cache, so N
  Fargate tasks converge on the new key within ``jwks_cache_seconds`` with no coordination.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.database import Database
from app.core.errors import ServerError
from app.core.logging import get_logger
from app.models.signing_key import KeyStatus
from app.repositories.signing_key_repository import SigningKeyRepository
from app.security import rsa_keys
from app.security.random_tokens import new_identifier

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ActiveSigningKey:
    kid: str
    algorithm: str
    private_key: rsa.RSAPrivateKey


@dataclass(frozen=True, slots=True)
class PublishedKey:
    kid: str
    algorithm: str
    status: str
    public_jwk: dict[str, Any]
    public_pem: str


@dataclass(slots=True)
class _KeyCache:
    """Per-process cache of key state.

    Public metadata is cached because /.well-known/jwks.json and every token verification
    would otherwise hit Postgres. Private keys are cached because every token issuance would
    otherwise hit Secrets Manager, which is both slow and rate-limited. Both are bounded by
    ``jwks_cache_seconds``, which is what bounds rotation propagation delay.
    """

    published: list[PublishedKey]
    current_kid: str | None
    expires_at_monotonic: float
    private_keys: dict[str, rsa.RSAPrivateKey]


class KeyManagementService:
    def __init__(
        self,
        *,
        settings: Settings,
        database: Database,
        key_provider: Any,
    ) -> None:
        self._settings = settings
        self._database = database
        self._provider = key_provider
        self._cache: _KeyCache | None = None
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ read paths
    #
    # Every read accepts the caller's session. That is not a convenience: opening a *second*
    # connection while a request already holds a transaction is a pool-exhaustion deadlock waiting
    # to happen. Under N concurrent refreshes where N equals the pool size, each request holds one
    # connection and blocks waiting for a second, and nothing can ever commit. Reusing the caller's
    # session keeps the token path at exactly one connection per request.
    async def get_signing_key(self, session: AsyncSession | None = None) -> ActiveSigningKey:
        """The key to sign the next token with."""
        cache = await self._get_cache(session)
        if cache.current_kid is None:
            raise ServerError("no active signing key is configured")
        kid = cache.current_kid
        private_key = cache.private_keys.get(kid)
        if private_key is None:
            private_key = await self._load_private_key(kid, session)
            cache.private_keys[kid] = private_key
        algorithm = next(
            (key.algorithm for key in cache.published if key.kid == kid), rsa_keys.JWS_ALGORITHM
        )
        return ActiveSigningKey(kid=kid, algorithm=algorithm, private_key=private_key)

    async def get_verification_key(
        self, kid: str, session: AsyncSession | None = None
    ) -> rsa.RSAPublicKey | None:
        """Public key for a ``kid``, or None if it is unknown or fully retired.

        One forced refresh is attempted on a miss: a token signed by a brand-new key can
        arrive at a task whose cache predates the rotation.
        """
        cache = await self._get_cache(session)
        match = next((key for key in cache.published if key.kid == kid), None)
        if match is None:
            cache = await self._refresh_cache(session)
            match = next((key for key in cache.published if key.kid == kid), None)
        if match is None:
            return None
        return rsa_keys.load_public_key(match.public_pem)

    async def get_jwks(
        self, session: AsyncSession | None = None
    ) -> dict[str, list[dict[str, Any]]]:
        cache = await self._get_cache(session)
        return {"keys": [key.public_jwk for key in cache.published]}

    async def list_keys(self, session: AsyncSession | None = None) -> list[PublishedKey]:
        cache = await self._get_cache(session)
        return list(cache.published)

    def invalidate_cache(self) -> None:
        """Drop the cache so the next read observes the database immediately.

        Called after this process performs a rotation; other tasks converge via TTL.
        """
        self._cache = None

    # ------------------------------------------------------------------ lifecycle
    async def ensure_initialized(self) -> str:
        """Create the first signing key if the deployment has none. Idempotent."""
        async with self._database.session() as session:
            repository = SigningKeyRepository(session)
            existing = await repository.get_current()
            if existing is not None:
                return existing.kid
        return await self.rotate(reason="bootstrap")

    async def rotate(self, *, reason: str = "scheduled") -> str:
        """Generate a new ``current`` key and demote the previous one to ``retiring``.

        Ordering matters. The new key is written to the private-key store *before* any
        metadata row exists, so a crash mid-rotation leaves an orphaned secret (harmless,
        unreferenced) rather than a metadata row pointing at material that was never saved —
        which would make the IdP unable to sign anything.
        """
        kid = f"{datetime.now(tz=UTC).strftime('%Y%m%d')}-{new_identifier()}"
        keypair = await asyncio.to_thread(
            rsa_keys.generate_keypair, kid, self._settings.rsa_key_size
        )
        ref = await self._provider.store(kid=kid, private_pem=keypair.private_pem)

        grace = timedelta(seconds=self._settings.key_rotation_grace_seconds)
        async with self._database.session() as session:
            repository = SigningKeyRepository(session)
            previous = await repository.get_current()
            await repository.create(
                kid=kid,
                public_jwk=keypair.public_jwk,
                public_pem=keypair.public_pem,
                private_key_ref=ref,
                status=KeyStatus.CURRENT,
                algorithm=rsa_keys.JWS_ALGORITHM,
            )
            if previous is not None:
                await repository.mark_retiring(
                    kid=previous.kid, retire_after=datetime.now(tz=UTC) + grace
                )

        self.invalidate_cache()
        logger.info(
            "signing key rotated",
            extra={
                "event": "key_rotated",
                "kid": kid,
                "previous_kid": previous.kid if previous else None,
                "reason": reason,
                "grace_seconds": self._settings.key_rotation_grace_seconds,
            },
        )
        return kid

    async def sweep_retired_keys(self, *, destroy_private_material: bool = True) -> list[str]:
        """Move ``retiring`` keys past their grace period to ``retired`` and drop them from JWKS."""
        retired: list[str] = []
        async with self._database.session() as session:
            repository = SigningKeyRepository(session)
            for key in await repository.list_expired_retiring(now=datetime.now(tz=UTC)):
                await repository.mark_retired(kid=key.kid)
                retired.append(key.kid)
                if destroy_private_material:
                    try:
                        await self._provider.delete(key.private_key_ref)
                    except Exception:
                        # The metadata transition is the security-relevant part; leftover
                        # material is cleaned up by the next sweep or by hand.
                        logger.warning(
                            "could not destroy private material for retired key",
                            extra={"kid": key.kid},
                            exc_info=True,
                        )
        if retired:
            self.invalidate_cache()
            logger.info("retired signing keys", extra={"event": "key_retired", "kids": retired})
        return retired

    # ------------------------------------------------------------------ internals
    @asynccontextmanager
    async def _session(self, session: AsyncSession | None) -> AsyncIterator[AsyncSession]:
        """Use the caller's session when given, otherwise open a short-lived one."""
        if session is not None:
            yield session
            return
        async with self._database.session() as own_session:
            yield own_session

    async def _get_cache(self, session: AsyncSession | None = None) -> _KeyCache:
        cache = self._cache
        if cache is not None and cache.expires_at_monotonic > time.monotonic():
            return cache
        return await self._refresh_cache(session)

    async def _refresh_cache(self, session: AsyncSession | None = None) -> _KeyCache:
        async with self._lock:
            # Re-checked under the lock: a thundering herd of requests arriving on cache expiry
            # should produce one database read, not one per request.
            cache = self._cache
            if cache is not None and cache.expires_at_monotonic > time.monotonic():
                return cache

            async with self._session(session) as active:
                rows = await SigningKeyRepository(active).list_publishable()
                published = [
                    PublishedKey(
                        kid=row.kid,
                        algorithm=row.algorithm,
                        status=row.status,
                        public_jwk=dict(row.public_jwk),
                        public_pem=row.public_pem,
                    )
                    for row in rows
                ]
                current_kid = next(
                    (row.kid for row in rows if row.status == str(KeyStatus.CURRENT)), None
                )

            preserved = dict(cache.private_keys) if cache is not None else {}
            live_kids = {key.kid for key in published}
            self._cache = _KeyCache(
                published=published,
                current_kid=current_kid,
                expires_at_monotonic=time.monotonic() + self._settings.jwks_cache_seconds,
                # Cached private keys for keys that left JWKS entirely are dropped, so a retired
                # key's material does not linger in process memory.
                private_keys={k: v for k, v in preserved.items() if k in live_kids},
            )
            return self._cache

    async def _load_private_key(
        self, kid: str, session: AsyncSession | None = None
    ) -> rsa.RSAPrivateKey:
        async with self._session(session) as active:
            row = await SigningKeyRepository(active).get_by_kid(kid)
        if row is None:
            raise ServerError(f"signing key metadata missing for kid {kid}")
        pem = await self._provider.load(row.private_key_ref)
        # Parsing a 2048-bit PEM is CPU work measured in milliseconds; off the event loop it goes.
        return await asyncio.to_thread(rsa_keys.load_private_key, pem)
