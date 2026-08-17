"""Redis client provisioning.

Redis holds only ephemeral state (§13), so short socket timeouts are correct: a slow
Redis should surface as a fast, observable failure rather than a request that hangs long
enough to exhaust the ECS task's worker capacity.
"""

from __future__ import annotations

from typing import Any, cast

import redis.asyncio as redis
from redis.asyncio.client import Redis

from app.config import Settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class RedisProvider:
    """Owns one connection pool per process."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: Redis | None = None

    def connect(self) -> None:
        if self._client is not None:
            return
        settings = self._settings
        self._client = redis.from_url(
            str(settings.redis_url),
            decode_responses=True,
            socket_timeout=settings.redis_socket_timeout_seconds,
            socket_connect_timeout=settings.redis_socket_timeout_seconds,
            health_check_interval=30,
            retry_on_timeout=False,
        )
        logger.info("redis client created", extra={"event": "redis_client_created"})

    async def disconnect(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
            logger.info("redis client closed", extra={"event": "redis_client_closed"})

    @property
    def client(self) -> Redis:
        if self._client is None:
            raise RuntimeError("redis not connected; call connect() during startup")
        return self._client

    def lazy_client(self) -> Redis:
        """A proxy that resolves to the live client on every attribute access.

        Lets the stores be constructed at composition time while the connection pool is created
        during startup, without giving every store a ``connect()`` step of its own. The cast is
        the single place this indirection is asserted: the proxy forwards everything to a real
        client, so it satisfies the same interface at runtime.
        """
        return cast("Redis", _LazyRedisProxy(self))

    async def healthcheck(self) -> bool:
        try:
            return bool(await self.client.ping())
        except Exception:
            logger.warning("redis healthcheck failed", exc_info=True)
            return False


class _LazyRedisProxy:
    __slots__ = ("_provider",)

    def __init__(self, provider: RedisProvider) -> None:
        self._provider = provider

    def __getattr__(self, item: str) -> Any:
        return getattr(self._provider.client, item)
