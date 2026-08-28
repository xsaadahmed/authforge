"""Redis client provisioning.

Redis holds only ephemeral state (§13). Command timeouts stay short so a slow Redis surfaces
as a fast failure rather than pinning ECS workers; connect timeouts are slightly longer to
cover TCP + TLS on ``rediss://``. The pool is capped so bursts cannot open unbounded
connections against ElastiCache.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, cast

import redis.asyncio as redis
from redis.asyncio.client import Redis
from redis.exceptions import RedisError

from app.config import Settings
from app.core.errors import TemporarilyUnavailableError
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
            max_connections=settings.redis_max_connections,
            socket_timeout=settings.redis_command_timeout_seconds,
            socket_connect_timeout=settings.redis_connect_timeout_seconds,
            health_check_interval=30,
            retry_on_timeout=False,
        )
        logger.info(
            "redis client created",
            extra={
                "event": "redis_client_created",
                "max_connections": settings.redis_max_connections,
                "connect_timeout_seconds": settings.redis_connect_timeout_seconds,
                "command_timeout_seconds": settings.redis_command_timeout_seconds,
            },
        )

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

    async def warmup_pool(self) -> None:
        """Open a handful of pool connections before the first request burst."""
        count = self._settings.redis_pool_prewarm_connections
        if count <= 0 or self._client is None:
            return
        results = await asyncio.gather(
            *(self._client.ping() for _ in range(count)),
            return_exceptions=True,
        )
        failures = [result for result in results if isinstance(result, Exception)]
        if failures:
            logger.warning(
                "redis pool prewarm incomplete",
                extra={"requested": count, "failed": len(failures)},
                exc_info=failures[0],
            )
            return
        logger.info("redis pool prewarmed", extra={"connections": count})

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
        attr = getattr(self._provider.client, item)
        if not callable(attr):
            return attr
        if not inspect.iscoroutinefunction(attr):
            return attr

        async def _guarded(*args: Any, **kwargs: Any) -> Any:
            try:
                return await attr(*args, **kwargs)
            except RedisError as exc:
                # Redis is an availability dependency for sessions/CSRF. Surface it as an
                # OAuth ``temporarily_unavailable`` so the caller sees a clean 503 instead of
                # a driver traceback (and so TestClient/ASGITransport do not re-raise).
                raise TemporarilyUnavailableError("temporarily unavailable") from exc

        return _guarded
