"""Datastore-failure translation that does not need a live Postgres or Redis."""

from __future__ import annotations

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from app.core.database import Database
from app.core.errors import TemporarilyUnavailableError
from app.core.redis_client import RedisProvider


@pytest.mark.asyncio
async def test_database_session_fails_loudly_when_the_engine_is_missing() -> None:
    database = Database.__new__(Database)
    database._engine = None
    database._sessionmaker = object()  # would still work if session() did not check the engine

    with pytest.raises(RuntimeError, match="not connected"):
        async with database.session():
            pass


@pytest.mark.asyncio
async def test_lazy_redis_proxy_translates_driver_errors() -> None:
    class _Broken:
        async def set(self, *args: object, **kwargs: object) -> None:
            raise RedisConnectionError("Error 111 connecting to 127.0.0.1:1.")

    provider = RedisProvider.__new__(RedisProvider)
    provider._client = _Broken()  # type: ignore[assignment]
    proxy = provider.lazy_client()

    with pytest.raises(TemporarilyUnavailableError):
        await proxy.set("csrf:x", "token")
