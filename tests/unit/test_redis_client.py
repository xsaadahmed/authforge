"""Redis pool configuration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.config import Settings
from app.core.redis_client import RedisProvider


def test_connect_uses_bounded_pool_and_split_timeouts() -> None:
    settings = Settings(
        redis_url="redis://localhost:6379/0",  # type: ignore[arg-type]
        redis_connect_timeout_seconds=2.0,
        redis_command_timeout_seconds=1.0,
        redis_max_connections=32,
    )
    provider = RedisProvider(settings)

    with patch("app.core.redis_client.redis.from_url", return_value=MagicMock()) as from_url:
        provider.connect()

    from_url.assert_called_once_with(
        "redis://localhost:6379/0",
        decode_responses=True,
        max_connections=32,
        socket_timeout=1.0,
        socket_connect_timeout=2.0,
        health_check_interval=30,
        retry_on_timeout=False,
    )
