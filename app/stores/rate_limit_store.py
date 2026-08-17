"""Sliding-window rate limiting in Redis.

Implemented as a sorted set of request timestamps evaluated by a Lua script. Three
properties drove that choice:

* **Accuracy at the boundary.** A plain ``INCR`` + ``EXPIRE`` fixed window lets an attacker
  send ``limit`` requests at the end of one window and ``limit`` more at the start of the
  next — twice the intended rate. A sliding window has no such seam.
* **Atomicity.** Prune, count, decide and record happen inside one script, so N ECS tasks
  checking the same key concurrently cannot each observe ``count == limit - 1`` and all
  admit. ``INCR`` then ``EXPIRE`` as two commands can also leave a key with no TTL if the
  process dies between them.
* **Determinism.** The script takes ``now`` as an argument instead of calling ``TIME``,
  keeping it safe to replicate.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from redis.asyncio.client import Redis
from redis.commands.core import AsyncScript

from app.security.random_tokens import new_opaque_token

# KEYS[1]=zset key  ARGV = now_ms, window_ms, limit, member
_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)

if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retry_ms = window
  if oldest[2] then
    retry_ms = (tonumber(oldest[2]) + window) - now
    if retry_ms < 0 then retry_ms = 0 end
  end
  return {0, count, retry_ms}
end

redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, window)
return {1, count + 1, 0}
"""

# KEYS[1]=zset key  ARGV = now_ms, window_ms, limit  (observe without consuming)
_PEEK_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retry_ms = window
  if oldest[2] then
    retry_ms = (tonumber(oldest[2]) + window) - now
    if retry_ms < 0 then retry_ms = 0 end
  end
  return {0, count, retry_ms}
end
return {1, count, 0}
"""


@dataclass(frozen=True, slots=True)
class RateLimitVerdict:
    allowed: bool
    current_count: int
    limit: int
    retry_after_seconds: int
    # True when the limiter itself could not be consulted and the request was admitted by
    # the fail-open policy. Surfaced so the caller can log it rather than assume a real pass.
    degraded: bool = False

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.current_count)


class RateLimitStore:
    """Raw sliding-window primitive. Policy (which limits, fail-open) lives in the service."""

    def __init__(self, redis: Redis) -> None:
        self._redis = redis
        # Registered on first use rather than in the constructor: the store is built at
        # composition time, before the connection pool exists.
        self._consume_script: AsyncScript | None = None
        self._peek_script: AsyncScript | None = None

    async def consume(self, *, key: str, limit: int, window_seconds: int) -> RateLimitVerdict:
        if self._consume_script is None:
            self._consume_script = self._redis.register_script(_SLIDING_WINDOW_LUA)
        now_ms = int(time.time() * 1000)
        window_ms = window_seconds * 1000
        raw = await self._consume_script(
            keys=[key], args=[now_ms, window_ms, limit, f"{now_ms}:{new_opaque_token(8)}"]
        )
        return self._to_verdict(raw, limit)

    async def peek(self, *, key: str, limit: int, window_seconds: int) -> RateLimitVerdict:
        if self._peek_script is None:
            self._peek_script = self._redis.register_script(_PEEK_LUA)
        now_ms = int(time.time() * 1000)
        raw = await self._peek_script(keys=[key], args=[now_ms, window_seconds * 1000, limit])
        return self._to_verdict(raw, limit)

    async def reset(self, *, key: str) -> None:
        """Clear a window — used after a successful login so one bad password followed by a
        good one does not leave the account near its limit."""
        await self._redis.delete(key)

    @staticmethod
    def _to_verdict(raw: Any, limit: int) -> RateLimitVerdict:
        # The Lua script returns {allowed, count, retry_after_ms}; Redis renders Lua numbers as
        # integers, so the three positions are parsed rather than trusted as types.
        allowed_raw, count_raw, retry_ms_raw = (int(value) for value in tuple(raw)[:3])
        retry_seconds = max(1, (retry_ms_raw + 999) // 1000) if retry_ms_raw else 0
        return RateLimitVerdict(
            allowed=bool(allowed_raw),
            current_count=count_raw,
            limit=limit,
            retry_after_seconds=retry_seconds,
        )
