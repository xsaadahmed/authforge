"""Short-lived denylist for revoked access-token identifiers.

Access tokens are self-contained JWTs, which is what makes them cheap to verify at scale and
also what makes them impossible to un-issue. RFC 7009 says revocation support for access
tokens is optional ("where feasible"); this is the feasible version — remember the ``jti`` of
a revoked token until its own ``exp`` passes, at which point the denylist entry is pointless
and Redis drops it automatically. Storage is therefore bounded by the access-token TTL, not by
the number of tokens ever issued.

**Failure behaviour is fail-open, deliberately.** If Redis cannot be reached, a token that
verifies cryptographically is accepted. Failing closed would mean a Redis outage breaks every
API call in the deployment, while the exposure from failing open is bounded by the
access-token lifetime (minutes) and only applies to tokens explicitly revoked inside that
window. The refresh token underneath was revoked in Postgres, so the session cannot be
extended past the current access token's expiry either way.
"""

from __future__ import annotations

from redis.asyncio.client import Redis

from app.core.logging import get_logger
from app.core.metrics import get_metrics

logger = get_logger(__name__)

_PREFIX = "revoked_jti:"


class TokenDenylistStore:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def revoke(self, *, jti: str, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            # Already expired; the signature check will reject it anyway.
            return
        await self._redis.set(f"{_PREFIX}{jti}", "1", ex=ttl_seconds)

    async def is_revoked(self, jti: str) -> bool:
        try:
            return bool(await self._redis.exists(f"{_PREFIX}{jti}"))
        except Exception:
            logger.error(
                "access-token denylist unavailable; failing open",
                extra={"degraded": True},
                exc_info=True,
            )
            get_metrics().count("DenylistUnavailable")
            return False
