"""Authorization-code storage with atomic single-use redemption.

Two properties matter here and both are enforced by Redis rather than by application logic:

* **Single use.** Redemption is a ``GETDEL``: one round trip that returns the payload and
  deletes the key. Two concurrent ``/token`` requests presenting the same code cannot both
  receive a payload, no matter which ECS task each lands on. A read-then-delete pair would
  leave a window where both reads succeed.
* **Short life.** The key carries a TTL (60-120s), so an unredeemed code cannot be replayed
  later even if it leaks from a browser history or a proxy log.

The Redis key is derived from the SHA-256 of the code, so a Redis memory dump, ``MONITOR``
session or slowlog never exposes a redeemable authorization code.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from redis.asyncio.client import Redis

from app.core.logging import get_logger
from app.security.random_tokens import hash_token, new_opaque_token

logger = get_logger(__name__)

_KEY_PREFIX = "authz_code:"


@dataclass(frozen=True, slots=True)
class AuthorizationCodePayload:
    """Everything ``/token`` must re-verify, captured at the moment the code was issued.

    Binding the client, redirect URI and PKCE challenge into the code itself is what makes
    the code useless to anyone who intercepts it: redemption has to arrive from the same
    client, quoting the same redirect URI, holding the matching verifier.
    """

    client_id: str
    user_id: str
    redirect_uri: str
    scopes: list[str]
    code_challenge: str
    code_challenge_method: str
    nonce: str | None
    auth_time: int
    session_id: str | None
    issued_at: int

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> AuthorizationCodePayload:
        data = json.loads(raw)
        return cls(**data)

    @property
    def auth_time_datetime(self) -> datetime:
        return datetime.fromtimestamp(self.auth_time, tz=UTC)


class AuthCodeStore:
    def __init__(self, redis: Redis, *, ttl_seconds: int) -> None:
        self._redis = redis
        self._ttl_seconds = ttl_seconds

    async def issue(self, payload: AuthorizationCodePayload) -> str:
        """Mint a code and store its payload. Returns the raw code for the redirect."""
        code = new_opaque_token()
        await self._redis.set(self._key(code), payload.to_json(), ex=self._ttl_seconds)
        return code

    async def redeem(self, code: str) -> AuthorizationCodePayload | None:
        """Atomically consume a code. ``None`` means unknown, expired, or already used."""
        raw = await self._redis.getdel(self._key(code))
        if raw is None:
            return None
        try:
            return AuthorizationCodePayload.from_json(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            # A payload we cannot parse is already deleted, so the code is spent either way.
            logger.error("authorization code payload could not be decoded")
            return None

    async def discard(self, code: str) -> None:
        """Proactively invalidate a code (e.g. the client aborted the exchange)."""
        await self._redis.delete(self._key(code))

    def _key(self, code: str) -> str:
        return f"{_KEY_PREFIX}{hash_token(code)}"
