"""Browser session, pending-MFA and CSRF state in Redis.

Sessions live server-side rather than in a signed cookie so that logout, MFA step-up and
"revoke this session" are immediate and central; a self-contained cookie can only be
invalidated by waiting for it to expire.

As with authorization codes, the Redis key is the hash of the session ID, so possession of
the datastore's contents does not yield a usable session cookie value.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

from redis.asyncio.client import Redis

from app.security.random_tokens import hash_token, new_opaque_token
from app.stores.serialization import as_text

_SESSION_PREFIX = "session:"
_PENDING_MFA_PREFIX = "pending_mfa:"
_CSRF_PREFIX = "csrf:"


@dataclass(slots=True)
class SessionState:
    """A fully authenticated browser session."""

    user_id: str
    auth_time: int
    mfa_verified: bool
    created_at: int
    # The `/authorize` request the user was trying to complete when redirected to login,
    # preserved so login can resume the flow instead of dead-ending on a success page.
    pending_authorize_query: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> SessionState:
        return cls(**json.loads(raw))

    @property
    def auth_time_datetime(self) -> datetime:
        return datetime.fromtimestamp(self.auth_time, tz=UTC)


@dataclass(slots=True)
class PendingMfaState:
    """Interim state between a correct password and a correct second factor.

    Kept in a *separate* key space from real sessions so there is no representable value of a
    session that means "password accepted, MFA outstanding". A bug in the MFA handler
    therefore cannot promote a half-authenticated user; it can only fail to promote them.
    """

    user_id: str
    password_verified_at: int
    attempts: int = 0
    pending_authorize_query: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> PendingMfaState:
        return cls(**json.loads(raw))


class SessionStore:
    def __init__(
        self, redis: Redis, *, session_ttl_seconds: int, pending_mfa_ttl_seconds: int
    ) -> None:
        self._redis = redis
        self._session_ttl = session_ttl_seconds
        self._pending_ttl = pending_mfa_ttl_seconds

    # ------------------------------------------------------------------ sessions
    async def create(self, state: SessionState) -> str:
        session_id = new_opaque_token()
        await self._redis.set(self._session_key(session_id), state.to_json(), ex=self._session_ttl)
        return session_id

    async def get(self, session_id: str) -> SessionState | None:
        raw = await self._redis.get(self._session_key(session_id))
        if raw is None:
            return None
        try:
            return SessionState.from_json(as_text(raw))
        except (json.JSONDecodeError, TypeError, ValueError):
            await self.delete(session_id)
            return None

    async def replace(self, session_id: str, state: SessionState) -> None:
        """Update a session's contents while preserving its remaining TTL.

        ``KEEPTTL`` matters: refreshing the expiry on every request would silently convert a
        12-hour absolute session into an indefinite sliding one.
        """
        await self._redis.set(self._session_key(session_id), state.to_json(), keepttl=True)

    async def delete(self, session_id: str) -> None:
        await self._redis.delete(self._session_key(session_id), self._csrf_key(session_id))

    async def rotate(self, old_session_id: str, state: SessionState) -> str:
        """Issue a new session ID for the same user and destroy the old one.

        This is the session-fixation defence: an attacker who planted a known session ID in
        the victim's browser before login holds a value that stops existing the instant the
        victim authenticates.
        """
        new_session_id = await self.create(state)
        await self.delete(old_session_id)
        return new_session_id

    async def ttl(self, session_id: str) -> int:
        return int(await self._redis.ttl(self._session_key(session_id)))

    # ------------------------------------------------------------------ pending MFA
    async def create_pending_mfa(self, state: PendingMfaState) -> str:
        pending_id = new_opaque_token()
        await self._redis.set(self._pending_key(pending_id), state.to_json(), ex=self._pending_ttl)
        return pending_id

    async def get_pending_mfa(self, pending_id: str) -> PendingMfaState | None:
        raw = await self._redis.get(self._pending_key(pending_id))
        if raw is None:
            return None
        try:
            return PendingMfaState.from_json(as_text(raw))
        except (json.JSONDecodeError, TypeError, ValueError):
            await self.delete_pending_mfa(pending_id)
            return None

    async def replace_pending_mfa(self, pending_id: str, state: PendingMfaState) -> None:
        await self._redis.set(self._pending_key(pending_id), state.to_json(), keepttl=True)

    async def delete_pending_mfa(self, pending_id: str) -> None:
        await self._redis.delete(self._pending_key(pending_id))

    # ------------------------------------------------------------------ CSRF
    async def issue_csrf_token(self, session_id: str, *, ttl_seconds: int | None = None) -> str:
        """Synchronizer token bound to this session, stored server-side.

        Bound to the session rather than being a self-validating value so that a token
        harvested from one user's form is meaningless in another user's browser.
        """
        token = new_opaque_token(24)
        await self._redis.set(
            self._csrf_key(session_id), token, ex=ttl_seconds or self._session_ttl
        )
        return token

    async def get_csrf_token(self, session_id: str) -> str | None:
        value = await self._redis.get(self._csrf_key(session_id))
        return as_text(value) if value is not None else None

    # ------------------------------------------------------------------ TOTP replay
    async def mark_totp_code_used(self, key: str, *, ttl_seconds: int) -> bool:
        """Claim a TOTP code exactly once. ``False`` means it was already used.

        ``SET NX`` makes this atomic across tasks, so an attacker replaying an observed code
        against several instances simultaneously still only gets one acceptance.
        """
        created = await self._redis.set(key, "1", ex=ttl_seconds, nx=True)
        return bool(created)

    def _session_key(self, session_id: str) -> str:
        return f"{_SESSION_PREFIX}{hash_token(session_id)}"

    def _pending_key(self, pending_id: str) -> str:
        return f"{_PENDING_MFA_PREFIX}{hash_token(pending_id)}"

    def _csrf_key(self, session_id: str) -> str:
        return f"{_CSRF_PREFIX}{hash_token(session_id)}"
