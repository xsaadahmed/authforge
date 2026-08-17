"""Rate-limit policy (§13, §21, §22).

The store implements the sliding-window mechanism; this service decides *what* is limited and
*what happens when the limiter itself is unavailable*.

**Fail-open is the chosen default, and it is a decision rather than an oversight.** If Redis
is down, failing closed would convert a cache outage into a total authentication outage for
every user — a self-inflicted denial of service far more likely than the brute-force campaign
the limiter defends against. The residual risk is bounded because the two controls that
actually stop credential attacks do not live in Redis: Argon2id makes each guess expensive,
and the per-account failure counter and lockout are durable rows in Postgres. Deployments with
a different threat model flip ``rate_limit_fail_open`` and get fail-closed behaviour, and
either way every degraded decision is logged and counted so the gap is visible.
"""

from __future__ import annotations

from dataclasses import replace

from app.config import Settings
from app.core.logging import get_logger
from app.core.metrics import get_metrics
from app.stores.rate_limit_store import RateLimitStore, RateLimitVerdict

logger = get_logger(__name__)


class RateLimitService:
    def __init__(self, *, settings: Settings, store: RateLimitStore) -> None:
        self._settings = settings
        self._store = store

    async def check_login_attempt(
        self, *, ip_address: str | None, subject: str | None
    ) -> RateLimitVerdict:
        """Limit login attempts per IP and per account, whichever binds first.

        Both dimensions are needed: per-IP alone lets a botnet spread one-guess-per-host
        attempts across a single account, and per-account alone lets one host walk a password
        list across many accounts.
        """
        verdicts: list[RateLimitVerdict] = []
        if ip_address:
            verdicts.append(
                await self._consume(
                    key=f"ratelimit:login:ip:{ip_address}",
                    limit=self._settings.login_rate_limit_per_ip,
                    window_seconds=self._settings.login_rate_limit_window_seconds,
                    scope="login_ip",
                )
            )
        if subject:
            verdicts.append(
                await self._consume(
                    key=f"ratelimit:login:account:{subject.lower()}",
                    limit=self._settings.login_rate_limit_per_account,
                    window_seconds=self._settings.login_rate_limit_window_seconds,
                    scope="login_account",
                )
            )
        return _most_restrictive(verdicts, default_limit=self._settings.login_rate_limit_per_ip)

    async def check_token_request(self, *, client_id: str) -> RateLimitVerdict:
        return await self._consume(
            key=f"ratelimit:token:client:{client_id}",
            limit=self._settings.token_rate_limit_per_client,
            window_seconds=self._settings.token_rate_limit_window_seconds,
            scope="token_client",
        )

    async def check_mfa_attempt(self, *, pending_id_hash: str) -> RateLimitVerdict:
        """Cap second-factor guesses.

        A 6-digit TOTP has a 1-in-a-million chance per guess, which is only strong if the
        number of guesses is bounded — unbounded guessing against a ~90-second window is a
        realistic attack.
        """
        return await self._consume(
            key=f"ratelimit:mfa:{pending_id_hash}",
            limit=5,
            window_seconds=self._settings.pending_mfa_ttl_seconds,
            scope="mfa",
        )

    async def clear_login_limits(self, *, ip_address: str | None, subject: str | None) -> None:
        """Called after a successful login so a legitimate typo does not accumulate."""
        try:
            if subject:
                await self._store.reset(key=f"ratelimit:login:account:{subject.lower()}")
            if ip_address:
                await self._store.reset(key=f"ratelimit:login:ip:{ip_address}")
        except Exception:
            logger.warning("could not clear login rate-limit counters", exc_info=True)

    async def _consume(
        self, *, key: str, limit: int, window_seconds: int, scope: str
    ) -> RateLimitVerdict:
        try:
            verdict = await self._store.consume(key=key, limit=limit, window_seconds=window_seconds)
        except Exception:
            logger.error(
                "rate limiter unavailable",
                extra={"limit_scope": scope, "fail_open": self._settings.rate_limit_fail_open},
                exc_info=True,
            )
            get_metrics().count("RateLimiterUnavailable", dimensions={"Scope": scope})
            return RateLimitVerdict(
                allowed=self._settings.rate_limit_fail_open,
                current_count=0,
                limit=limit,
                retry_after_seconds=0 if self._settings.rate_limit_fail_open else window_seconds,
                degraded=True,
            )
        if not verdict.allowed:
            logger.warning(
                "rate limit exceeded",
                extra={"limit_scope": scope, "limit": limit, "window_seconds": window_seconds},
            )
            get_metrics().count("RateLimitExceeded", dimensions={"Scope": scope})
        return verdict


def _most_restrictive(verdicts: list[RateLimitVerdict], *, default_limit: int) -> RateLimitVerdict:
    if not verdicts:
        return RateLimitVerdict(
            allowed=True, current_count=0, limit=default_limit, retry_after_seconds=0
        )
    blocked = [verdict for verdict in verdicts if not verdict.allowed]
    if blocked:
        worst = max(blocked, key=lambda verdict: verdict.retry_after_seconds)
        return replace(worst, degraded=any(verdict.degraded for verdict in verdicts))
    return replace(verdicts[0], degraded=any(verdict.degraded for verdict in verdicts))
