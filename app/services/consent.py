"""Consent resolution and recording."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.models.audit import AuditEventType
from app.models.client import OAuthClient
from app.repositories.consent_repository import ConsentRepository
from app.services.audit import AuditService

# OIDC Core §3.1.2.1: `openid` merely selects the OIDC flow, and `offline_access` is a
# durability request rather than access to data. Neither says anything a user could
# meaningfully approve or refuse on its own, so neither is shown as a tick-box; the prompt
# describes what the client will be able to read.
_NON_PROMPTABLE_SCOPES = frozenset({"openid"})


@dataclass(frozen=True, slots=True)
class ConsentDecision:
    """Whether the pending authorization request can proceed without asking the user."""

    consent_required: bool
    already_granted: list[str]
    newly_requested: list[str]

    @property
    def promptable_scopes(self) -> list[str]:
        return [scope for scope in self.newly_requested if scope not in _NON_PROMPTABLE_SCOPES]


class ConsentService:
    def __init__(self, *, settings: Settings, audit: AuditService) -> None:
        self._settings = settings
        self._audit = audit

    async def evaluate(
        self,
        session: AsyncSession,
        *,
        user_id: str,
        client: OAuthClient,
        requested_scopes: Sequence[str],
    ) -> ConsentDecision:
        """Decide whether to prompt.

        A prompt is skipped only when every requested scope is already inside a live grant.
        Requesting even one new scope re-prompts for the whole set, so a client cannot widen
        its access by drip-feeding one extra scope at a time past a user who stopped reading.
        """
        requested = list(dict.fromkeys(requested_scopes))
        if not self._settings.consent_required or not client.require_consent:
            return ConsentDecision(
                consent_required=False, already_granted=requested, newly_requested=[]
            )

        record = await ConsentRepository(session).get(user_id=user_id, client_id=client.id)
        granted: set[str] = set()
        if record is not None and not _is_expired(record.expires_at):
            granted = set(record.granted_scopes)

        outstanding = [scope for scope in requested if scope not in granted]
        return ConsentDecision(
            consent_required=bool(outstanding),
            already_granted=[scope for scope in requested if scope in granted],
            newly_requested=outstanding,
        )

    async def grant(
        self,
        session: AsyncSession,
        *,
        user_id: str,
        client: OAuthClient,
        scopes: Sequence[str],
    ) -> list[str]:
        """Record a decision.

        The previously granted set is unioned with the newly approved scopes so that
        approving a second client request does not silently drop an earlier grant; narrowing
        happens through explicit revocation.
        """
        repository = ConsentRepository(session)
        existing = await repository.get(user_id=user_id, client_id=client.id)
        merged = set(scopes)
        if existing is not None and not _is_expired(existing.expires_at):
            merged |= set(existing.granted_scopes)
        final = sorted(merged)
        await repository.grant(user_id=user_id, client_id=client.id, scopes=final)
        await self._audit.record_in_transaction(
            session,
            AuditEventType.CONSENT_GRANTED,
            user_id=user_id,
            client_id=client.client_id,
            detail={"scopes": final},
        )
        return final

    async def deny(
        self, *, user_id: str, client: OAuthClient, scopes: Sequence[str]
    ) -> None:
        await self._audit.record(
            AuditEventType.CONSENT_DENIED,
            success=False,
            user_id=user_id,
            client_id=client.client_id,
            detail={"requested_scopes": list(scopes)},
        )

    async def revoke(
        self, session: AsyncSession, *, user_id: str, client: OAuthClient
    ) -> None:
        await ConsentRepository(session).revoke(user_id=user_id, client_id=client.id)
        await self._audit.record_in_transaction(
            session,
            AuditEventType.CONSENT_REVOKED,
            user_id=user_id,
            client_id=client.client_id,
        )


def _is_expired(expires_at: datetime | None) -> bool:
    return expires_at is not None and expires_at <= datetime.now(tz=UTC)
