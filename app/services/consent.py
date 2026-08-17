"""Consent resolution and recording.

The subtlety worth stating explicitly is why two sets are tracked per (user, client):

* ``granted_scopes`` — what the client may actually have.
* ``considered_scopes`` — what the user has been shown, approved or not.

With only the granted set, "the user declined this scope" and "the user has never been asked about
this scope" look identical. Prompting on any ungranted scope would then re-prompt forever after a
user declines something; not prompting would let a client silently add a scope. Tracking what has
been *considered* separates the two: a request is prompted only when it contains something new, and
the tokens carry only what was granted.
"""

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

# OIDC Core §3.1.2.1: `openid` only selects the OIDC flow. Declining it would not narrow access, it
# would make the request fail in a way the user cannot interpret, so it is shown as context rather
# than as a choice and is treated as granted whenever it is requested.
IMPLIED_SCOPES = frozenset({"openid"})


@dataclass(frozen=True, slots=True)
class ConsentDecision:
    """Whether the pending authorization request can proceed without asking the user."""

    consent_required: bool
    # The subset of the request the client may actually have, given prior decisions.
    effective_scopes: list[str]
    # Requested scopes the user has never been shown; the reason a prompt is needed.
    unseen_scopes: list[str]

    @property
    def has_any_grant(self) -> bool:
        return bool(self.effective_scopes)


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
        requested = list(dict.fromkeys(requested_scopes))
        if not self._settings.consent_required or not client.require_consent:
            # A first-party client configured to skip consent: every requested scope is effective.
            return ConsentDecision(
                consent_required=False, effective_scopes=requested, unseen_scopes=[]
            )

        record = await ConsentRepository(session).get(user_id=user_id, client_id=client.id)
        granted: set[str] = set()
        considered: set[str] = set(IMPLIED_SCOPES)
        if record is not None and not _is_expired(record.expires_at):
            granted = set(record.granted_scopes)
            considered |= set(record.considered_scopes)
        granted |= IMPLIED_SCOPES

        unseen = [scope for scope in requested if scope not in considered]
        return ConsentDecision(
            consent_required=bool(unseen),
            effective_scopes=[scope for scope in requested if scope in granted],
            unseen_scopes=unseen,
        )

    async def grant(
        self,
        session: AsyncSession,
        *,
        user_id: str,
        client: OAuthClient,
        approved_scopes: Sequence[str],
        requested_scopes: Sequence[str],
    ) -> list[str]:
        """Record a decision covering exactly the scopes this request asked about.

        Merge rule: for scopes in *this* request the current decision wins, so unticking a
        previously approved scope genuinely narrows the grant. Scopes outside this request keep
        whatever the user decided before, so approving a narrow request does not silently revoke an
        earlier broader grant.
        """
        repository = ConsentRepository(session)
        existing = await repository.get(user_id=user_id, client_id=client.id)
        previous_granted: set[str] = set()
        previous_considered: set[str] = set()
        if existing is not None and not _is_expired(existing.expires_at):
            previous_granted = set(existing.granted_scopes)
            previous_considered = set(existing.considered_scopes)

        in_this_request = set(requested_scopes)
        approved = set(approved_scopes) | (in_this_request & IMPLIED_SCOPES)
        granted = (previous_granted - in_this_request) | approved
        considered = previous_considered | in_this_request | IMPLIED_SCOPES

        await repository.grant(
            user_id=user_id,
            client_id=client.id,
            granted_scopes=sorted(granted),
            considered_scopes=sorted(considered),
        )
        await self._audit.record_in_transaction(
            session,
            AuditEventType.CONSENT_GRANTED,
            user_id=user_id,
            client_id=client.client_id,
            detail={
                "granted_scopes": sorted(granted),
                "declined_scopes": sorted(in_this_request - approved),
            },
        )
        return sorted(granted)

    async def deny(
        self,
        session: AsyncSession,
        *,
        user_id: str,
        client: OAuthClient,
        scopes: Sequence[str],
    ) -> None:
        await self._audit.record(
            session,
            AuditEventType.CONSENT_DENIED,
            success=False,
            user_id=user_id,
            client_id=client.client_id,
            detail={"requested_scopes": list(scopes)},
        )

    async def revoke(self, session: AsyncSession, *, user_id: str, client: OAuthClient) -> None:
        """Forget the decision entirely, so the next request prompts from scratch."""
        await ConsentRepository(session).revoke(user_id=user_id, client_id=client.id)
        await self._audit.record_in_transaction(
            session,
            AuditEventType.CONSENT_REVOKED,
            user_id=user_id,
            client_id=client.client_id,
        )


def _is_expired(expires_at: datetime | None) -> bool:
    return expires_at is not None and expires_at <= datetime.now(tz=UTC)
