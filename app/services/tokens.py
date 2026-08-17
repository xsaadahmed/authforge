"""Token issuance, validation, refresh rotation and revocation (§8, §10).

The two flows that matter most are here:

**Authorization code exchange.** The code is redeemed with a single atomic Redis ``GETDEL``, so
it is single-use across the whole fleet. Everything the code was bound to at issuance — client,
redirect URI, PKCE challenge — is re-verified against what the redeeming request presents. A
code alone is worthless.

**Refresh with rotation.** Every successful refresh mints a new token in the same family and
spends the presented one, via one atomic ``UPDATE ... WHERE used_at IS NULL``. Presenting an
already-spent token means the raw value existed in two places, which is treated as theft: the
entire family is revoked and the client must re-authenticate the user. That is strictly better
than rejecting only the replayed token, because an attacker who stole the token would otherwise
keep whatever generation they hold.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from jwt.exceptions import InvalidTokenError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.errors import (
    BearerTokenError,
    InvalidGrantError,
    InvalidScopeError,
    OAuthErrorCode,
)
from app.core.logging import get_logger
from app.models.audit import AuditEventType
from app.models.client import OAuthClient
from app.models.token import RevocationReason
from app.models.user import User
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.user_repository import UserRepository
from app.security import pkce as pkce_lib
from app.security.random_tokens import (
    hash_token,
    new_identifier,
    new_jti,
    new_opaque_token,
)
from app.services import claims as claims_lib
from app.services.audit import AuditService
from app.services.key_management import KeyManagementService
from app.stores.auth_code_store import AuthCodeStore
from app.stores.token_denylist import TokenDenylistStore

logger = get_logger(__name__)

# OIDC Core §11: a client must ask for `offline_access` to receive a refresh token. Issuing one
# unasked would hand every client long-lived access it never requested.
SCOPE_OFFLINE_ACCESS = claims_lib.SCOPE_OFFLINE_ACCESS
# Clock skew tolerated when validating `iat`/`nbf`/`exp` on tokens we ourselves issued.
_LEEWAY_SECONDS = 30


@dataclass(frozen=True, slots=True)
class TokenSet:
    """The RFC 6749 §5.1 / OIDC Core §3.1.3.3 token response."""

    access_token: str
    token_type: str
    expires_in: int
    scope: str
    refresh_token: str | None = None
    id_token: str | None = None

    def to_response(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "scope": self.scope,
        }
        if self.refresh_token:
            payload["refresh_token"] = self.refresh_token
        if self.id_token:
            payload["id_token"] = self.id_token
        return payload


@dataclass(frozen=True, slots=True)
class VerifiedAccessToken:
    subject: str
    client_id: str
    scopes: list[str]
    jti: str
    expires_at: int
    session_id: str | None


class TokenService:
    def __init__(
        self,
        *,
        settings: Settings,
        keys: KeyManagementService,
        auth_codes: AuthCodeStore,
        denylist: TokenDenylistStore,
        audit: AuditService,
    ) -> None:
        self._settings = settings
        self._keys = keys
        self._auth_codes = auth_codes
        self._denylist = denylist
        self._audit = audit

    # ------------------------------------------------------------------ code exchange
    async def exchange_authorization_code(
        self,
        db: AsyncSession,
        *,
        client: OAuthClient,
        code: str,
        redirect_uri: str | None,
        code_verifier: str | None,
    ) -> TokenSet:
        payload = await self._auth_codes.redeem(code)
        if payload is None:
            # Unknown, expired, or already redeemed — indistinguishable by design, and all
            # three mean the same thing to the client.
            await self._audit.record(
                AuditEventType.AUTHZ_FAILURE,
                success=False,
                client_id=client.client_id,
                detail={"stage": "code_exchange", "reason": "unknown_or_used_code"},
            )
            raise InvalidGrantError("authorization code is invalid, expired, or already used")

        if payload.client_id != client.client_id:
            # A code issued to a different client. The code is already consumed by the GETDEL
            # above, so a cross-client probe also burns the code — the legitimate client's
            # exchange will fail and the user retries, which is the safe direction to fail.
            await self._audit.record(
                AuditEventType.AUTHZ_FAILURE,
                success=False,
                client_id=client.client_id,
                detail={"stage": "code_exchange", "reason": "client_mismatch"},
            )
            raise InvalidGrantError("authorization code was not issued to this client")

        # RFC 6749 §4.1.3: redirect_uri is required on exchange when it was in the request, and
        # must be identical. This is what stops a code obtained via an injected redirect from
        # being exchanged against the legitimate registration.
        if redirect_uri is None or redirect_uri != payload.redirect_uri:
            await self._audit.record(
                AuditEventType.AUTHZ_FAILURE,
                success=False,
                client_id=client.client_id,
                detail={"stage": "code_exchange", "reason": "redirect_uri_mismatch"},
            )
            raise InvalidGrantError("redirect_uri does not match the authorization request")

        if not code_verifier or not pkce_lib.verify_code_verifier(
            code_verifier=code_verifier,
            code_challenge=payload.code_challenge,
            code_challenge_method=payload.code_challenge_method,
        ):
            await self._audit.record(
                AuditEventType.AUTHZ_FAILURE,
                success=False,
                client_id=client.client_id,
                detail={"stage": "code_exchange", "reason": "pkce_verification_failed"},
            )
            raise InvalidGrantError("PKCE verification failed")

        user = await UserRepository(db).get_by_id(payload.user_id)
        if user is None or not user.is_active:
            raise InvalidGrantError("the authorizing user is no longer active")

        token_set = await self._issue_token_set(
            db,
            user=user,
            client=client,
            scopes=list(payload.scopes),
            auth_time=payload.auth_time_datetime,
            nonce=payload.nonce,
            session_id=payload.session_id,
            issue_refresh_token=True,
            include_id_token=claims_lib.SCOPE_OPENID in payload.scopes,
        )
        await self._audit.record_in_transaction(
            db,
            AuditEventType.TOKEN_ISSUED,
            user_id=user.id,
            client_id=client.client_id,
            detail={"grant_type": "authorization_code", "scopes": list(payload.scopes)},
        )
        return token_set

    # ------------------------------------------------------------------ refresh
    async def refresh(
        self,
        db: AsyncSession,
        *,
        client: OAuthClient,
        refresh_token: str,
        requested_scope: str | None = None,
    ) -> TokenSet:
        """Rotate a refresh token, or detect its reuse and burn the family."""
        token_hash = hash_token(refresh_token)
        repository = RefreshTokenRepository(db)

        claimed = await repository.claim_for_rotation(token_hash=token_hash, client_id=client.id)
        if claimed is None:
            await self._handle_failed_claim(db, client=client, token_hash=token_hash)
            raise InvalidGrantError("refresh token is invalid, expired, or revoked")

        user = await UserRepository(db).get_by_id(claimed.user_id)
        if user is None or not user.is_active:
            await repository.revoke_family(
                claimed.family_id, reason=RevocationReason.ADMIN_ACTION
            )
            raise InvalidGrantError("the authorizing user is no longer active")

        granted_scopes = list(claimed.scopes)
        if requested_scope is not None:
            # RFC 6749 §6: a client may narrow but never widen on refresh.
            requested = claims_lib.parse_scope_string(requested_scope)
            widened = set(requested) - set(granted_scopes)
            if widened:
                raise InvalidScopeError(
                    "refresh cannot request scopes beyond the original grant: "
                    + ", ".join(sorted(widened))
                )
            granted_scopes = requested

        token_set = await self._issue_token_set(
            db,
            user=user,
            client=client,
            scopes=granted_scopes,
            auth_time=claimed.auth_time,
            nonce=None,  # OIDC Core §12.2: no nonce in a refreshed ID token.
            session_id=None,
            issue_refresh_token=True,
            include_id_token=claims_lib.SCOPE_OPENID in granted_scopes,
            family_id=claimed.family_id,
            generation=claimed.generation + 1,
            previous_token_hash=token_hash,
            # Absolute family lifetime: the rotated token inherits the original expiry rather
            # than sliding it forward (docs/adr/0003).
            refresh_expires_at=claimed.expires_at,
        )
        await self._audit.record_in_transaction(
            db,
            AuditEventType.TOKEN_REFRESHED,
            user_id=user.id,
            client_id=client.client_id,
            detail={
                "family_id": claimed.family_id,
                "generation": claimed.generation + 1,
                "scopes": granted_scopes,
            },
        )
        return token_set

    async def _handle_failed_claim(
        self, db: AsyncSession, *, client: OAuthClient, token_hash: str
    ) -> None:
        """Classify a failed atomic claim and react to genuine reuse.

        Reached by: an unknown token, a token belonging to another client, an expired token, an
        already-revoked token, a replayed token, and the loser of a legitimate concurrent
        double-refresh. Only the last two look identical in the database, and both are treated
        as reuse — a client that races itself is indistinguishable from an attacker replaying a
        stolen token, and the safe interpretation of an ambiguous signal is the pessimistic one.
        """
        repository = RefreshTokenRepository(db)
        existing = await repository.get_by_hash(token_hash)
        if existing is None:
            await self._audit.record(
                AuditEventType.TOKEN_REVOKED,
                success=False,
                client_id=client.client_id,
                detail={"reason": "unknown_refresh_token"},
            )
            return

        if existing.client_id != client.id:
            await self._audit.record(
                AuditEventType.AUTHZ_FAILURE,
                success=False,
                client_id=client.client_id,
                detail={"reason": "refresh_token_client_mismatch", "family_id": existing.family_id},
            )
            return

        if existing.used_at is not None:
            revoked_count = await repository.revoke_family(
                existing.family_id, reason=RevocationReason.REUSE_DETECTED
            )
            # Same transaction as the revocation: "we killed the family" and "here is why"
            # must commit together or not at all.
            await self._audit.record_in_transaction(
                db,
                AuditEventType.REFRESH_REUSE_DETECTED,
                success=False,
                user_id=existing.user_id,
                client_id=client.client_id,
                detail={
                    "family_id": existing.family_id,
                    "generation": existing.generation,
                    "tokens_revoked": revoked_count,
                    "originally_used_at": existing.used_at.isoformat(),
                },
            )
            logger.warning(
                "refresh token reuse detected; family revoked",
                extra={
                    "event": "refresh_reuse_detected",
                    "family_id": existing.family_id,
                    "user_id": existing.user_id,
                    "oauth_client_id": client.client_id,
                    "tokens_revoked": revoked_count,
                },
            )
            return

        reason = "revoked" if existing.revoked else "expired"
        await self._audit.record(
            AuditEventType.TOKEN_REVOKED,
            success=False,
            user_id=existing.user_id,
            client_id=client.client_id,
            detail={"reason": f"refresh_token_{reason}", "family_id": existing.family_id},
        )

    # ------------------------------------------------------------------ issuance
    async def _issue_token_set(
        self,
        db: AsyncSession,
        *,
        user: User,
        client: OAuthClient,
        scopes: list[str],
        auth_time: datetime,
        nonce: str | None,
        session_id: str | None,
        issue_refresh_token: bool,
        include_id_token: bool,
        family_id: str | None = None,
        generation: int = 0,
        previous_token_hash: str | None = None,
        refresh_expires_at: datetime | None = None,
    ) -> TokenSet:
        now = int(time.time())
        access_ttl = client.access_token_ttl_seconds or self._settings.access_token_ttl_seconds
        signing_key = await self._keys.get_signing_key()

        access_claims = claims_lib.build_access_token_claims(
            issuer=self._settings.issuer,
            subject=user.id,
            audiences=self._access_token_audiences(),
            client_id=client.client_id,
            scopes=scopes,
            issued_at=now,
            expires_at=now + access_ttl,
            jti=new_jti(),
            auth_time=int(auth_time.timestamp()),
            session_id=session_id,
        )
        access_token = jwt.encode(
            access_claims,
            signing_key.private_key,  # type: ignore[arg-type]
            algorithm=signing_key.algorithm,
            headers={"kid": signing_key.kid, "typ": claims_lib.ACCESS_TOKEN_TYPE_HEADER},
        )

        id_token: str | None = None
        if include_id_token:
            id_ttl = self._settings.id_token_ttl_seconds
            id_claims = claims_lib.build_id_token_claims(
                issuer=self._settings.issuer,
                subject=user.id,
                client_id=client.client_id,
                issued_at=now,
                expires_at=now + id_ttl,
                auth_time=int(auth_time.timestamp()),
                nonce=nonce,
                granted_scopes=scopes,
                user=_user_claim_source(user),
                access_token=access_token,
                session_id=session_id,
            )
            id_token = jwt.encode(
                id_claims,
                signing_key.private_key,  # type: ignore[arg-type]
                algorithm=signing_key.algorithm,
                headers={"kid": signing_key.kid, "typ": claims_lib.ID_TOKEN_TYPE_HEADER},
            )

        refresh_token: str | None = None
        if issue_refresh_token and self._may_issue_refresh_token(client=client, scopes=scopes):
            refresh_token = new_opaque_token()
            ttl = client.refresh_token_ttl_seconds or self._settings.refresh_token_ttl_seconds
            await RefreshTokenRepository(db).create(
                token_hash=hash_token(refresh_token),
                family_id=family_id or _new_family_id(),
                generation=generation,
                previous_token_hash=previous_token_hash,
                user_id=user.id,
                client_id=client.id,
                scopes=scopes,
                auth_time=auth_time,
                expires_at=refresh_expires_at or datetime.now(tz=UTC) + timedelta(seconds=ttl),
            )

        return TokenSet(
            access_token=access_token,
            token_type="Bearer",
            expires_in=access_ttl,
            scope=claims_lib.format_scope_string(scopes),
            refresh_token=refresh_token,
            id_token=id_token,
        )

    def _may_issue_refresh_token(self, *, client: OAuthClient, scopes: list[str]) -> bool:
        return client.allow_refresh_tokens and SCOPE_OFFLINE_ACCESS in scopes

    def _access_token_audiences(self) -> list[str]:
        return [self._settings.issuer, *self._settings.access_token_audiences]

    # ------------------------------------------------------------------ verification
    async def verify_access_token(self, token: str) -> VerifiedAccessToken:
        """Validate a bearer access token for a protected resource (§8E).

        Order is deliberate: parse the header to find ``kid``, resolve the key, then let PyJWT
        verify the signature *before* any claim is trusted. Reading claims from an unverified
        token — even just to find the issuer — is how signature-stripping bugs happen. The
        algorithm is pinned to RS256 so a token with ``alg: none`` or a symmetric ``alg`` can
        never be presented as valid.
        """
        try:
            header = jwt.get_unverified_header(token)
        except InvalidTokenError as exc:
            raise BearerTokenError(description="malformed token") from exc

        kid = header.get("kid")
        if not kid:
            raise BearerTokenError(description="token has no key identifier")
        if header.get("typ") not in (claims_lib.ACCESS_TOKEN_TYPE_HEADER, "JWT"):
            raise BearerTokenError(description="token is not an access token")

        public_key = await self._keys.get_verification_key(str(kid))
        if public_key is None:
            raise BearerTokenError(description="token was signed by an unknown or retired key")

        try:
            payload = jwt.decode(
                token,
                public_key,  # type: ignore[arg-type]
                algorithms=["RS256"],
                issuer=self._settings.issuer,
                audience=self._access_token_audiences(),
                leeway=_LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "iss", "sub", "jti"]},
            )
        except InvalidTokenError as exc:
            raise BearerTokenError(description=f"token rejected: {exc}") from exc

        jti = str(payload["jti"])
        if await self._denylist.is_revoked(jti):
            raise BearerTokenError(description="token has been revoked")

        return VerifiedAccessToken(
            subject=str(payload["sub"]),
            client_id=str(payload.get("client_id", "")),
            scopes=claims_lib.parse_scope_string(payload.get("scope")),
            jti=jti,
            expires_at=int(payload["exp"]),
            session_id=payload.get("sid"),
        )

    def require_scope(self, verified: VerifiedAccessToken, scope: str) -> None:
        if scope not in verified.scopes:
            raise BearerTokenError(
                OAuthErrorCode.INSUFFICIENT_SCOPE,
                f"the {scope} scope is required",
                status_code=403,
                required_scope=scope,
            )

    # ------------------------------------------------------------------ revocation
    async def revoke(
        self, db: AsyncSession, *, client: OAuthClient, token: str, token_type_hint: str | None
    ) -> None:
        """RFC 7009 revocation. Never signals whether the token existed.

        The endpoint returns 200 regardless, so an unauthenticated-ish caller cannot use it as
        an oracle for token validity. The hint only decides which lookup is tried first.
        """
        order = ["refresh_token", "access_token"]
        if token_type_hint == "access_token":
            order.reverse()

        for kind in order:
            if kind == "refresh_token" and await self._revoke_refresh_token(
                db, client=client, token=token
            ):
                return
            if kind == "access_token" and await self._revoke_access_token(client=client, token=token):
                return

    async def _revoke_refresh_token(
        self, db: AsyncSession, *, client: OAuthClient, token: str
    ) -> bool:
        repository = RefreshTokenRepository(db)
        existing = await repository.get_by_hash(hash_token(token))
        if existing is None or existing.client_id != client.id:
            return False
        # Family-wide, not just this generation: revoking one link in a rotation chain while
        # leaving its successor alive would not actually end the client's access.
        revoked = await repository.revoke_family(
            existing.family_id, reason=RevocationReason.CLIENT_REQUEST
        )
        await self._audit.record_in_transaction(
            db,
            AuditEventType.TOKEN_REVOKED,
            user_id=existing.user_id,
            client_id=client.client_id,
            detail={
                "token_type": "refresh_token",
                "family_id": existing.family_id,
                "tokens_revoked": revoked,
            },
        )
        return True

    async def _revoke_access_token(self, *, client: OAuthClient, token: str) -> bool:
        try:
            verified = await self.verify_access_token(token)
        except BearerTokenError:
            return False
        if verified.client_id != client.client_id:
            return False
        remaining = verified.expires_at - int(time.time())
        await self._denylist.revoke(jti=verified.jti, ttl_seconds=remaining)
        await self._audit.record(
            AuditEventType.TOKEN_REVOKED,
            user_id=verified.subject,
            client_id=client.client_id,
            detail={"token_type": "access_token", "jti": verified.jti},
        )
        return True

    async def revoke_all_for_client(
        self, db: AsyncSession, *, client: OAuthClient, reason: RevocationReason
    ) -> int:
        count = await RefreshTokenRepository(db).revoke_all_for_client(client.id, reason=reason)
        await self._audit.record_in_transaction(
            db,
            AuditEventType.TOKEN_REVOKED,
            client_id=client.client_id,
            detail={"token_type": "refresh_token", "tokens_revoked": count, "reason": str(reason)},
        )
        return count

    async def revoke_all_for_user(
        self, db: AsyncSession, *, user_id: str, reason: RevocationReason
    ) -> int:
        count = await RefreshTokenRepository(db).revoke_all_for_user(user_id, reason=reason)
        await self._audit.record_in_transaction(
            db,
            AuditEventType.TOKEN_REVOKED,
            user_id=user_id,
            detail={"token_type": "refresh_token", "tokens_revoked": count, "reason": str(reason)},
        )
        return count


def _user_claim_source(user: User) -> claims_lib.UserClaimSource:
    return claims_lib.UserClaimSource(
        user_id=user.id,
        email=user.email,
        email_verified=user.email_verified,
        full_name=user.full_name,
        given_name=user.given_name,
        family_name=user.family_name,
        picture_url=user.picture_url,
        updated_at_epoch=int(user.updated_at.timestamp()) if user.updated_at else None,
    )


def _new_family_id() -> str:
    return new_identifier()
