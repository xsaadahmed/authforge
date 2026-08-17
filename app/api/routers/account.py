"""Self-service account endpoints: MFA enrolment (§8F).

Authenticated by the browser session, because enrolling a second factor is an
account-security operation and must not be reachable with an OAuth access token issued to a
third-party client — a client with ``profile`` scope should not be able to enrol or replace a
user's second factor.
"""

from __future__ import annotations

from fastapi import APIRouter, Response

from app.api.deps import ContainerDep, CurrentSessionDep, DbDep
from app.core.errors import DomainError
from app.schemas.account import (
    MfaConfirmRequest,
    MfaEnrolmentResponse,
    RecoveryCodesResponse,
)
from app.security import totp as totp_lib
from app.stores.session_store import SessionState

router = APIRouter(prefix="/account", tags=["account"])


@router.post("/mfa/enroll", response_model=MfaEnrolmentResponse, summary="Begin TOTP enrolment")
async def begin_enrolment(
    container: ContainerDep, db: DbDep, current: CurrentSessionDep, response: Response
) -> MfaEnrolmentResponse:
    session = _require_session(current)
    challenge = await container.authentication.begin_mfa_enrolment(db, user_id=session.user_id)
    # The secret is a credential: no caching, anywhere, under any circumstances.
    response.headers["Cache-Control"] = "no-store"
    return MfaEnrolmentResponse(
        secret=challenge.secret,
        provisioning_uri=challenge.provisioning_uri,
        digits=totp_lib.TOTP_DIGITS,
        period_seconds=totp_lib.TOTP_PERIOD_SECONDS,
    )


@router.post(
    "/mfa/confirm", response_model=RecoveryCodesResponse, summary="Confirm TOTP enrolment"
)
async def confirm_enrolment(
    payload: MfaConfirmRequest,
    container: ContainerDep,
    db: DbDep,
    current: CurrentSessionDep,
    response: Response,
) -> RecoveryCodesResponse:
    session = _require_session(current)
    result = await container.authentication.confirm_mfa_enrolment(
        db, user_id=session.user_id, code=payload.code
    )
    response.headers["Cache-Control"] = "no-store"
    return RecoveryCodesResponse(recovery_codes=result.recovery_codes)


@router.post(
    "/mfa/recovery-codes",
    response_model=RecoveryCodesResponse,
    summary="Replace the recovery-code set",
)
async def regenerate_recovery_codes(
    container: ContainerDep, db: DbDep, current: CurrentSessionDep, response: Response
) -> RecoveryCodesResponse:
    session = _require_session(current)
    result = await container.authentication.regenerate_recovery_codes(db, user_id=session.user_id)
    response.headers["Cache-Control"] = "no-store"
    return RecoveryCodesResponse(recovery_codes=result.recovery_codes)


def _require_session(current: tuple[str, SessionState] | None) -> SessionState:
    if current is None:
        raise DomainError("sign in first", status_code=401)
    return current[1]
