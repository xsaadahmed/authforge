"""Self-service account schemas (MFA enrolment)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class MfaEnrolmentResponse(BaseModel):
    """The staged TOTP secret.

    Returned once, to an already-authenticated user over TLS, and inert until confirmed: an
    unconfirmed credential is never treated as an enrolled factor.
    """

    secret: str
    provisioning_uri: str
    digits: int
    period_seconds: int


class MfaConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class RecoveryCodesResponse(BaseModel):
    """Displayed once. Only SHA-256 hashes are stored, so they cannot be shown again."""

    recovery_codes: list[str]
