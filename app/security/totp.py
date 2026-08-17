"""TOTP (RFC 6238) second factor, backed by ``pyotp``.

Two things this module deliberately owns, because they are policy rather than mathematics:
the size of the accepted time window, and the rule that a code may only be accepted once
per user per time step (replay protection).
"""

from __future__ import annotations

import pyotp

from app.security.random_tokens import hash_token

TOTP_DIGITS = 6
TOTP_PERIOD_SECONDS = 30
# Accept the immediately previous and next step to tolerate clock skew and slow typing.
# Wider windows multiply an attacker's guessing surface for no usability gain.
TOTP_VALID_WINDOW = 1


def generate_secret() -> str:
    """A fresh base32 TOTP secret (160 bits, the RFC 4226 recommendation)."""
    return pyotp.random_base32(length=32)


def provisioning_uri(*, secret: str, account_name: str, issuer_name: str) -> str:
    """``otpauth://`` URI for authenticator-app enrolment via QR code or manual entry."""
    return pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_PERIOD_SECONDS).provisioning_uri(
        name=account_name, issuer_name=issuer_name
    )


def verify_code(*, secret: str, code: str, at_timestamp: int | None = None) -> bool:
    """Verify a TOTP code, tolerating one step of clock skew in each direction."""
    cleaned = (code or "").strip().replace(" ", "")
    if not cleaned.isdigit() or len(cleaned) != TOTP_DIGITS:
        return False
    totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_PERIOD_SECONDS)
    if at_timestamp is not None:
        return bool(totp.verify(cleaned, for_time=at_timestamp, valid_window=TOTP_VALID_WINDOW))
    return bool(totp.verify(cleaned, valid_window=TOTP_VALID_WINDOW))


def current_code(secret: str, at_timestamp: int | None = None) -> str:
    """Only used by tests and the enrolment confirmation flow's own self-check."""
    totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_PERIOD_SECONDS)
    return totp.at(at_timestamp) if at_timestamp is not None else totp.now()


def replay_key(*, user_id: str, code: str) -> str:
    """Redis key marking a TOTP code as already spent for this user.

    A valid TOTP code stays valid for ~90 seconds given the skew window. Without this,
    an attacker who observes one code (shoulder-surfing, a phished form, a proxy) can
    reuse it. The code itself is hashed so it never lands in Redis or a slowlog verbatim.
    """
    return f"totp_used:{user_id}:{hash_token(code.strip())}"
