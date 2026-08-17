"""PKCE (RFC 7636) challenge generation and verification.

Only ``S256`` is supported. ``plain`` is rejected outright: accepting it would let a
network attacker who can read the authorization request replay the code, which is exactly
the attack PKCE exists to stop, and the OAuth 2.0 Security BCP tells us to require S256.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets

S256 = "S256"
SUPPORTED_CODE_CHALLENGE_METHODS = (S256,)

# RFC 7636 §4.1: code_verifier = 43*128 unreserved characters.
_VERIFIER_PATTERN = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
# A challenge is base64url(SHA-256(...)) with padding stripped: always 43 characters.
_CHALLENGE_PATTERN = re.compile(r"^[A-Za-z0-9\-_]{43}$")


class PKCEError(ValueError):
    """Raised when PKCE parameters are structurally invalid."""


def b64url_encode(raw: bytes) -> str:
    """base64url without padding, as every OAuth/JOSE spec expects."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_code_verifier(entropy_bytes: int = 32) -> str:
    """Generate a spec-conformant verifier. Used by tests and the demo RP, not the IdP."""
    if entropy_bytes < 32:
        raise PKCEError("a code verifier needs at least 256 bits of entropy")
    return secrets.token_urlsafe(entropy_bytes)[:128]


def compute_s256_challenge(code_verifier: str) -> str:
    """base64url(SHA-256(ASCII(code_verifier))) — RFC 7636 §4.2."""
    validate_code_verifier(code_verifier)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return b64url_encode(digest)


def validate_code_verifier(code_verifier: str) -> None:
    if not _VERIFIER_PATTERN.match(code_verifier or ""):
        raise PKCEError("code_verifier must be 43-128 unreserved characters (RFC 7636 §4.1)")


def validate_code_challenge(code_challenge: str, code_challenge_method: str) -> None:
    """Validate the ``/authorize`` side of PKCE before a code is ever minted."""
    if code_challenge_method not in SUPPORTED_CODE_CHALLENGE_METHODS:
        raise PKCEError(
            f"unsupported code_challenge_method {code_challenge_method!r}; only S256 is allowed"
        )
    if not _CHALLENGE_PATTERN.match(code_challenge or ""):
        raise PKCEError("code_challenge must be a 43-character base64url SHA-256 digest")


def verify_code_verifier(
    *, code_verifier: str, code_challenge: str, code_challenge_method: str
) -> bool:
    """Constant-time PKCE verification.

    Returns ``False`` rather than raising for any failure — including malformed input — so
    that a caller cannot accidentally distinguish "wrong verifier" from "malformed
    verifier" in a response, and so the timing of both paths is dominated by the hash.
    """
    if code_challenge_method not in SUPPORTED_CODE_CHALLENGE_METHODS:
        return False
    try:
        computed = compute_s256_challenge(code_verifier)
    except PKCEError:
        return False
    return hmac.compare_digest(computed, code_challenge)
