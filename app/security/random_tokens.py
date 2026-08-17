"""Opaque token, code and identifier generation.

Every value here comes from ``secrets`` (the OS CSPRNG), never ``random``. Tokens are
stored only as SHA-256 hashes; the raw value exists in one HTTP response and nowhere else.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from ulid import ULID

# 32 bytes = 256 bits, per the spec's refresh-token requirement.
_DEFAULT_ENTROPY_BYTES = 32
_RECOVERY_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # Crockford-ish: no O/0, I/1.
_RECOVERY_CODE_GROUPS = 2
_RECOVERY_CODE_GROUP_LEN = 5


def new_opaque_token(entropy_bytes: int = _DEFAULT_ENTROPY_BYTES) -> str:
    """A urlsafe-base64 random string used for refresh tokens, codes and session IDs."""
    return secrets.token_urlsafe(entropy_bytes)


def hash_token(raw_token: str) -> str:
    """SHA-256 hex digest used as the storage key for an opaque token.

    A plain hash (not Argon2) is correct here: the input is 256 bits of CSPRNG output, so
    there is no dictionary to attack and no benefit to a slow KDF — while a slow KDF on the
    token path would add latency to every refresh.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def tokens_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def new_identifier() -> str:
    """A sortable, collision-resistant public identifier (ULID) for rows and `kid`s."""
    return str(ULID())


def new_jti() -> str:
    """Unique JWT identifier, used for correlating audit events to issued tokens."""
    return str(ULID())


def new_recovery_code() -> str:
    """A human-transcribable one-time MFA recovery code, e.g. ``K7QF2-9MTXD``.

    50 bits of entropy: far too much to guess online, short enough to write down.
    """
    groups = [
        "".join(secrets.choice(_RECOVERY_CODE_ALPHABET) for _ in range(_RECOVERY_CODE_GROUP_LEN))
        for _ in range(_RECOVERY_CODE_GROUPS)
    ]
    return "-".join(groups)


def normalize_recovery_code(code: str) -> str:
    """Fold user-entered formatting differences before hashing/comparing."""
    return code.strip().upper().replace(" ", "").replace("-", "")


def hash_recovery_code(code: str) -> str:
    return hash_token(normalize_recovery_code(code))
