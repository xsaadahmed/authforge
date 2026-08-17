"""Argon2id password hashing.

Argon2id is the OWASP-recommended choice for new systems: memory-hard, so a GPU/ASIC
attacker buys far less advantage per dollar than against bcrypt or PBKDF2.
"""

from __future__ import annotations

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.config import Settings

# A hash of a throwaway password, used to burn a comparable amount of CPU when the account
# does not exist. Without this, "unknown user" returns in microseconds while "known user,
# wrong password" takes ~50ms, which is a usable account-enumeration oracle.
_DUMMY_PASSWORD = "authforge-timing-equalizer"


class PasswordPolicyError(ValueError):
    """Raised when a proposed password fails policy."""


class PasswordHasherService:
    """Wraps ``argon2-cffi`` with this deployment's cost parameters."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._hasher = PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_cost_kib,
            parallelism=settings.argon2_parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        self._dummy_hash = self._hasher.hash(_DUMMY_PASSWORD)

    def validate_policy(self, password: str) -> None:
        minimum = self._settings.password_min_length
        if len(password) < minimum:
            raise PasswordPolicyError(f"password must be at least {minimum} characters")
        if len(password) > 1024:
            # Argon2 is memory-hard; unbounded input is a cheap DoS vector.
            raise PasswordPolicyError("password must be at most 1024 characters")

    def hash(self, password: str) -> str:
        self.validate_policy(password)
        return self._hasher.hash(password)

    def verify(self, *, password: str, password_hash: str | None) -> bool:
        """Verify a password, spending comparable time whether or not the account exists.

        ``password_hash=None`` means "no such user" (or a user with no password credential);
        we still perform one Argon2 verification against a dummy hash before returning
        False.
        """
        if password_hash is None:
            self._burn_cpu()
            return False
        try:
            self._hasher.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
        return True

    def needs_rehash(self, password_hash: str) -> bool:
        """True when the stored hash used weaker parameters than the current policy."""
        try:
            return self._hasher.check_needs_rehash(password_hash)
        except InvalidHashError:
            return True

    def _burn_cpu(self) -> None:
        try:
            self._hasher.verify(self._dummy_hash, "definitely-not-the-password")
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            pass
