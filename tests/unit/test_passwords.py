"""Argon2id password hashing unit tests."""

from __future__ import annotations

import time

import pytest

from app.config import Settings
from app.security.passwords import PasswordHasherService, PasswordPolicyError


@pytest.fixture(scope="module")
def hasher() -> PasswordHasherService:
    return PasswordHasherService(
        Settings(
            environment="test",
            argon2_time_cost=1,
            argon2_memory_cost_kib=8192,
            argon2_parallelism=1,
        )
    )


def test_hash_is_argon2id_and_carries_its_parameters(hasher: PasswordHasherService) -> None:
    """The variant matters: argon2i and argon2d each trade away one of the protections we want."""
    digest = hasher.hash("a-perfectly-fine-password")
    assert digest.startswith("$argon2id$")
    assert "m=8192" in digest
    assert "t=1" in digest
    assert "p=1" in digest


def test_same_password_hashes_differently_each_time(hasher: PasswordHasherService) -> None:
    """A per-hash random salt is what stops one rainbow table covering every account."""
    password = "a-perfectly-fine-password"
    assert hasher.hash(password) != hasher.hash(password)


def test_correct_password_verifies(hasher: PasswordHasherService) -> None:
    digest = hasher.hash("a-perfectly-fine-password")
    assert hasher.verify(password="a-perfectly-fine-password", password_hash=digest)


def test_wrong_password_does_not_verify(hasher: PasswordHasherService) -> None:
    digest = hasher.hash("a-perfectly-fine-password")
    assert not hasher.verify(password="a-perfectly-fine-passworD", password_hash=digest)


def test_missing_hash_is_rejected_without_raising(hasher: PasswordHasherService) -> None:
    assert not hasher.verify(password="anything", password_hash=None)


def test_corrupt_hash_is_rejected_without_raising(hasher: PasswordHasherService) -> None:
    assert not hasher.verify(password="anything", password_hash="not-a-real-argon2-hash")


def test_unknown_account_costs_comparable_time_to_a_wrong_password(
    hasher: PasswordHasherService,
) -> None:
    """Guards the account-enumeration side channel.

    Verification against a real hash takes milliseconds; returning early for an unknown user would
    take microseconds, and that difference is measurable over a network. The service hashes a dummy
    value instead, so both paths cost roughly the same.

    The assertion is deliberately loose (a 10x band, best of several runs) because absolute timings
    on shared CI hardware are noisy — the failure being guarded against is an early return, which is
    orders of magnitude faster, not a 20% difference.
    """
    digest = hasher.hash("a-perfectly-fine-password")

    def best_of(iterations: int, password_hash: str | None) -> float:
        return min(
            (
                lambda: (
                    start := time.perf_counter(),
                    hasher.verify(password="wrong-password", password_hash=password_hash),
                    time.perf_counter() - start,
                )[-1]
            )()
            for _ in range(iterations)
        )

    wrong_password = best_of(5, digest)
    unknown_account = best_of(5, None)
    assert unknown_account > wrong_password / 10


@pytest.mark.parametrize("password", ["", "short", "eleven-chrs"])
def test_short_passwords_are_refused(hasher: PasswordHasherService, password: str) -> None:
    with pytest.raises(PasswordPolicyError):
        hasher.hash(password)


def test_absurdly_long_passwords_are_refused(hasher: PasswordHasherService) -> None:
    """Argon2 is memory-hard by design, so unbounded input is a cheap denial-of-service vector."""
    with pytest.raises(PasswordPolicyError):
        hasher.hash("x" * 2000)


def test_rehash_is_requested_when_cost_parameters_increase() -> None:
    weak = PasswordHasherService(
        Settings(
            environment="test",
            argon2_time_cost=1,
            argon2_memory_cost_kib=8192,
            argon2_parallelism=1,
        )
    )
    strong = PasswordHasherService(
        Settings(
            environment="test",
            argon2_time_cost=3,
            argon2_memory_cost_kib=16384,
            argon2_parallelism=1,
        )
    )
    old_digest = weak.hash("a-perfectly-fine-password")
    assert strong.needs_rehash(old_digest)
    assert not weak.needs_rehash(old_digest)
    # The old hash must still verify, or raising the cost would lock every existing user out.
    assert strong.verify(password="a-perfectly-fine-password", password_hash=old_digest)


def test_unparseable_hash_is_treated_as_needing_rehash(hasher: PasswordHasherService) -> None:
    assert hasher.needs_rehash("$unknown$scheme$value")
