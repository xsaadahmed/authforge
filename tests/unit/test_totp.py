"""TOTP (RFC 6238) unit tests."""

from __future__ import annotations

import pyotp
import pytest

from app.security import totp


def test_generated_secret_is_usable_base32() -> None:
    secret = totp.generate_secret()
    assert len(secret) == 32
    # Round-trips through an independent TOTP implementation, proving the secret is well-formed
    # rather than merely accepted by our own code.
    assert pyotp.TOTP(secret).now().isdigit()


def test_current_code_verifies() -> None:
    secret = totp.generate_secret()
    assert totp.verify_code(secret=secret, code=totp.current_code(secret))


def test_code_from_one_step_ago_is_accepted() -> None:
    """One step of tolerance in each direction covers clock skew and slow typing."""
    secret = totp.generate_secret()
    now = 1_700_000_000
    previous = totp.current_code(secret, at_timestamp=now - totp.TOTP_PERIOD_SECONDS)
    assert totp.verify_code(secret=secret, code=previous, at_timestamp=now)


def test_code_from_the_next_step_is_accepted() -> None:
    secret = totp.generate_secret()
    now = 1_700_000_000
    following = totp.current_code(secret, at_timestamp=now + totp.TOTP_PERIOD_SECONDS)
    assert totp.verify_code(secret=secret, code=following, at_timestamp=now)


def test_code_from_two_steps_ago_is_rejected() -> None:
    """The window is bounded; a wider one would just multiply an attacker's guessing surface."""
    secret = totp.generate_secret()
    now = 1_700_000_000
    stale = totp.current_code(secret, at_timestamp=now - 3 * totp.TOTP_PERIOD_SECONDS)
    assert not totp.verify_code(secret=secret, code=stale, at_timestamp=now)


def test_code_for_a_different_secret_is_rejected() -> None:
    assert not totp.verify_code(
        secret=totp.generate_secret(), code=totp.current_code(totp.generate_secret())
    )


@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", "12 34 56 78", "  ", "12345a"])
def test_malformed_codes_are_rejected(code: str) -> None:
    assert not totp.verify_code(secret=totp.generate_secret(), code=code)


def test_whitespace_around_a_code_is_tolerated() -> None:
    secret = totp.generate_secret()
    assert totp.verify_code(secret=secret, code=f"  {totp.current_code(secret)}  ")


def test_provisioning_uri_round_trips_into_a_working_authenticator_configuration() -> None:
    """Parsed back with pyotp's own URI parser, which is what an authenticator app effectively does.

    Asserting on the parsed result rather than on substrings also covers the parameters that are
    omitted from the URI precisely because they equal the `otpauth` defaults.
    """
    secret = totp.generate_secret()
    uri = totp.provisioning_uri(
        secret=secret, account_name="user@example.test", issuer_name="AuthForge"
    )
    assert uri.startswith("otpauth://totp/")
    assert f"secret={secret}" in uri
    assert "issuer=AuthForge" in uri

    parsed = pyotp.parse_uri(uri)
    assert parsed.secret == secret
    assert parsed.digits == totp.TOTP_DIGITS
    assert parsed.interval == totp.TOTP_PERIOD_SECONDS
    assert parsed.name == "user@example.test"
    # A code generated from the parsed configuration must verify against our own verifier.
    assert totp.verify_code(secret=secret, code=parsed.now())


def test_replay_key_does_not_contain_the_code_itself() -> None:
    """The replay marker lands in Redis, so it must not be a usable second factor if disclosed."""
    key = totp.replay_key(user_id="01ABCDEF", code="123456")
    assert "123456" not in key
    assert key.startswith("totp_used:01ABCDEF:")


def test_replay_keys_are_distinct_per_user_and_per_code() -> None:
    assert totp.replay_key(user_id="a", code="123456") != totp.replay_key(
        user_id="b", code="123456"
    )
    assert totp.replay_key(user_id="a", code="123456") != totp.replay_key(
        user_id="a", code="654321"
    )
