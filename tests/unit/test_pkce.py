"""PKCE (RFC 7636) unit tests."""

from __future__ import annotations

import base64
import hashlib

import pytest

from app.security import pkce


def test_challenge_matches_the_rfc_7636_appendix_b_vector() -> None:
    """The spec's own worked example, so the implementation is checked against the RFC itself."""
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert pkce.compute_s256_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_challenge_is_unpadded_base64url_of_sha256() -> None:
    verifier = pkce.generate_code_verifier()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    challenge = pkce.compute_s256_challenge(verifier)
    assert challenge == expected
    assert "=" not in challenge
    assert len(challenge) == 43


def test_matching_verifier_is_accepted() -> None:
    verifier = pkce.generate_code_verifier()
    challenge = pkce.compute_s256_challenge(verifier)
    assert pkce.verify_code_verifier(
        code_verifier=verifier, code_challenge=challenge, code_challenge_method="S256"
    )


def test_mismatched_verifier_is_rejected() -> None:
    challenge = pkce.compute_s256_challenge(pkce.generate_code_verifier())
    assert not pkce.verify_code_verifier(
        code_verifier=pkce.generate_code_verifier(),
        code_challenge=challenge,
        code_challenge_method="S256",
    )


def test_plain_method_is_rejected_even_when_the_values_match() -> None:
    """A PKCE downgrade must fail closed.

    With `plain`, the challenge *is* the verifier, so an attacker who can read the authorization
    request can replay the code. The OAuth Security BCP requires S256, so `plain` is refused even
    in the case where the naive comparison would have succeeded.
    """
    verifier = pkce.generate_code_verifier()
    assert not pkce.verify_code_verifier(
        code_verifier=verifier, code_challenge=verifier, code_challenge_method="plain"
    )
    with pytest.raises(pkce.PKCEError):
        pkce.validate_code_challenge(verifier, "plain")


@pytest.mark.parametrize(
    "verifier",
    [
        "",
        "too-short",
        "a" * 42,  # one below the RFC minimum
        "a" * 129,  # one above the RFC maximum
        "contains spaces and !!! invalid chars aaaaaaaaaaaaaaaaaaaa",
        "has/slashes/and+plus/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ],
)
def test_malformed_verifiers_are_rejected(verifier: str) -> None:
    with pytest.raises(pkce.PKCEError):
        pkce.validate_code_verifier(verifier)


def test_verification_returns_false_rather_than_raising_on_malformed_input() -> None:
    """Malformed and merely-wrong verifiers must be indistinguishable to a caller.

    If one raised and the other returned False, a handler could easily end up reporting different
    errors for the two cases, telling an attacker whether their guess was structurally plausible.
    """
    challenge = pkce.compute_s256_challenge(pkce.generate_code_verifier())
    assert (
        pkce.verify_code_verifier(
            code_verifier="!!!", code_challenge=challenge, code_challenge_method="S256"
        )
        is False
    )


@pytest.mark.parametrize(
    "challenge",
    ["", "short", "a" * 42, "a" * 44, "contains+invalid/chars=aaaaaaaaaaaaaaaaaaaa"],
)
def test_malformed_challenges_are_rejected_at_the_authorize_endpoint(challenge: str) -> None:
    with pytest.raises(pkce.PKCEError):
        pkce.validate_code_challenge(challenge, "S256")


def test_generated_verifier_has_at_least_256_bits_of_entropy() -> None:
    with pytest.raises(pkce.PKCEError):
        pkce.generate_code_verifier(entropy_bytes=16)
    assert len(pkce.generate_code_verifier()) >= 43


def test_generated_verifiers_do_not_repeat() -> None:
    assert len({pkce.generate_code_verifier() for _ in range(200)}) == 200
