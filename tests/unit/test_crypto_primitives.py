"""Unit tests for encryption, RSA/JWK handling and opaque token generation."""

from __future__ import annotations

import base64

import jwt
import pytest

from app.security import rsa_keys
from app.security.encryption import DecryptionError, SecretEncryptor
from app.security.random_tokens import (
    hash_recovery_code,
    hash_token,
    new_opaque_token,
    new_recovery_code,
    normalize_recovery_code,
    tokens_equal,
)

KEY_MATERIAL = "a-test-key-with-plenty-of-entropy-0123456789"


def test_encryption_round_trips() -> None:
    encryptor = SecretEncryptor(KEY_MATERIAL)
    assert encryptor.decrypt(encryptor.encrypt("JBSWY3DPEHPK3PXP")) == "JBSWY3DPEHPK3PXP"


def test_ciphertext_is_versioned_and_hides_the_plaintext() -> None:
    ciphertext = SecretEncryptor(KEY_MATERIAL).encrypt("JBSWY3DPEHPK3PXP")
    assert ciphertext.startswith("v1.")
    assert "JBSWY3DPEHPK3PXP" not in ciphertext


def test_encrypting_the_same_value_twice_gives_different_ciphertexts() -> None:
    """A fresh nonce per encryption. Reusing a GCM nonce under one key is catastrophic, and equal
    ciphertexts would also reveal which users share a secret."""
    encryptor = SecretEncryptor(KEY_MATERIAL)
    assert encryptor.encrypt("same") != encryptor.encrypt("same")


def test_tampered_ciphertext_is_rejected_rather_than_decrypted_to_garbage() -> None:
    """This is why AES-GCM rather than AES-CTR: the tag makes tampering a loud failure."""
    encryptor = SecretEncryptor(KEY_MATERIAL)
    version, nonce, body = encryptor.encrypt("JBSWY3DPEHPK3PXP").split(".")
    flipped = bytearray(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    flipped[0] ^= 0x01
    tampered = base64.urlsafe_b64encode(bytes(flipped)).rstrip(b"=").decode()
    with pytest.raises(DecryptionError):
        encryptor.decrypt(f"{version}.{nonce}.{tampered}")


def test_a_different_key_cannot_decrypt() -> None:
    ciphertext = SecretEncryptor(KEY_MATERIAL).encrypt("secret")
    with pytest.raises(DecryptionError):
        SecretEncryptor("a-completely-different-key-0123456789").decrypt(ciphertext)


@pytest.mark.parametrize("payload", ["", "garbage", "v1.only-two-parts", "v2.aaa.bbb"])
def test_malformed_envelopes_are_rejected(payload: str) -> None:
    with pytest.raises(DecryptionError):
        SecretEncryptor(KEY_MATERIAL).decrypt(payload)


def test_empty_key_material_is_refused() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        SecretEncryptor("")


# ---------------------------------------------------------------------------- RSA / JWK
def test_generated_keypair_signs_and_verifies_a_real_jwt() -> None:
    """End-to-end through PyJWT, so the PEM/JWK conversions are proven interoperable."""
    keypair = rsa_keys.generate_keypair("test-kid")
    token = jwt.encode(
        {"sub": "abc"},
        keypair.private_pem,
        algorithm="RS256",
        headers={"kid": keypair.kid},
    )
    decoded = jwt.decode(token, keypair.public_pem, algorithms=["RS256"])
    assert decoded["sub"] == "abc"
    assert jwt.get_unverified_header(token)["kid"] == "test-kid"


def test_keys_below_2048_bits_are_refused() -> None:
    with pytest.raises(ValueError, match="2048"):
        rsa_keys.generate_keypair("weak", key_size=1024)


def test_public_jwk_has_the_rfc_7517_fields_and_no_private_material() -> None:
    jwk = rsa_keys.generate_keypair("test-kid").public_jwk
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"
    assert jwk["kid"] == "test-kid"
    # `d`, `p`, `q` and friends are the private half; their presence in JWKS would be a total
    # compromise of the signing key.
    assert set(jwk) == {"kty", "use", "alg", "kid", "n", "e"}


def test_jwk_modulus_is_unpadded_base64url_with_no_leading_zero_byte() -> None:
    """RFC 7518 §2 'Base64urlUInt': minimum-length big-endian, unpadded. Verifiers reject a
    modulus with a spurious leading zero byte, which is the classic way this goes wrong."""
    jwk = rsa_keys.generate_keypair("test-kid", key_size=2048).public_jwk
    modulus = base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4))
    assert "=" not in jwk["n"]
    assert len(modulus) == 256
    assert modulus[0] != 0
    assert base64.urlsafe_b64decode(jwk["e"] + "==") == b"\x01\x00\x01"


def test_private_pem_is_pkcs8_and_public_pem_is_spki() -> None:
    keypair = rsa_keys.generate_keypair("test-kid")
    assert keypair.private_pem.startswith("-----BEGIN PRIVATE KEY-----")
    assert keypair.public_pem.startswith("-----BEGIN PUBLIC KEY-----")


def test_loading_a_public_key_where_a_private_key_is_expected_fails() -> None:
    keypair = rsa_keys.generate_keypair("test-kid")
    with pytest.raises(ValueError):
        rsa_keys.load_private_key(keypair.public_pem)


# ---------------------------------------------------------------------------- opaque tokens
def test_opaque_tokens_have_at_least_256_bits_of_entropy() -> None:
    token = new_opaque_token()
    # 32 random bytes in urlsafe-base64 is 43 characters.
    assert len(token) >= 43
    assert len({new_opaque_token() for _ in range(500)}) == 500


def test_token_hash_is_deterministic_hex_sha256() -> None:
    digest = hash_token("abc")
    assert len(digest) == 64
    assert digest == hash_token("abc")
    assert digest != hash_token("abd")
    assert all(character in "0123456789abcdef" for character in digest)


def test_constant_time_comparison_matches_normal_equality() -> None:
    assert tokens_equal("abc", "abc")
    assert not tokens_equal("abc", "abd")
    assert not tokens_equal("abc", "abcd")


def test_recovery_codes_are_transcribable_and_unambiguous() -> None:
    """No O/0 or I/1, because these get written on paper and typed back in."""
    code = new_recovery_code()
    assert len(code) == 11
    assert code[5] == "-"
    assert not set(code) & {"O", "0", "I", "1"}


def test_recovery_code_normalization_folds_user_formatting() -> None:
    assert normalize_recovery_code(" k7qf2-9mtxd ") == "K7QF29MTXD"
    assert hash_recovery_code("k7qf2 9mtxd") == hash_recovery_code("K7QF2-9MTXD")


def test_recovery_codes_do_not_repeat() -> None:
    assert len({new_recovery_code() for _ in range(500)}) == 500
