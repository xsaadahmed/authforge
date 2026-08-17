"""RSA keypair generation and JWK (RFC 7517) serialization.

The `cryptography` library does the number theory. This module only converts between the
three representations the IdP needs: a live key object for signing, PEM for storage in
Secrets Manager, and a public JWK for the JWKS endpoint.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

JWS_ALGORITHM = "RS256"
_PUBLIC_EXPONENT = 65537


@dataclass(frozen=True, slots=True)
class GeneratedKeyPair:
    kid: str
    private_pem: str
    public_pem: str
    public_jwk: dict[str, Any]


def generate_keypair(kid: str, key_size: int = 2048) -> GeneratedKeyPair:
    if key_size < 2048:
        raise ValueError("RSA keys below 2048 bits are not acceptable for token signing")
    private_key = rsa.generate_private_key(public_exponent=_PUBLIC_EXPONENT, key_size=key_size)
    return GeneratedKeyPair(
        kid=kid,
        private_pem=private_key_to_pem(private_key),
        public_pem=public_key_to_pem(private_key.public_key()),
        public_jwk=public_key_to_jwk(private_key.public_key(), kid=kid),
    )


def private_key_to_pem(private_key: rsa.RSAPrivateKey) -> str:
    """Unencrypted PKCS#8 PEM.

    Not encrypting here is deliberate: the confidentiality boundary is Secrets Manager
    (encrypted with KMS, access-controlled by IAM), and adding a passphrase would just move
    the problem to "where do we keep the passphrase".
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def public_key_to_pem(public_key: rsa.RSAPublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def load_private_key(private_pem: str) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(private_pem.encode("ascii"), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("expected an RSA private key")
    return key


def load_public_key(public_pem: str) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(public_pem.encode("ascii"))
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("expected an RSA public key")
    return key


def public_key_to_jwk(public_key: rsa.RSAPublicKey, *, kid: str) -> dict[str, Any]:
    """Render a public RSA key as a JWK suitable for /.well-known/jwks.json."""
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": JWS_ALGORITHM,
        "kid": kid,
        "n": _b64_uint(numbers.n),
        "e": _b64_uint(numbers.e),
    }


def _b64_uint(value: int) -> str:
    """Big-endian, minimum-length, unpadded base64url — RFC 7518 §2 'Base64urlUInt'."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
