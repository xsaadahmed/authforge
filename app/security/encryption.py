"""Authenticated symmetric encryption for secrets that must be recoverable.

Used for TOTP secrets: unlike a password, the server needs the original value back to
verify a code, so hashing is not an option. AES-256-GCM gives confidentiality plus
integrity, so a tampered ciphertext fails loudly instead of decrypting to garbage.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_NONCE_BYTES = 12  # 96 bits, the GCM-recommended nonce size.
_KEY_BYTES = 32
_VERSION_PREFIX = "v1"


class DecryptionError(ValueError):
    """Raised when a ciphertext cannot be authenticated or decoded."""


def _derive_key(key_material: str, *, purpose: bytes) -> bytes:
    """HKDF-SHA256 the configured key string into a 32-byte AES key.

    Deriving rather than requiring exact base64 means operators cannot accidentally supply
    a 20-character key that silently gets padded, and it domain-separates uses via `info`.
    HKDF cannot manufacture entropy, so the configured value must still be a random 32-byte
    secret in any deployed environment — enforced in `Settings`.
    """
    if not key_material:
        raise ValueError("encryption key material must not be empty")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_BYTES,
        salt=None,
        info=purpose,
    ).derive(key_material.encode("utf-8"))


class SecretEncryptor:
    """Encrypts/decrypts short secrets with a single deployment key."""

    def __init__(self, key_material: str, *, purpose: bytes = b"authforge/totp-secret") -> None:
        self._key = _derive_key(key_material, purpose=purpose)

    def encrypt(self, plaintext: str) -> str:
        """Return ``v1.<b64(nonce)>.<b64(ciphertext||tag)>``.

        The version prefix exists so a future key/algorithm migration can decrypt old
        values without guessing at their format.
        """
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext.encode("utf-8"), None)
        return f"{_VERSION_PREFIX}.{_b64(nonce)}.{_b64(ciphertext)}"

    def decrypt(self, payload: str) -> str:
        parts = (payload or "").split(".")
        if len(parts) != 3 or parts[0] != _VERSION_PREFIX:
            raise DecryptionError("malformed ciphertext envelope")
        try:
            nonce = _unb64(parts[1])
            ciphertext = _unb64(parts[2])
            return AESGCM(self._key).decrypt(nonce, ciphertext, None).decode("utf-8")
        except (InvalidTag, ValueError, UnicodeDecodeError) as exc:
            raise DecryptionError("ciphertext failed authentication") from exc


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
