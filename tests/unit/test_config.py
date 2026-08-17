"""Configuration validation tests.

A misconfigured IdP is a security incident, not an inconvenience, so `Settings` refuses to
construct rather than warning. These tests pin the invariants that refusal enforces.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import Settings

_DEPLOYED_BASE = {
    "environment": "prod",
    "issuer": "https://idp.example.com",
    "signing_key_provider": "aws_secrets_manager",
    "totp_encryption_key": "a-real-32-byte-random-value-here-ok",
    "session_cookie_secure": True,
}


def test_local_defaults_are_permissive() -> None:
    settings = Settings(environment="local")
    assert settings.issuer.startswith("http://")
    assert settings.signing_key_provider == "local"
    assert not settings.is_deployed


def test_a_valid_production_configuration_constructs() -> None:
    settings = Settings(**_DEPLOYED_BASE)  # type: ignore[arg-type]
    assert settings.is_deployed


def test_production_requires_https_issuer() -> None:
    with pytest.raises(ValidationError, match="issuer must use https"):
        Settings(**{**_DEPLOYED_BASE, "issuer": "http://idp.example.com"})  # type: ignore[arg-type]


def test_production_requires_secure_cookies() -> None:
    with pytest.raises(ValidationError, match="session_cookie_secure"):
        Settings(**{**_DEPLOYED_BASE, "session_cookie_secure": False})  # type: ignore[arg-type]


def test_production_refuses_filesystem_signing_keys() -> None:
    """A private key on a container filesystem is one image layer or volume snapshot from
    disclosure, so deployed environments must use Secrets Manager."""
    with pytest.raises(ValidationError, match="signing_key_provider"):
        Settings(**{**_DEPLOYED_BASE, "signing_key_provider": "local"})  # type: ignore[arg-type]


def test_production_refuses_the_development_totp_key() -> None:
    with pytest.raises(ValidationError, match="totp_encryption_key"):
        Settings(**{**_DEPLOYED_BASE, "totp_encryption_key": "dev-only-insecure"})  # type: ignore[arg-type]


def test_key_rotation_grace_must_outlast_two_access_token_lifetimes() -> None:
    """§11's invariant.

    A `retiring` key must stay in JWKS at least twice as long as an access token lives, so a token
    signed a moment before rotation cannot outlive its verification key.
    """
    with pytest.raises(ValidationError, match="key_rotation_grace_seconds"):
        Settings(environment="test", access_token_ttl_seconds=900, key_rotation_grace_seconds=1000)
    Settings(environment="test", access_token_ttl_seconds=900, key_rotation_grace_seconds=1800)


def test_issuer_trailing_slash_is_normalized_away() -> None:
    """`iss` is compared byte-for-byte by relying parties, so one canonical form is essential."""
    assert Settings(environment="test", issuer="https://idp.example.com/").issuer == (
        "https://idp.example.com"
    )


def test_issuer_must_be_an_absolute_url() -> None:
    with pytest.raises(ValidationError, match="absolute http"):
        Settings(environment="test", issuer="idp.example.com")


def test_url_for_builds_absolute_endpoint_urls() -> None:
    settings = Settings(environment="test", issuer="https://idp.example.com")
    assert settings.url_for("/token") == "https://idp.example.com/token"
    assert settings.url_for("token") == "https://idp.example.com/token"


def test_sync_database_url_strips_the_async_driver_for_alembic() -> None:
    settings = Settings(
        environment="test",
        database_url="postgresql+asyncpg://u:p@host:5432/db",  # type: ignore[arg-type]
    )
    assert settings.sync_database_url() == "postgresql://u:p@host:5432/db"


def test_rsa_keys_below_2048_bits_are_refused_by_configuration() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="test", rsa_key_size=1024)


def test_access_token_lifetime_is_bounded() -> None:
    """Short access tokens make stateless verification acceptable; an hour is the ceiling."""
    with pytest.raises(ValidationError):
        Settings(environment="test", access_token_ttl_seconds=86400)


def test_authorization_code_lifetime_is_bounded_to_minutes() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="test", authorization_code_ttl_seconds=3600)


def test_settings_are_immutable_once_constructed() -> None:
    """Frozen so no request handler can mutate policy at runtime."""
    settings = Settings(environment="test")
    with pytest.raises(ValidationError):
        settings.access_token_ttl_seconds = 60  # type: ignore[misc]
