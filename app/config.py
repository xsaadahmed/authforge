"""Typed, 12-factor configuration.

Every knob the IdP has is declared here so that a deployment is fully described by its
environment variables. Nothing reads ``os.environ`` directly outside this module.
"""

from __future__ import annotations

import functools
from typing import Literal

from pydantic import Field, PostgresDsn, RedisDsn, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["local", "test", "staging", "prod"]
KeyProvider = Literal["local", "aws_secrets_manager"]


class Settings(BaseSettings):
    """Application settings.

    Resolution order is the pydantic-settings default: explicit init kwargs, then
    environment variables, then values from ``.env``. Secrets in staging/prod arrive as
    environment variables injected by the ECS task definition from Secrets Manager.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="AUTHFORGE_",
        extra="ignore",
        frozen=True,
    )

    environment: Environment = "local"
    log_level: str = "INFO"
    debug_templates: bool = False

    # ------------------------------------------------------------------ identity
    # The `iss` claim and the base for every URL in the discovery document. Must be the
    # externally reachable origin (the ALB hostname in AWS), because RPs resolve
    # endpoints from discovery and validate `iss` against what they configured.
    issuer: str = "http://localhost:8000"

    # ------------------------------------------------------------------ datastores
    database_url: PostgresDsn = Field(
        default=PostgresDsn("postgresql+asyncpg://authforge:authforge@localhost:5432/authforge")
    )
    database_pool_size: int = Field(default=5, ge=1, le=100)
    database_max_overflow: int = Field(default=5, ge=0, le=100)
    database_pool_timeout_seconds: float = Field(default=5.0, gt=0)
    database_statement_timeout_ms: int = Field(default=5_000, ge=0)

    redis_url: RedisDsn = Field(default=RedisDsn("redis://localhost:6379/0"))
    redis_connect_timeout_seconds: float = Field(
        default=2.0,
        gt=0,
        description="TCP + TLS handshake budget for new pool connections (staging uses rediss://).",
    )
    redis_command_timeout_seconds: float = Field(
        default=1.0,
        gt=0,
        description="Read/write timeout for commands on already-open connections.",
    )
    redis_max_connections: int = Field(
        default=32,
        ge=1,
        le=500,
        description="Per-process connection pool cap (one Uvicorn worker per ECS task).",
    )
    redis_pool_prewarm_connections: int = Field(
        default=4,
        ge=0,
        le=50,
        description="Parallel PINGs at startup to open pool connections before traffic arrives.",
    )

    # ------------------------------------------------------------------ token policy
    access_token_ttl_seconds: int = Field(default=600, ge=60, le=3600)
    # Extra `aud` values placed in access tokens alongside the issuer. The issuer is always
    # present because the IdP's own /userinfo is a resource server for its tokens; a
    # deployment adds its API's identifier here so that resource servers can reject tokens
    # minted for a different audience (RFC 9068 §4).
    access_token_audiences: list[str] = Field(default_factory=list)
    id_token_ttl_seconds: int = Field(default=600, ge=60, le=3600)
    # Refresh tokens use an ABSOLUTE family lifetime (see docs/adr/0003). A rotated token
    # inherits its family's expiry rather than extending it, which bounds the blast radius
    # of a stolen token to a window the operator chose up front.
    refresh_token_ttl_seconds: int = Field(default=30 * 24 * 3600, ge=300)
    authorization_code_ttl_seconds: int = Field(default=90, ge=10, le=600)
    # Grace period during which a `retiring` key still verifies. Must be >= 2x the access
    # token TTL so no in-flight token can outlive its key's presence in JWKS (§11).
    key_rotation_grace_seconds: int = Field(default=3600, ge=120)
    jwks_cache_seconds: int = Field(default=30, ge=0, le=600)

    # ------------------------------------------------------------------ sessions / UI
    session_ttl_seconds: int = Field(default=12 * 3600, ge=60)
    pending_mfa_ttl_seconds: int = Field(default=300, ge=30, le=900)
    session_cookie_name: str = "authforge_session"
    session_cookie_secure: bool = True
    session_cookie_samesite: Literal["lax", "strict", "none"] = "lax"

    # ------------------------------------------------------------------ rate limiting
    login_rate_limit_per_ip: int = Field(default=30, ge=1)
    login_rate_limit_per_account: int = Field(default=10, ge=1)
    login_rate_limit_window_seconds: int = Field(default=300, ge=10)
    token_rate_limit_per_client: int = Field(default=600, ge=1)
    token_rate_limit_window_seconds: int = Field(default=60, ge=1)
    account_lockout_threshold: int = Field(default=10, ge=1)
    account_lockout_seconds: int = Field(default=900, ge=30)
    # Fail-open: if Redis is unreachable the limiter admits the request rather than
    # locking out the world. See docs/adr/0005 for the threat-model reasoning.
    rate_limit_fail_open: bool = True

    # ------------------------------------------------------------------ crypto / keys
    signing_key_provider: KeyProvider = "local"
    # Only used when signing_key_provider == "local": directory holding PEM private keys
    # named "<kid>.pem". Gitignored; never used in staging/prod.
    local_key_directory: str = "dev-keys"
    # Only used when signing_key_provider == "aws_secrets_manager": secrets are stored at
    # "<prefix>/<kid>".
    aws_secret_name_prefix: str = "authforge/signing-keys"
    aws_region: str = "us-east-1"
    rsa_key_size: int = Field(default=2048, ge=2048)

    # 32-byte urlsafe-base64 key used to encrypt TOTP secrets at rest (Fernet-style AES).
    # Must be supplied in every non-local environment.
    totp_encryption_key: str = "dev-only-insecure-totp-encryption-key-change-me"

    # Bearer token for the minimal admin API. Admin surface is intentionally tiny (§31);
    # the CLI is the primary path.
    admin_api_token: str | None = None

    # ------------------------------------------------------------------ password policy
    argon2_time_cost: int = Field(default=3, ge=1)
    argon2_memory_cost_kib: int = Field(default=65536, ge=8192)
    argon2_parallelism: int = Field(default=4, ge=1)
    password_min_length: int = Field(default=12, ge=8)

    # ------------------------------------------------------------------ behaviour flags
    # Audit writes share the caller's transaction where possible, but a failure to record
    # an audit event must never deny a legitimate authentication (§12/§21).
    audit_failures_are_fatal: bool = False
    consent_required: bool = True

    @field_validator("issuer")
    @classmethod
    def _issuer_has_no_trailing_slash(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("issuer must be an absolute http(s) URL")
        return value.rstrip("/")

    @model_validator(mode="after")
    def _enforce_deployed_environment_invariants(self) -> Settings:
        """Refuse to boot with development defaults in a deployed environment.

        A misconfigured IdP is a security incident, not an inconvenience, so these are
        hard failures at startup rather than warnings in a log nobody reads.
        """
        if self.environment in ("staging", "prod"):
            problems: list[str] = []
            if not self.issuer.startswith("https://"):
                problems.append("issuer must use https")
            if not self.session_cookie_secure:
                problems.append("session_cookie_secure must be true")
            if self.signing_key_provider != "aws_secrets_manager":
                problems.append("signing_key_provider must be aws_secrets_manager")
            if self.totp_encryption_key.startswith("dev-only"):
                problems.append("totp_encryption_key must be set to a real key")
            if self.debug_templates:
                problems.append("debug_templates must be false")
            if problems:
                raise ValueError(
                    f"invalid configuration for environment={self.environment}: "
                    + "; ".join(problems)
                )
        if self.key_rotation_grace_seconds < 2 * self.access_token_ttl_seconds:
            raise ValueError(
                "key_rotation_grace_seconds must be at least 2x access_token_ttl_seconds "
                "so tokens signed just before a rotation still verify"
            )
        return self

    @property
    def is_deployed(self) -> bool:
        return self.environment in ("staging", "prod")

    def url_for(self, path: str) -> str:
        return f"{self.issuer}/{path.lstrip('/')}"

    def sync_database_url(self) -> str:
        """Alembic runs synchronously; strip the asyncpg driver marker."""
        return str(self.database_url).replace("+asyncpg", "")


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton.

    Cached because construction reads the filesystem (.env) and because FastAPI resolves
    it as a dependency on hot paths. Tests clear the cache via ``get_settings.cache_clear``.
    """
    return Settings()
