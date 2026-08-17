"""Initial schema.

Creates every table in §12 of the specification: identity (`users`, `mfa_credentials`,
`recovery_codes`), client registration (`oauth_clients`, `client_redirect_uris`, `scopes`,
`client_scopes`), authorization state (`consents`, `refresh_tokens`), key metadata
(`signing_keys`) and the security audit trail (`audit_log`).

Two details are worth noting because they are load-bearing rather than incidental:

* `refresh_tokens` carries a partial index on `(token_hash) WHERE used_at IS NULL AND revoked =
  false`. Every refresh request looks up exactly one still-redeemable token, so the index only
  needs to cover live rows; spent generations accumulate for forensics without inflating it.
* `signing_keys` stores public JWK material and a *reference* to the private key, never the
  private key itself. A database dump therefore cannot mint tokens.

Revision ID: 0001_initial_schema
Revises: (base)
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_log",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("user_id", sa.String(length=26), nullable=True),
        sa.Column("client_id", sa.String(length=64), nullable=True),
        sa.Column("subject_hint", sa.String(length=320), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("detail", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_log")),
    )
    op.create_index(
        "ix_audit_log_client_id_created_at", "audit_log", ["client_id", "created_at"], unique=False
    )
    op.create_index(op.f("ix_audit_log_created_at"), "audit_log", ["created_at"], unique=False)
    op.create_index(
        "ix_audit_log_event_type_created_at",
        "audit_log",
        ["event_type", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_audit_log_user_id_created_at", "audit_log", ["user_id", "created_at"], unique=False
    )
    op.create_table(
        "oauth_clients",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("client_secret_hash", sa.String(length=64), nullable=True),
        sa.Column("client_type", sa.String(length=16), nullable=False),
        sa.Column("token_endpoint_auth_method", sa.String(length=32), nullable=False),
        sa.Column("client_name", sa.String(length=255), nullable=False),
        sa.Column("client_uri", sa.Text(), nullable=True),
        sa.Column("logo_uri", sa.Text(), nullable=True),
        sa.Column("policy_uri", sa.Text(), nullable=True),
        sa.Column("tos_uri", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("require_consent", sa.Boolean(), nullable=False),
        sa.Column("access_token_ttl_seconds", sa.Integer(), nullable=True),
        sa.Column("refresh_token_ttl_seconds", sa.Integer(), nullable=True),
        sa.Column("allow_refresh_tokens", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_oauth_clients")),
        sa.UniqueConstraint("client_id", name=op.f("uq_oauth_clients_client_id")),
    )
    op.create_table(
        "scopes",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("is_oidc", sa.Boolean(), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scopes")),
        sa.UniqueConstraint("name", name=op.f("uq_scopes_name")),
    )
    op.create_table(
        "signing_keys",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("kid", sa.String(length=64), nullable=False),
        sa.Column("algorithm", sa.String(length=16), nullable=False),
        sa.Column("public_jwk", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("public_pem", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("private_key_ref", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retiring_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retire_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_signing_keys")),
        sa.UniqueConstraint("kid", name=op.f("uq_signing_keys_kid")),
    )
    op.create_index("ix_signing_keys_status", "signing_keys", ["status"], unique=False)
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=True),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("email_verified", sa.Boolean(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("is_admin", sa.Boolean(), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("given_name", sa.String(length=128), nullable=True),
        sa.Column("family_name", sa.String(length=128), nullable=True),
        sa.Column("picture_url", sa.Text(), nullable=True),
        sa.Column("failed_login_count", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "password_changed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
        sa.UniqueConstraint("username", name=op.f("uq_users_username")),
    )
    op.create_index("ix_users_email_active", "users", ["email", "is_active"], unique=False)
    op.create_table(
        "client_redirect_uris",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("client_id", sa.String(length=26), nullable=False),
        sa.Column("uri", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["oauth_clients.id"],
            name=op.f("fk_client_redirect_uris_client_id_oauth_clients"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_client_redirect_uris")),
        sa.UniqueConstraint("client_id", "uri", name="uq_client_redirect_uris_client_id_uri"),
    )
    op.create_table(
        "client_scopes",
        sa.Column("client_id", sa.String(length=26), nullable=False),
        sa.Column("scope_name", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["oauth_clients.id"],
            name=op.f("fk_client_scopes_client_id_oauth_clients"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scope_name"],
            ["scopes.name"],
            name=op.f("fk_client_scopes_scope_name_scopes"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("client_id", "scope_name", name=op.f("pk_client_scopes")),
    )
    op.create_index("ix_client_scopes_scope_name", "client_scopes", ["scope_name"], unique=False)
    op.create_table(
        "consents",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("user_id", sa.String(length=26), nullable=False),
        sa.Column("client_id", sa.String(length=26), nullable=False),
        sa.Column("granted_scopes", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("considered_scopes", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["oauth_clients.id"],
            name=op.f("fk_consents_client_id_oauth_clients"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_consents_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_consents")),
        sa.UniqueConstraint("user_id", "client_id", name="uq_consents_user_id_client_id"),
    )
    op.create_index("ix_consents_user_id", "consents", ["user_id"], unique=False)
    op.create_table(
        "mfa_credentials",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("user_id", sa.String(length=26), nullable=False),
        sa.Column("factor_type", sa.String(length=16), nullable=False),
        sa.Column("secret_encrypted", sa.Text(), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_mfa_credentials_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mfa_credentials")),
        sa.UniqueConstraint("user_id", name=op.f("uq_mfa_credentials_user_id")),
    )
    op.create_table(
        "recovery_codes",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("user_id", sa.String(length=26), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_recovery_codes_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_recovery_codes")),
        sa.UniqueConstraint("user_id", "code_hash", name="uq_recovery_codes_user_id_code_hash"),
    )
    op.create_index(
        "ix_recovery_codes_user_id_unused",
        "recovery_codes",
        ["user_id"],
        unique=False,
        postgresql_where=sa.text("used_at IS NULL"),
    )
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.String(length=26), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("family_id", sa.String(length=26), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("previous_token_hash", sa.String(length=64), nullable=True),
        sa.Column("user_id", sa.String(length=26), nullable=False),
        sa.Column("client_id", sa.String(length=26), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("auth_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "issued_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=32), nullable=True),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["oauth_clients.id"],
            name=op.f("fk_refresh_tokens_client_id_oauth_clients"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_refresh_tokens_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_refresh_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_refresh_tokens_token_hash")),
    )
    op.create_index(
        "ix_refresh_tokens_active",
        "refresh_tokens",
        ["token_hash"],
        unique=False,
        postgresql_where=sa.text("used_at IS NULL AND revoked = false"),
    )
    op.create_index("ix_refresh_tokens_expires_at", "refresh_tokens", ["expires_at"], unique=False)
    op.create_index("ix_refresh_tokens_family_id", "refresh_tokens", ["family_id"], unique=False)
    op.create_index(
        "ix_refresh_tokens_user_id_client_id",
        "refresh_tokens",
        ["user_id", "client_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_refresh_tokens_user_id_client_id", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_family_id", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_expires_at", table_name="refresh_tokens")
    op.drop_index(
        "ix_refresh_tokens_active",
        table_name="refresh_tokens",
        postgresql_where=sa.text("used_at IS NULL AND revoked = false"),
    )
    op.drop_table("refresh_tokens")
    op.drop_index(
        "ix_recovery_codes_user_id_unused",
        table_name="recovery_codes",
        postgresql_where=sa.text("used_at IS NULL"),
    )
    op.drop_table("recovery_codes")
    op.drop_table("mfa_credentials")
    op.drop_index("ix_consents_user_id", table_name="consents")
    op.drop_table("consents")
    op.drop_index("ix_client_scopes_scope_name", table_name="client_scopes")
    op.drop_table("client_scopes")
    op.drop_table("client_redirect_uris")
    op.drop_index("ix_users_email_active", table_name="users")
    op.drop_table("users")
    op.drop_index("ix_signing_keys_status", table_name="signing_keys")
    op.drop_table("signing_keys")
    op.drop_table("scopes")
    op.drop_table("oauth_clients")
    op.drop_index("ix_audit_log_user_id_created_at", table_name="audit_log")
    op.drop_index("ix_audit_log_event_type_created_at", table_name="audit_log")
    op.drop_index(op.f("ix_audit_log_created_at"), table_name="audit_log")
    op.drop_index("ix_audit_log_client_id_created_at", table_name="audit_log")
    op.drop_table("audit_log")
